// v0.4: Python lockfiles + installed environments, container image references, and --harden checks.
import { join, basename, relative } from 'node:path';
import { readText, listDir, exists, walk, isSecretPair } from './util.js';
import { parseDotenv } from './scanners.js';

const tilde = (ctx, p) => (p.startsWith(ctx.home) ? '~' + p.slice(ctx.home.length).replace(/\\/g, '/') : p);
const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.turbo', 'vendor', '.venv', 'venv', '__pycache__', 'coverage', '.cache', '.tox', 'site-packages']);
const files = (ctx, root) => walk(root, { maxDepth: ctx.depth, skip: SKIP });

/** PEP 503 normalised name. */
export const pyName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');

/* ---------- Python lockfiles ---------- */
export const isPyLock = (f) => /^requirements[\w.-]*\.(txt|in)$|^constraints[\w.-]*\.txt$/i.test(basename(f)) || ['poetry.lock', 'uv.lock', 'Pipfile.lock', 'pdm.lock', 'pylock.toml'].includes(basename(f));

export function parsePyLock(file, text) {
  const base = basename(file);
  const out = [];
  if (base === 'Pipfile.lock') {
    let j; try { j = JSON.parse(text); } catch { return out; }
    for (const sec of ['default', 'develop']) for (const [n, v] of Object.entries(j[sec] || {})) { const m = String(v?.version || '').match(/^==\s*(\S+)$/); if (m) out.push({ name: pyName(n), version: m[1], hashed: !!v.hashes?.length }); }
  } else if (/\.(lock|toml)$/.test(base)) {
    // poetry.lock / uv.lock / pdm.lock / pylock.toml: [[package]] blocks with name = "..." and version = "..."
    for (const block of text.split(/^\[\[packages?\]\]\s*$/m).slice(1)) {
      const n = block.match(/^name\s*=\s*"([^"]+)"/m);
      const v = block.match(/^version\s*=\s*"([^"]+)"/m);
      if (n && v) out.push({ name: pyName(n[1]), version: v[1], hashed: /hash\s*=\s*"sha256:|"sha256:/.test(block) });
    }
  } else {
    // requirements.txt: join continuation lines; "name[extra]==1.2.3 ; marker --hash=..."
    for (const raw of text.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
      const line = raw.replace(/(^|\s)#.*$/, '').trim();
      if (!line || line.startsWith('-')) continue;
      const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|>|<)?\s*([^\s;,]+)?/);
      if (!m) continue;
      out.push({ name: pyName(m[1]), version: m[3] === '==' || m[3] === '===' ? m[4] : null, spec: m[3] || null, hashed: /--hash[= ]sha256:/.test(line) });
    }
  }
  return out;
}

function sitePackages(root) {
  const out = [];
  for (const env of ['.venv', 'venv', 'env', '.env']) {
    const base = join(root, env);
    if (!exists(join(base, 'pyvenv.cfg'))) continue;
    for (const py of listDir(join(base, 'lib'))) if (py.isDirectory() && /^python3/.test(py.name)) out.push(join(base, 'lib', py.name, 'site-packages'));
    out.push(join(base, 'Lib', 'site-packages'));
  }
  return out.filter(exists);
}

export function scanPython(ctx) {
  const bad = new Map();
  for (const p of ctx.iocs.packages.filter((x) => x.ecosystem === 'PyPI')) { const k = pyName(p.name); bad.set(k, [...(bad.get(k) || []), p]); }
  const out = [];
  const seen = new Set();
  const hit = (p, version, where, how) => {
    const key = `${p.name}@${version}|${where}`;
    if (seen.has(key)) return; seen.add(key);
    out.push({ id: 'supply.malicious-version', category: 'persistence', severity: 'critical', incident: p.incident,
      title: `Known-malicious package ${p.name}==${version} (${p.campaign})`, location: where,
      detail: `${how}. Python runs its startup hooks on every interpreter start, including pip, so don't run Python in that environment first. Rebuild it from scratch pinned to ${p.safe}, then rotate everything the host could reach from a clean machine. ${p.ref}` });
  };
  const find = (name, version) => (bad.get(name) || []).find((p) => p.versions.includes(version));
  for (const root of ctx.projects) {
    for (const f of files(ctx, root)) {
      if (!isPyLock(f)) continue;
      const t = readText(f);
      if (!t) continue;
      for (const { name, version } of parsePyLock(f, t)) { const p = version && find(name, version); if (p) hit(p, version, tilde(ctx, f), 'Pinned in this file'); }
    }
    for (const sp of sitePackages(root)) {
      for (const ent of listDir(sp)) {
        const m = ent.name.match(/^(.+)-([^-]+)\.dist-info$/);
        if (m) { const p = find(pyName(m[1]), m[2]); if (p) hit(p, m[2], tilde(ctx, join(sp, ent.name)), 'Installed in this virtualenv'); }
      }
      const pth = readText(join(sp, 'cook.pth'));
      if (pth && /^\s*import\s+cook\b/m.test(pth)) out.push({ id: 'persistence.python-startup-hook', category: 'persistence', severity: 'critical', incident: 'litellm',
        title: 'litellm 1.107.0 startup hook cook.pth is installed', location: tilde(ctx, join(sp, 'cook.pth')),
        detail: 'Runs the credential stealer at every Python start. From a shell (not Python): delete cook.pth, cook.py, sitecustomize.py and their __pycache__ entries, kill the process holding /tmp/remote_code_loader.lock, rebuild the venv, rotate. https://docs.litellm.ai/blog/security-incident-oct-21-2026' });
    }
  }
  return out;
}

/* ---------- Container image references (Dockerfile FROM, compose image:) ---------- */
export function imageRefs(file, text) {
  const out = [];
  const base = basename(file);
  const stages = new Set();
  if (/^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$/i.test(base)) {
    for (const [i, line] of text.split(/\r?\n/).entries()) {
      const m = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i);
      if (!m) continue;
      if (!stages.has(m[1].toLowerCase())) out.push({ ref: m[1], line: i + 1 });
      if (m[2]) stages.add(m[2].toLowerCase());
    }
    return out;
  }
  if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/i.test(base)) {
    for (const [i, line] of text.split(/\r?\n/).entries()) {
      const m = line.match(/^\s+image:\s*["']?([^"'\s#]+)/);
      if (m) out.push({ ref: m[1], line: i + 1 });
    }
  }
  return out;
}

export function parseImage(ref) {
  const [nameTag, digest] = ref.split('@');
  const slash = nameTag.lastIndexOf('/');
  const colon = nameTag.lastIndexOf(':');
  const hasTag = colon > slash;
  let repo = (hasTag ? nameTag.slice(0, colon) : nameTag).toLowerCase();
  const tag = hasTag ? nameTag.slice(colon + 1) : digest ? null : 'latest';
  if (!/^[^/]+[.:][^/]*\//.test(repo) && !repo.startsWith('localhost/')) repo = 'docker.io/' + (repo.includes('/') ? repo : 'library/' + repo);
  return { repo, tag, digest: digest || null, variable: /\$/.test(ref) };
}

export function scanImages(ctx) {
  const rules = ctx.iocs.images || [];
  const out = [];
  for (const root of ctx.projects) {
    for (const f of files(ctx, root)) {
      if (!/docker|compose|containerfile/i.test(basename(f))) continue;
      const t = readText(f);
      if (!t) continue;
      for (const { ref, line } of imageRefs(f, t)) {
        const img = parseImage(ref);
        for (const r of rules) {
          const repos = r.repos.map((x) => parseImage(x + ':x').repo);
          if (!repos.includes(img.repo)) continue;
          const badDigest = img.digest && (r.digests.includes(img.digest) || (r.digestPrefixes || []).some((p) => img.digest.startsWith(p)));
          const where = `${tilde(ctx, f)}:${line}`;
          if (badDigest || (!img.digest && r.badTags.includes(img.tag))) {
            out.push({ id: 'supply.malicious-image', category: 'persistence', severity: 'critical', incident: r.incident, title: `Compromised image ${ref}`, location: where,
              detail: `This image ran the ${r.incident} stealer. Treat every container started from it as compromised and rotate what it could reach. Use ${r.safe}. ${r.ref}` });
          } else if (!img.digest && r.floatingTags.includes(img.tag)) {
            out.push({ id: 'supply.floating-image-exposed', category: 'persistence', severity: 'high', incident: r.incident, title: `${ref} pointed at the compromised image during ${r.window}`, location: where,
              detail: `Any container that pulled this floating tag in that window ran the stealer. Check pull/start times (\`docker image inspect\`, k8s events). Pin ${r.safe}. ${r.ref}` });
          }
        }
      }
    }
  }
  return out;
}

/* ---------- --harden: preventive settings, each with the exact fix ---------- */
const H = (title, location, detail, fix, severity = 'low', id = 'hardening.config') => ({ id, category: 'hardening', severity, title, location, detail, fix });

export function scanHarden(ctx) {
  const out = [];
  if (!ctx.harden) return out;
  for (const root of ctx.projects) {
    const all = files(ctx, root);
    const rel = (f) => relative(root, f).replace(/\\/g, '/') || basename(f);
    // Docker images not pinned by digest (one finding per file).
    for (const f of all) {
      if (!/docker|compose|containerfile/i.test(basename(f))) continue;
      const t = readText(f);
      if (!t) continue;
      const loose = imageRefs(f, t).map((r) => ({ ...r, img: parseImage(r.ref) })).filter((r) => !r.img.digest && !r.img.variable && r.ref !== 'scratch');
      if (loose.length) out.push(H(`${loose.length} image reference(s) not pinned by digest in ${rel(f)}`, tilde(ctx, f),
        `Tags are mutable: LiteLLM's latest/main-stable pointed at a stealer for ~2.5 hours on Oct 21. Unpinned: ${loose.slice(0, 5).map((r) => r.ref).join(', ')}${loose.length > 5 ? ', …' : ''}.`,
        'Pin as image:tag@sha256:<digest> (get it with `docker buildx imagetools inspect <image:tag>`) and let Dependabot/Renovate bump digests.', 'low', 'hardening.image-digest'));
    }
    // Python: requirements without hashes / unpinned; uv without exclude-newer.
    const hasUvLock = exists(join(root, 'uv.lock'));
    const pyproject = readText(join(root, 'pyproject.toml')) || '';
    const uvToml = readText(join(root, 'uv.toml')) || '';
    for (const f of all.filter((x) => /^requirements[\w.-]*\.txt$/i.test(basename(x)))) {
      const reqs = parsePyLock(f, readText(f) || '');
      if (!reqs.length) continue;
      const unpinned = reqs.filter((r) => !r.version);
      if (unpinned.length) out.push(H(`${unpinned.length} of ${reqs.length} requirement(s) not pinned with == in ${rel(f)}`, tilde(ctx, f),
        `An unpinned \`litellm\` resolved to the malicious 1.107.0 for ~2 hours on Oct 21. Unpinned: ${unpinned.slice(0, 5).map((r) => r.name).join(', ')}${unpinned.length > 5 ? ', …' : ''}.`,
        'Compile a lock: `uv pip compile requirements.in --generate-hashes -o requirements.txt` (or pip-tools `pip-compile --generate-hashes`).', 'low', 'hardening.python-pin'));
      else if (!reqs.every((r) => r.hashed)) out.push(H(`${rel(f)} is pinned but has no --hash entries`, tilde(ctx, f),
        'Hashes make pip refuse any file that differs from the one you locked (pip turns on hash-checking mode when any requirement has --hash).',
        'Regenerate with `--generate-hashes` and install with `pip install --require-hashes -r requirements.txt`.', 'low', 'hardening.python-hashes'));
    }
    if ((hasUvLock || /\[tool\.uv\]/.test(pyproject)) && !/exclude-newer\s*=/.test(pyproject + uvToml)) out.push(H('uv has no release-age cooldown', tilde(ctx, join(root, 'pyproject.toml')),
      'uv can ignore files uploaded too recently; the malicious litellm was live for under 2 hours.',
      'Add `exclude-newer = "3 days"` under [tool.uv] in pyproject.toml (or uv.toml). With pip, where your version supports it: `pip install --uploaded-prior-to P3D`.', 'low', 'hardening.python-cooldown'));
    // pnpm: builds allowed for everything
    const ws = readText(join(root, 'pnpm-workspace.yaml')) || '';
    if (/^\s*dangerouslyAllowAllBuilds\s*:\s*true/m.test(ws)) out.push(H('pnpm runs every dependency\'s build scripts', tilde(ctx, join(root, 'pnpm-workspace.yaml')),
      'pnpm blocks dependency build scripts by default; dangerouslyAllowAllBuilds turns that off, which is how preinstall worms like tensorlake run.',
      'Remove dangerouslyAllowAllBuilds and allow-list only what needs to build (`allowBuilds` / `onlyBuiltDependencies`, or `pnpm approve-builds`).', 'medium', 'hardening.pnpm-builds'));
    // Long-lived publish/cloud secrets in workflows where OIDC exists
    for (const f of all.filter((x) => /[\\/]\.github[\\/]workflows[\\/][^\\/]+\.ya?ml$/.test(x))) {
      const t = readText(f) || '';
      const r = rel(f);
      if (/npm publish|pnpm publish|yarn npm publish/.test(t) && /NODE_AUTH_TOKEN:\s*\$\{\{\s*secrets\./.test(t)) out.push(H(`npm publish uses a long-lived token in ${r}`, tilde(ctx, f), 'A stolen NPM_TOKEN can publish from anywhere. npm trusted publishing uses short-lived OIDC credentials bound to this workflow.', 'Configure a trusted publisher on npmjs.com (package → Settings), add `permissions: id-token: write`, and drop NODE_AUTH_TOKEN. Provenance says where a package was built, not that it is safe.', 'low', 'hardening.oidc'));
      if (/pypa\/gh-action-pypi-publish/.test(t) && /password:\s*\$\{\{\s*secrets\./.test(t)) out.push(H(`PyPI publish uses an API token in ${r}`, tilde(ctx, f), 'PyPI recommends Trusted Publishing over API tokens from CI.', 'Add a trusted publisher on pypi.org, set `permissions: id-token: write`, and remove `password:`.', 'low', 'hardening.oidc'));
      if (/aws-actions\/configure-aws-credentials/.test(t) && /aws-secret-access-key:\s*\$\{\{\s*secrets\./.test(t)) out.push(H(`AWS access keys stored as secrets in ${r}`, tilde(ctx, f), 'Long-lived IAM keys in CI are what GhostAction-style workflows exfiltrate.', 'Use `role-to-assume` with GitHub OIDC (`permissions: id-token: write`) and delete the IAM user keys.', 'low', 'hardening.oidc'));
    }
    // .env files tracked by git or not ignored (needs git)
    if (ctx.exec) {
      const envs = all.filter((f) => /^\.env(\..+)?$/.test(basename(f)) && !/\.(example|sample|template|dist|defaults|demo|emulated|emulator|mock)$/i.test(basename(f)));
      if (envs.length && ctx.exec('git', ['-C', root, 'rev-parse', '--is-inside-work-tree'])) {
        const tracked = new Set((ctx.exec('git', ['-C', root, 'ls-files', '--', ...envs.map(rel)]) || '').split(/\r?\n/).filter(Boolean));
        for (const f of envs) {
          const r = rel(f);
          // Committed env files with only public config (NEXT_PUBLIC_*, URLs, fakes) are normal; flag only real-looking secrets.
          const n = parseDotenv(readText(f) || '').filter(([k, v]) => isSecretPair(k, v)).length;
          if (!n) continue;
          if (tracked.has(r)) out.push(H(`${r} is committed to git with ${n} secret-looking value(s)`, tilde(ctx, f), 'Anyone with repo access (and every fork/clone) has these values, including in history.', `\`git rm --cached ${r}\`, add it to .gitignore, rotate every value in it, and scan history with gitleaks/TruffleHog.`, 'high', 'hardening.env-tracked'));
          else if (ctx.exec('git', ['-C', root, 'check-ignore', '-q', r]) === null) out.push(H(`${r} holds ${n} secret-looking value(s) and is not in .gitignore`, tilde(ctx, f), 'One `git add .` away from being committed.', `Add \`${basename(f)}\` (or \`.env*\` with \`!.env.example\`) to .gitignore.`, 'medium', 'hardening.env-ignore'));
        }
      }
    }
  }
  return out;
}

export const V4_SCANNERS = { python: scanPython, images: scanImages, harden: scanHarden };
