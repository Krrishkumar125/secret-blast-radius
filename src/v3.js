// v0.3 scanners: other ecosystems' credential files, editor extensions, npm cache,
// lockfile exposure windows from git history, and the opt-in OSV malicious lookup.
import { join, basename, relative } from 'node:path';
import { readFileSync, realpathSync } from 'node:fs';
const real = (p) => { try { return realpathSync.native(p); } catch { return p; } };
import { readText, listDir, exists, walk, isReference, fingerprint } from './util.js';
import { parseLockfile } from './supply.js';

const EXT_IOCS = JSON.parse(readFileSync(new URL('./extension-iocs.json', import.meta.url), 'utf8'));
const tilde = (ctx, p) => (p.startsWith(ctx.home) ? '~' + p.slice(ctx.home.length).replace(/\\/g, '/') : p);
const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.turbo', 'vendor', '.venv', 'venv', '__pycache__', 'coverage', '.cache']);
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock']);

/* ---------- 1. Other ecosystems' credential files ---------- */
// Paths come from each tool's own docs (see README "Sources").
export function scanEcosystems(ctx) {
  const out = [];
  const h = ctx.home;
  const appData = join(h, 'AppData', 'Roaming');
  const add = (f, title, value, severity, detail, category = 'npm') =>
    out.push({ id: 'registry.plaintext-token', category, severity, title, location: tilde(ctx, f), fingerprint: value ? fingerprint(value) : undefined, detail });

  // RubyGems: ~/.gem/credentials or ~/.local/share/gem/credentials (YAML ":rubygems_api_key: rubygems_...")
  for (const f of [join(h, '.gem', 'credentials'), join(h, '.local', 'share', 'gem', 'credentials')]) {
    const t = readText(f);
    if (!t) continue;
    for (const m of t.matchAll(/^\s*(:?[\w-]*api_key|https?:\/\/\S+?):\s+(\S+)\s*$/gm)) {
      if (isReference(m[2])) continue;
      add(f, 'Plaintext RubyGems API key', m[2], 'critical', 'Lets a stealer push gems you own. Delete it at rubygems.org → Settings → API keys, then `gem signin` with a gem-scoped key that has an expiry and MFA.');
    }
  }
  // Cargo: $CARGO_HOME/credentials.toml (cargo:token provider stores tokens in plain text)
  const cargoHome = ctx.env.CARGO_HOME || join(h, '.cargo');
  for (const f of [join(cargoHome, 'credentials.toml'), join(cargoHome, 'credentials')]) {
    const t = readText(f);
    if (!t) continue;
    for (const m of t.matchAll(/^\s*token\s*=\s*"([^"]+)"/gm)) {
      if (isReference(m[1])) continue;
      add(f, 'Plaintext crates.io / Cargo registry token', m[1], 'critical', 'cargo:token stores tokens unencrypted. Revoke at crates.io/settings/tokens, then configure `global-credential-providers` (cargo:libsecret / macos-keychain / wincred) and `cargo login` again.');
    }
  }
  // Composer: project auth.json and global auth.json
  const composerHomes = [ctx.env.COMPOSER_HOME, join(h, '.config', 'composer'), join(h, '.composer'), join(appData, 'Composer')].filter(Boolean);
  const composerFiles = [...composerHomes.map((d) => join(d, 'auth.json')), ...ctx.projects.map((p) => join(p, 'auth.json'))];
  for (const f of new Set(composerFiles)) {
    const t = readText(f);
    if (!t) continue;
    let j; try { j = JSON.parse(t); } catch { continue; }
    const vals = [];
    for (const kind of ['github-oauth', 'gitlab-oauth', 'gitlab-token', 'bearer', 'forgejo-token', 'http-basic', 'bitbucket-oauth']) {
      for (const [host, v] of Object.entries(j?.[kind] || {})) {
        const secret = typeof v === 'string' ? v : v?.password ?? v?.token ?? v?.['consumer-secret'];
        if (typeof secret === 'string' && !isReference(secret)) vals.push([kind, host, secret]);
      }
    }
    for (const [kind, host, secret] of vals) {
      const inProject = ctx.projects.some((p) => f === join(p, 'auth.json'));
      add(f, `Composer ${kind} credential for ${host}${inProject ? ' (project auth.json)' : ''}`, secret, kind === 'github-oauth' ? 'high' : 'medium',
        (inProject ? 'Composer docs: keep auth.json in .gitignore. ' : '') + 'Revoke the token at the host and re-add it with `composer config --global --auth`. For GitHub prefer a fine-grained, read-only, expiring token.', kind === 'github-oauth' ? 'github' : 'npm');
    }
  }
  // Terraform CLI: ~/.terraform.d/credentials.tfrc.json  ({credentials: {host: {token}}})
  for (const f of [join(h, '.terraform.d', 'credentials.tfrc.json'), join(appData, 'terraform.d', 'credentials.tfrc.json')]) {
    const t = readText(f);
    if (!t) continue;
    try {
      for (const [host, v] of Object.entries(JSON.parse(t).credentials || {})) if (v?.token && !isReference(v.token)) add(f, `Terraform token for ${host}`, v.token, 'high', 'Can run plans/applies in your HCP Terraform workspaces (and read their state and variables). `terraform logout`, revoke at the host, then `terraform login`.', 'cloud');
    } catch {}
  }
  // Pulumi: ~/.pulumi/credentials.json  ({accessTokens: {url: token}})
  {
    const f = join(ctx.env.PULUMI_HOME || join(h, '.pulumi'), 'credentials.json');
    const t = readText(f);
    if (t) {
      try {
        for (const [url, tok] of Object.entries(JSON.parse(t).accessTokens || {})) if (typeof tok === 'string' && tok && !isReference(tok)) add(f, `Pulumi access token for ${url}`, tok, 'high', 'Reads stack state and decrypts config secrets. `pulumi logout`, delete the token in Pulumi Cloud → Access tokens, then `pulumi login`.', 'cloud');
      } catch {}
    }
  }
  // Local Terraform state files in projects: often hold resource secrets in plain text.
  for (const root of ctx.projects) {
    for (const f of walk(root, { maxDepth: ctx.depth, skip: SKIP })) {
      if (!/\.tfstate(\.backup)?$/.test(f)) continue;
      const t = readText(f);
      if (!t || !/"resources"\s*:\s*\[\s*\{/.test(t)) continue;
      out.push({ id: 'cloud.tfstate', category: 'cloud', severity: 'medium', title: 'Local Terraform state file', location: tilde(ctx, f),
        detail: 'Terraform state stores resource attributes, including passwords and keys, in plain text. Move state to an encrypted remote backend and treat secrets in it as exposed if this machine is.' });
    }
  }
  return out;
}

/* ---------- 2. Editor extensions (VS Code, Cursor, Windsurf, VSCodium, remote servers) ---------- */
export function extensionDirs(ctx) {
  const h = ctx.home;
  return [
    ['VS Code', join(h, '.vscode', 'extensions')], ['VS Code Insiders', join(h, '.vscode-insiders', 'extensions')],
    ['VS Code Server', join(h, '.vscode-server', 'extensions')], ['Cursor', join(h, '.cursor', 'extensions')],
    ['Cursor Server', join(h, '.cursor-server', 'extensions')], ['Windsurf', join(h, '.windsurf', 'extensions')],
    ['VSCodium', join(h, '.vscode-oss', 'extensions')], ['Kiro', join(h, '.kiro', 'extensions')], ['Antigravity', join(h, '.antigravity', 'extensions')],
  ];
}

export function scanExtensions(ctx) {
  const iocs = new Map([...EXT_IOCS.extensions, ...(ctx.iocs.extensions || [])].map((e) => [e.id.toLowerCase(), e]));
  const out = [];
  for (const [editor, dir] of extensionDirs(ctx)) {
    for (const ent of listDir(dir)) {
      if (!ent.isDirectory()) continue;
      const pj = readText(join(dir, ent.name, 'package.json'));
      if (!pj) continue;
      let j; try { j = JSON.parse(pj); } catch { continue; }
      if (!j.publisher || !j.name) continue;
      const id = `${j.publisher}.${j.name}`.toLowerCase();
      const related = [id, ...(j.extensionPack || []), ...(j.extensionDependencies || [])].map((x) => String(x).toLowerCase());
      for (const rid of related) {
        const ioc = iocs.get(rid);
        if (!ioc) continue;
        if (rid === id && ioc.versions && !ioc.versions.includes(j.version)) continue;
        const via = rid === id ? '' : ` (pulled in by ${id} via extensionPack/extensionDependencies)`;
        out.push({
          id: 'editor.malicious-extension', category: 'persistence', severity: ioc.status === 'sleeper' ? 'high' : 'critical', incident: 'glassworm',
          title: `${ioc.status === 'sleeper' ? 'Flagged sleeper' : 'Known-malicious'} ${editor} extension ${rid}${rid === id ? '@' + j.version : ''}${via}`,
          location: tilde(ctx, join(dir, ent.name)),
          detail: (ioc.status === 'sleeper' ? 'Published as a benign clone, then able to turn malicious via an update. ' : 'GlassWorm extensions steal GitHub/npm/Open VSX tokens and crypto wallets. ') +
            `Uninstall it, check other extensions from the same publisher, then rotate from a clean machine. ${ioc.ref}`,
        });
      }
    }
  }
  return out;
}

/* ---------- 3. npm cache: tarballs of known-bad versions were fetched on this machine ---------- */
export function scanNpmCache(ctx) {
  const bad = ctx.iocs.packages.filter((p) => p.ecosystem === 'npm');
  if (!bad.length) return [];
  const needles = bad.flatMap((p) => p.versions.map((v) => ({ p, v, s: `/${p.name}/-/${p.name.split('/').pop()}-${v}.tgz` })));
  const dirs = [ctx.env.npm_config_cache && join(ctx.env.npm_config_cache, '_cacache'), join(ctx.home, '.npm', '_cacache'), join(ctx.home, 'AppData', 'Local', 'npm-cache', '_cacache')].filter(Boolean);
  const out = [];
  const seen = new Set();
  for (const d of new Set(dirs)) {
    const idx = join(d, 'index-v5');
    if (!exists(idx)) continue;
    for (const f of walk(idx, { maxDepth: 3 })) {
      const t = readText(f);
      if (!t || !t.includes('/-/')) continue;
      for (const n of needles) {
        if (seen.has(n.s) || !t.includes(n.s)) continue;
        seen.add(n.s);
        out.push({ id: 'supply.npm-cache-hit', category: 'persistence', severity: 'critical', incident: n.p.incident,
          title: `npm cache holds ${n.p.name}@${n.v} (${n.p.campaign})`, location: tilde(ctx, d),
          detail: `This machine downloaded the malicious tarball at some point, even if no current lockfile has it. Assume its install script ran: check persistence first, then rotate from a clean device. Clear with \`npm cache clean --force\` only after you have collected evidence. ${n.p.ref}` });
      }
    }
  }
  return out;
}

/* ---------- 4. Exposure window from lockfile git history ---------- */
const MAX_COMMITS = 400;
export function scanHistory(ctx) {
  if (!ctx.exec || !ctx.history) return [];
  const bad = new Map(ctx.iocs.packages.filter((p) => p.ecosystem === 'npm').map((p) => [p.name, p]));
  const out = [];
  for (const root of ctx.projects) {
    const top = ctx.exec('git', ['-C', root, 'rev-parse', '--show-toplevel']);
    if (!top) continue;
    const repo = real(top.trim());
    const lockRel = walk(real(root), { maxDepth: ctx.depth, skip: SKIP }).filter((f) => LOCKFILES.has(basename(f))).map((f) => relative(repo, f).replace(/\\/g, '/'));
    for (const lf of lockRel) {
      const args = ['-C', repo, 'log', `--max-count=${MAX_COMMITS}`, '--format=%H %cI', ...(ctx.history.since ? [`--since=${ctx.history.since}`] : []), '--', lf];
      const log = ctx.exec('git', args);
      if (!log) continue;
      const commits = log.trim().split('\n').filter(Boolean).map((l) => { const [sha, date] = l.split(' '); return { sha, date }; }).reverse(); // oldest first
      const intervals = []; // {key, start, end}
      const open = new Map();
      for (const c of commits) {
        const text = ctx.exec('git', ['-C', repo, 'show', `${c.sha}:${lf}`]);
        const now = new Set();
        if (text) for (const { name, version } of parseLockfile(lf, text)) if (bad.get(name)?.versions.includes(version)) now.add(`${name}@${version}`);
        for (const k of now) if (!open.has(k)) open.set(k, { key: k, start: c, end: null });
        for (const [k, iv] of open) if (!now.has(k)) { iv.end = c; intervals.push(iv); open.delete(k); }
      }
      intervals.push(...open.values());
      for (const iv of intervals) {
        const k = iv.key;
        const p = bad.get(k.slice(0, k.lastIndexOf('@')));
        const w = { first: iv.start, removed: iv.end };
        const still = !w.removed;
        out.push({ id: 'supply.history-exposure', category: 'persistence', severity: still ? 'critical' : 'high', incident: p.incident,
          title: `${k} was in ${lf} ${w.first.date.slice(0, 10)} → ${still ? 'now (still present)' : w.removed.date.slice(0, 10)}`,
          location: `${tilde(ctx, repo)} (${lf} @ ${w.first.sha.slice(0, 7)})`,
          detail: `Any machine or CI run that installed from this lockfile in that window may have run the payload. Check CI logs/runners for those dates and rotate the secrets they held. ${p.ref}` });
      }
      if (commits.length >= MAX_COMMITS) out.push({ id: 'supply.history-truncated', category: 'hardening', severity: 'low', title: `Lockfile history truncated at ${MAX_COMMITS} commits`, location: `${tilde(ctx, repo)}/${lf}`, detail: 'Use --since <date> to focus on the incident window.' });
    }
  }
  return out;
}

/* ---------- 5. Opt-in OSV lookup for MAL- advisories (network) ---------- */
const OSV_ECOSYSTEM = { npm: 'npm' };
export function collectPackages(ctx) {
  const pkgs = new Map();
  for (const root of ctx.projects) {
    for (const f of walk(root, { maxDepth: ctx.depth, skip: SKIP })) {
      if (!LOCKFILES.has(basename(f))) continue;
      const t = readText(f);
      if (!t) continue;
      for (const { name, version } of parseLockfile(f, t)) if (name && /^\d/.test(version)) pkgs.set(`${name}@${version}`, { name, version, ecosystem: 'npm', file: tilde(ctx, f) });
    }
  }
  return [...pkgs.values()];
}

export async function osvMalicious(ctx, { fetchImpl = globalThis.fetch, endpoint = 'https://api.osv.dev/v1/querybatch', batch = 500 } = {}) {
  const pkgs = collectPackages(ctx);
  const out = [];
  if (!pkgs.length) return { findings: out, queried: 0 };
  if (typeof fetchImpl !== 'function') throw new Error('--osv needs Node 18+ (global fetch)');
  for (let i = 0; i < pkgs.length; i += batch) {
    const chunk = pkgs.slice(i, i + batch);
    // Only package names and versions leave the machine: never file contents or secrets.
    const res = await fetchImpl(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: OSV_ECOSYSTEM[p.ecosystem] }, version: p.version })) }) });
    if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
    const j = await res.json();
    (j.results || []).forEach((r, k) => {
      const mal = (r?.vulns || []).filter((v) => /^MAL-/.test(v.id));
      if (!mal.length) return;
      const p = chunk[k];
      out.push({ id: 'supply.osv-malicious', category: 'persistence', severity: 'critical',
        title: `OSV lists ${p.name}@${p.version} as malicious (${mal.map((v) => v.id).join(', ')})`, location: p.file,
        detail: `Malicious-package advisory from the OpenSSF malicious-packages feed via OSV. Treat machines that installed it as compromised. https://osv.dev/vulnerability/${mal[0].id}` });
    });
  }
  return { findings: out, queried: pkgs.length };
}

export const V3_SCANNERS = { ecosystems: scanEcosystems, extensions: scanExtensions, 'npm-cache': scanNpmCache, history: scanHistory };
