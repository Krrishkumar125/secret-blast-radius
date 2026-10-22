import { join, relative, dirname, basename } from 'node:path';
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readText, listDir, exists, walk, isReference } from './util.js';

const BUNDLED = JSON.parse(readFileSync(new URL('./iocs.json', import.meta.url), 'utf8'));
const SKIP = new Set(['.git', 'dist', 'build', '.next', '.turbo', 'vendor', '.venv', 'venv', '__pycache__', 'coverage', '.cache']);
const rel = (root, p) => relative(root, p).replace(/\\/g, '/') || basename(p);
const tilde = (ctx, p) => (p.startsWith(ctx.home) ? '~' + p.slice(ctx.home.length).replace(/\\/g, '/') : p);

export function loadIocs(extraFiles = []) {
  const merged = { updated: BUNDLED.updated, packages: [...BUNDLED.packages], extensions: [], images: [...(BUNDLED.images || [])], markers: structuredClone(BUNDLED.markers) };
  for (const f of extraFiles) {
    const j = JSON.parse(readFileSync(f, 'utf8'));
    merged.packages.push(...(j.packages || []));
    merged.extensions.push(...(j.extensions || []));
    merged.images.push(...(j.images || []));
    for (const [k, v] of Object.entries(j.markers || {})) merged.markers[k] = [...new Set([...(merged.markers[k] || []), ...v])];
    if (j.updated && j.updated > merged.updated) merged.updated = j.updated;
  }
  return merged;
}

/* ---------- lockfile parsing: returns [{name, version}] ---------- */
export function parseLockfile(file, text) {
  const out = [];
  const base = basename(file);
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
    let j; try { j = JSON.parse(text); } catch { return out; }
    for (const [k, v] of Object.entries(j.packages || {})) {
      if (!k || !v?.version) continue;
      const name = v.name || k.slice(k.lastIndexOf('node_modules/') + 13);
      out.push({ name, version: v.version, hasInstallScript: !!v.hasInstallScript });
    }
    const walkV1 = (deps) => { for (const [name, v] of Object.entries(deps || {})) { if (v?.version) out.push({ name, version: v.version }); walkV1(v.dependencies); } };
    if (!j.packages) walkV1(j.dependencies);
  } else if (base === 'pnpm-lock.yaml') {
    // v6: "/name@1.2.3:" or "/@scope/name@1.2.3(peer):"; v9: "name@1.2.3:"; v5: "/name/1.2.3:"
    let current = null;
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^ {2}'?\/?((?:@[^/@\s]+\/)?[^/@\s:']+)[@/](\d[^:(\s']*)(?:\([^:]*\))?'?:\s*$/);
      if (m) { current = { name: m[1], version: m[2] }; out.push(current); continue; }
      if (current && /^ {4}requiresBuild: true/.test(line)) current.hasInstallScript = true;
      if (/^\S/.test(line)) current = null;
    }
  } else if (base === 'yarn.lock') {
    let names = null;
    for (const line of text.split(/\r?\n/)) {
      if (/^\S.*:$/.test(line) && !line.startsWith('#')) {
        names = line.slice(0, -1).split(/,\s*/).map((s) => s.replace(/^"|"$/g, '')).map((s) => s.slice(0, s.lastIndexOf('@')) || s);
        continue;
      }
      const v = line.match(/^ {2}version:?\s+"?([^"\s]+)"?/);
      if (v && names) { for (const n of new Set(names)) out.push({ name: n.replace(/@npm:.*$/, ''), version: v[1] }); names = null; }
    }
  } else if (base === 'bun.lock') {
    for (const m of text.matchAll(/"((?:@[^"/@]+\/)?[^"/@]+)@(\d[^"]*)"/g)) out.push({ name: m[1], version: m[2] });
  }
  return out;
}

const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock']);

function projectFiles(ctx, root, includeNodeModules = false) {
  const skip = new Set(SKIP);
  if (!includeNodeModules) skip.add('node_modules');
  return walk(root, { maxDepth: ctx.depth, skip });
}

/* ---------- 1. Known-malicious package versions (lockfiles + installed copies) ---------- */
export function scanMalicious(ctx) {
  const iocs = ctx.iocs;
  const bad = new Map(iocs.packages.filter((p) => p.ecosystem === 'npm').map((p) => [p.name, p]));
  const out = [];
  const seen = new Set();
  const hit = (pkg, version, where, how) => {
    const key = `${pkg.name}@${version}|${where}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      id: 'supply.malicious-version', category: 'persistence', severity: 'critical', incident: pkg.incident,
      title: `Known-malicious package ${pkg.name}@${version} (${pkg.campaign})`,
      location: where,
      detail: `${how}. Treat every machine/CI runner that installed it as compromised: remove persistence first, then rotate from a clean device. Safe version: ${pkg.safe}. ${pkg.ref}`,
    });
  };
  for (const root of ctx.projects) {
    for (const f of projectFiles(ctx, root)) {
      const base = basename(f);
      if (LOCKFILES.has(base)) {
        const text = readText(f);
        if (!text) continue;
        const parsed = parseLockfile(f, text);
        for (const { name, version } of parsed) {
          const p = bad.get(name);
          if (p && p.versions.includes(version)) hit(p, version, tilde(ctx, f), 'Resolved in this lockfile');
        }
        for (const marker of iocs.markers.optionalDependencies || []) {
          if (parsed.some((p) => p.name === marker)) {
            out.push({ id: 'supply.worm-marker', category: 'persistence', severity: 'critical', incident: 'shai-hulud', title: `Shai-Hulud marker dependency ${marker} in lockfile`, location: tilde(ctx, f), detail: 'The Mini Shai-Hulud worm adds this optionalDependency when it republishes a package. Find which package pulled it in.' });
          }
        }
      }
    }
    // Installed copies: node_modules/<name>/package.json for each IOC name (cheap, exact).
    for (const [name, p] of bad) {
      for (const nm of [join(root, 'node_modules', ...name.split('/'))]) {
        const pj = readText(join(nm, 'package.json'));
        if (!pj) continue;
        try { const v = JSON.parse(pj).version; if (p.versions.includes(v)) hit(p, v, tilde(ctx, nm), 'Installed in node_modules'); } catch {}
      }
    }
  }
  return out;
}

/* ---------- 2. Install-script exposure from lockfiles ---------- */
export function scanInstallScripts(ctx) {
  const out = [];
  for (const root of ctx.projects) {
    for (const f of projectFiles(ctx, root)) {
      if (!LOCKFILES.has(basename(f))) continue;
      const text = readText(f);
      if (!text) continue;
      const pkgs = parseLockfile(f, text).filter((p) => p.hasInstallScript);
      const names = [...new Set(pkgs.map((p) => p.name))].sort();
      if (!names.length) continue;
      out.push({
        id: 'supply.install-scripts', category: 'hardening', severity: 'low',
        title: `${names.length} dependenc${names.length === 1 ? 'y runs' : 'ies run'} install scripts (${rel(root, f)})`,
        location: tilde(ctx, f), names,
        detail: `${names.slice(0, 12).join(', ')}${names.length > 12 ? ', …' : ''}. Each runs with your user's access to every secret above on \`npm install\`. Allow-list these (pnpm \`allowBuilds\`, \`@lavamoat/allow-scripts\`) and set \`ignore-scripts=true\` for the rest.`,
      });
    }
  }
  return out;
}

/* ---------- 3. Repo-level worm artefacts (GhostAction, Shai-Hulud, PolinRider-style launchers) ---------- */
const NON_CODE_EXT = /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp|bmp|mp3|mp4|wav|pdf|txt|css|md|lock)(\s|"|'|$)/i;

export function scanRepo(ctx) {
  const out = [];
  const ips = ctx.iocs.markers.ips || [];
  const domains = ctx.iocs.markers.domains || [];
  for (const root of ctx.projects) {
    // .vscode/tasks.json auto-run launchers
    for (const f of projectFiles(ctx, root).filter((p) => /[\\/]\.vscode[\\/]tasks\.json$/.test(p))) {
      let j; try { j = JSON.parse(readText(f).replace(/^\s*\/\/.*$/gm, '')); } catch { continue; }
      for (const t of j.tasks || []) {
        if (t?.runOptions?.runOn !== 'folderOpen') continue;
        const cmd = [t.command, ...(t.args || [])].filter((x) => typeof x === 'string').join(' ');
        const hidden = t.hide === true || t.presentation?.reveal === 'never';
        const disguised = /\b(node|bun|deno|python3?|bash|sh)\s+\S+/.test(cmd) && NON_CODE_EXT.test(cmd);
        const fetches = /(curl|wget|iwr|Invoke-WebRequest)[^|]*\|\s*(ba)?sh|https?:\/\/\d+\.\d+\.\d+\.\d+/.test(cmd);
        if (!(disguised || fetches || hidden)) continue;
        out.push({
          id: 'repo.autorun-task', category: 'persistence', severity: disguised || fetches ? 'critical' : 'medium', incident: 'ghostaction',
          title: `VS Code task "${t.label || '?'}" auto-runs on folder open${disguised ? ' and executes a non-code file' : ''}`,
          location: tilde(ctx, f),
          detail: disguised || fetches
            ? 'Matches the GhostAction / PolinRider launcher (tasks.json → `node public/fonts/*.woff2`). Do not open this folder in VS Code; check `crontab -l` for `#ghc2`; rotate credentials from a clean device.'
            : 'Hidden task that runs when the folder is opened. Legitimate uses exist; confirm you added it.',
        });
      }
    }
    // Claude Code project hooks that run disguised files or pipe the network into a shell
    for (const f of [join(root, '.claude', 'settings.json'), join(root, '.claude', 'settings.local.json')]) {
      const text = readText(f);
      if (!text) continue;
      let j; try { j = JSON.parse(text); } catch { continue; }
      const cmds = JSON.stringify(j.hooks || {}).match(/"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g) || [];
      for (const c of cmds) {
        const cmd = JSON.parse(c.replace(/^"command"\s*:\s*/, ''));
        if ((/\b(node|bun|bash|sh)\s+\S+/.test(cmd) && NON_CODE_EXT.test(cmd)) || /(curl|wget)[^|]*\|\s*(ba)?sh/.test(cmd) || ips.some((ip) => cmd.includes(ip))) {
          out.push({ id: 'repo.agent-hook', category: 'persistence', severity: 'critical', incident: 'shai-hulud', title: 'Claude Code hook runs a disguised file or remote script', location: tilde(ctx, f), detail: 'Shai-Hulud plants .claude/settings.json and .vscode/tasks.json so opening the repo in an agent or editor runs the payload. Remove it and treat the machine as exposed.' });
        }
      }
    }
    // Workflows
    const wfDir = join(root, '.github', 'workflows');
    for (const ent of listDir(wfDir)) {
      if (!ent.isFile() || !/\.ya?ml$/.test(ent.name)) continue;
      const f = join(wfDir, ent.name);
      const text = readText(f) || '';
      const ioc = [...ips, ...domains].find((x) => text.includes(x));
      const historyDump = /git\s+log\s+-p\s+--all/.test(text) && /curl\b[^\n]*(-d|--data|--data-binary|-F|-X\s*POST)/.test(text);
      const allSecrets = /toJSON\(\s*secrets\s*\)/.test(text) && /curl|wget|nc\s/.test(text);
      if (!(ioc || historyDump || allSecrets)) continue;
      out.push({
        id: 'repo.exfil-workflow', category: 'persistence', severity: ioc ? 'critical' : 'high', incident: 'ghostaction',
        title: `Workflow ${ent.name} ${ioc ? `contacts known attacker infrastructure (${ioc})` : historyDump ? 'dumps git history and POSTs it' : 'serialises all secrets and sends them out'}`,
        location: tilde(ctx, f),
        detail: 'GhostAction pushes "security audit" workflows that exfiltrate Actions secrets and every credential in git history. Revoke the pushing account\'s tokens/OAuth grants first, then remove the file on every branch and rotate repo secrets plus anything ever committed.',
      });
    }
    // Worm branch names
    const refsText = [readText(join(root, '.git', 'packed-refs')) || '', ...((ctx.iocs.markers.branches || []).filter((b) => exists(join(root, '.git', 'refs', 'heads', ...b.split('/'))) || exists(join(root, '.git', 'refs', 'remotes', 'origin', ...b.split('/')))))].join('\n');
    for (const b of ctx.iocs.markers.branches || []) {
      if (refsText.includes(b)) out.push({ id: 'repo.worm-branch', category: 'persistence', severity: 'high', incident: 'tensorlake', title: `Worm branch "${b}" exists in this repo`, location: tilde(ctx, join(root, '.git')), detail: 'The tensorlake worm pushes this branch with a fake formatter workflow. Delete it remotely and check who pushed it.' });
    }
  }
  return out;
}

/* ---------- 4. Host persistence beyond gh-token-monitor ---------- */
export function scanHostPersistence(ctx) {
  const out = [];
  const m = ctx.iocs.markers;
  for (const f of m.files || []) {
    if (process.platform === 'win32' || !ctx.checkTmp || !exists(f)) continue;
    const ll = /remote_code_loader|\.pc_once_/.test(f);
    out.push({ id: 'persistence.ioc-file', category: 'persistence', severity: 'critical', incident: ll ? 'litellm' : 'subql', title: `Infection marker ${f} present`, location: f,
      detail: ll ? 'Left by the litellm 1.107.0 payload (loader lock or upload marker). The upload marker means exfiltration succeeded. Do not start Python/pip first: delete cook.pth, cook.py, sitecustomize.py from site-packages, kill the loader, rebuild, then rotate.' : '@subql/common@5.8.3 leaves this lock file. Its detached stealer survives `npm uninstall`; isolate and rebuild the host.' });
  }
  if (!ctx.exec) return out;
  const cron = ctx.exec('crontab', ['-l']);
  if (cron) {
    for (const line of cron.split(/\r?\n/)) {
      if (line.trim().startsWith('#')) continue;
      const marker = (m.cron || []).find((x) => line.includes(x));
      const pipe = /(curl|wget)\s[^|]*\|\s*(ba)?sh/.test(line) && /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(line);
      if (marker || pipe) out.push({ id: 'persistence.cron', category: 'persistence', severity: 'critical', incident: 'ghostaction', title: 'Crontab entry pulls and runs remote scripts', location: 'crontab -l', detail: `${marker ? `Matches GhostAction marker "${marker}". ` : ''}The machine runs whatever the server sends every few minutes. Remove the line (\`crontab -e\`), disconnect, then rotate from a clean device.` });
    }
  }
  const ps = ctx.exec('ps', ['-eo', 'args']);
  if (ps) {
    for (const proc of m.processes || []) {
      if (ps.split(/\r?\n/).some((l) => l.includes(proc) && !l.includes('secret-blast-radius'))) out.push({ id: 'persistence.process', category: 'persistence', severity: 'critical', incident: proc.includes('manifest') ? 'subql' : 'tensorlake', title: `Worm process running: ${proc}`, location: 'ps', detail: 'Kill it and isolate the machine before rotating anything.' });
    }
  }
  return out;
}

/* ---------- 5. PHP2Shell: CVE-2026-109618 / CVE-2026-109619 ---------- */
export const PHP_FIXED = { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 };

/** Returns {status: 'fixed'|'vulnerable'|'eol'|'unknown'|'floating', fixed?} */
export function phpStatus(version) {
  const m = String(version).match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return { status: 'unknown' };
  const [maj, min, patch] = [Number(m[1]), Number(m[2]), m[3] === undefined ? null : Number(m[3])];
  const branch = `${maj}.${min}`;
  if (maj < 8 || (maj === 8 && min <= 1)) return { status: 'eol', branch };
  const fixedPatch = PHP_FIXED[branch];
  if (fixedPatch === undefined) return { status: maj > 8 || min > 5 ? 'fixed' : 'unknown', branch };
  const fixed = `${branch}.${fixedPatch}`;
  if (patch === null) return { status: 'floating', branch, fixed };
  return { status: patch >= fixedPatch ? 'fixed' : 'vulnerable', branch, fixed };
}

const PHP_REF = 'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching';

function phpFinding(where, version, st, source, distro = false) {
  if (st.status === 'fixed' || st.status === 'unknown') return null;
  const base = { id: 'php.php2shell', category: 'php', incident: 'php2shell', location: where };
  if (st.status === 'eol') return { ...base, severity: 'critical', title: `PHP ${version} (${source}) is end-of-life and unpatched for PHP2Shell`, detail: `PHP ≤ 8.1 gets no fix for CVE-2026-109618/-109619 (unauthenticated RCE). Upgrade to 8.2.35+ (8.4.27 / 8.5.12 recommended); CISA advises taking unpatchable internet-facing systems offline. ${PHP_REF}` };
  return { ...base, severity: distro ? 'high' : 'critical', title: `PHP ${version} (${source}) is vulnerable to PHP2Shell; fixed in ${st.fixed}`, detail: `${distro ? 'Distro build: your vendor may have backported the fix, so check its security tracker before assuming you are safe. ' : ''}CVE-2026-109618/-109619 allow unauthenticated RCE (demonstrated on Apache mod_php; also PHP-FPM via app code paths). Update to ${st.fixed}+ and restart every PHP worker. ${PHP_REF}` };
}

export function scanPhp(ctx) {
  const out = [];
  if (ctx.exec) {
    const v = ctx.exec('php', ['-r', 'echo PHP_VERSION, "|", PHP_EXTRA_VERSION, "|", PHP_BINARY;']);
    const [ver, extra = '', bin = ''] = (v || '').trim().split('|');
    if (/^\d+\.\d+/.test(ver)) {
      // Distro packages (/usr/bin/php, or a vendor suffix) often carry backported fixes without bumping PHP_VERSION.
      const distro = !!extra || /^\/usr\/(s?bin)\//.test(bin);
      const f = phpFinding(bin || 'php on PATH', ver + extra, phpStatus(ver), 'local php binary', distro);
      if (f) out.push(f);
    }
  }
  for (const root of ctx.projects) {
    for (const f of projectFiles(ctx, root)) {
      const base = basename(f);
      const isDocker = /^(Dockerfile|Containerfile)(\..+)?$|\.Dockerfile$/i.test(base);
      const isCompose = /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/i.test(base);
      if (!isDocker && !isCompose) continue;
      const text = readText(f);
      if (!text) continue;
      const floating = [];
      const re = isDocker ? /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/gim : /^\s*image:\s*["']?([^\s"']+)/gim;
      for (const m of text.matchAll(re)) {
        const image = m[1];
        const noDigest = image.split('@')[0];
        const colon = noDigest.lastIndexOf(':');
        if (colon < 0 || noDigest.slice(colon).includes('/')) continue;
        const repoName = noDigest.slice(0, colon).split('/').pop();
        if (!/^php(-fpm|-apache|-cli|-zts)?$/i.test(repoName)) continue;
        const tag = noDigest.slice(colon + 1);
        if (!/^\d/.test(tag)) {
          if (/^(latest|apache|fpm|cli|zts|alpine)/i.test(tag)) floating.push(image);
          continue;
        }
        const st = phpStatus(tag);
        if (st.status === 'floating') { floating.push(image); continue; }
        const fnd = phpFinding(tilde(ctx, f), tag, st, `image ${image}`);
        if (fnd) out.push(fnd);
      }
      if (floating.length) {
        const uniq = [...new Set(floating)];
        out.push({ id: 'php.floating-tag', category: 'php', incident: 'php2shell', severity: 'low', title: `${uniq.length} PHP image tag${uniq.length > 1 ? 's' : ''} without a patch version (${uniq.slice(0, 3).join(', ')}${uniq.length > 3 ? ', …' : ''})`, location: tilde(ctx, f), detail: 'Tags like php:8.3-fpm move to the fixed release, but images you already built (and CI layer caches) keep the old patch. Rebuild with `--pull --no-cache` and confirm `php -v` shows 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later.' });
      }
    }
    const composer = readText(join(root, 'composer.json'));
    if (composer) {
      try {
        const pv = JSON.parse(composer)?.config?.platform?.php;
        if (pv) {
          const st = phpStatus(pv);
          if (st.status === 'eol') out.push({ id: 'php.platform-eol', category: 'php', incident: 'php2shell', severity: 'medium', title: `composer.json pins platform PHP ${pv} (end-of-life)`, location: tilde(ctx, join(root, 'composer.json')), detail: 'config.platform.php tells Composer you deploy on an EOL PHP that will not get the PHP2Shell fix. Plan the upgrade to 8.2.35+.' });
        }
      } catch {}
    }
  }
  return out;
}

/* ---------- 6. PaaS-linked secrets (Railway, Vercel, Fly, Heroku, Render, Netlify) ---------- */
export function scanPaas(ctx) {
  const out = [];
  const h = ctx.home;
  const cli = [
    { p: [join(h, '.railway', 'config.json')], name: 'Railway CLI', key: /"token"\s*:\s*"[^"]{8,}"/, rotate: 'railway logout && railway login; revoke old tokens under Account → Tokens' },
    { p: [join(h, '.local', 'share', 'com.vercel.cli', 'auth.json'), join(h, 'Library', 'Application Support', 'com.vercel.cli', 'auth.json'), join(h, 'AppData', 'Roaming', 'com.vercel.cli', 'Data', 'auth.json')], name: 'Vercel CLI', key: /"token"\s*:\s*"[^"]{8,}"/, rotate: 'vercel logout; revoke at vercel.com/account/tokens' },
    { p: [join(h, '.fly', 'config.yml')], name: 'Fly.io CLI', key: /access_token:\s*\S{8,}/, rotate: 'fly auth logout; revoke at fly.io/user/personal_access_tokens' },
    { p: [join(h, '.render', 'cli.yaml')], name: 'Render CLI', key: /(key|token):\s*\S{8,}/, rotate: 'render logout; revoke API keys in Account Settings' },
    { p: [join(h, '.config', 'netlify', 'config.json'), join(h, 'Library', 'Preferences', 'netlify', 'config.json')], name: 'Netlify CLI', key: /"token"\s*:\s*"[^"]{8,}"/, rotate: 'netlify logout; revoke at app.netlify.com/user/applications' },
  ];
  for (const c of cli) for (const p of c.p) {
    const t = readText(p);
    if (t && c.key.test(t)) out.push({ id: 'paas.cli-token', category: 'paas', severity: 'high', title: `${c.name} token stored in plaintext`, location: tilde(ctx, p), detail: `Gives full control of your projects and their env vars. Rotate: ${c.rotate}.` });
  }
  const netrc = readText(join(h, '.netrc')) || readText(join(h, '_netrc'));
  if (netrc) {
    for (const m of netrc.matchAll(/machine\s+(\S+)[\s\S]*?password\s+(\S+)/g)) {
      if (isReference(m[2])) continue;
      const heroku = /heroku\.com$/.test(m[1]);
      out.push({ id: 'netrc.password', category: heroku ? 'paas' : 'github', severity: 'high', title: `${heroku ? 'Heroku API key' : `Plaintext login for ${m[1]}`} in ~/.netrc`, location: '~/.netrc', detail: `${heroku ? 'Rotate with `heroku authorizations:rotate` / `heroku logout`. ' : ''}~/.netrc is read verbatim by the GhostAction stealer and Shai-Hulud.` });
    }
  }
  // Project links: which deploy target holds this project's env vars?
  const links = [
    ['Railway', ['railway.json', 'railway.toml'], 'railway'],
    ['Vercel', ['.vercel/project.json', 'vercel.json'], null],
    ['Fly.io', ['fly.toml'], null],
    ['Render', ['render.yaml'], null],
    ['Heroku', ['Procfile', 'app.json'], null],
    ['Netlify', ['netlify.toml', '.netlify/state.json'], null],
  ];
  const railwayLinked = new Set();
  const rcfg = readText(join(h, '.railway', 'config.json'));
  if (rcfg) { try { for (const k of Object.keys(JSON.parse(rcfg).projects || {})) railwayLinked.add(k.replace(/\\/g, '/').replace(/\/$/, '')); } catch {} }
  for (const root of ctx.projects) {
    for (const [name, files, incident] of links) {
      let found = files.find((f) => exists(join(root, ...f.split('/'))));
      if (name === 'Heroku' && found === 'Procfile' && !exists(join(root, 'app.json')) && !/heroku/i.test(readText(join(root, 'package.json')) || '')) found = undefined; // Procfile alone is too generic
      const viaCli = name === 'Railway' && railwayLinked.has(root.replace(/\\/g, '/').replace(/\/$/, ''));
      if (!found && !viaCli) continue;
      out.push({
        id: 'paas.project-link', category: 'paas', severity: incident ? 'medium' : 'low', incident: incident || undefined,
        title: `${basename(root)} deploys to ${name} (${found || 'linked via railway CLI'})`,
        location: tilde(ctx, found ? join(root, found) : root),
        detail: incident
          ? 'Railway disclosed on Oct 21, 2026 that env vars may have been read and decrypted; it asks every user to roll all variables and private registry credentials, then review logs. Rotate at each provider, update the variables, then redeploy (env is read at start).'
          : `Secrets for this project live in ${name}'s env store. If the platform discloses an incident, rotate at the provider, update the variable, then redeploy.`,
      });
    }
  }
  return out;
}

/* ---------- 7. eMudhra: certificates chaining to the distrusted emSign ECC Root CA - G3 ---------- */
const EMSIGN = /emSign ECC Root CA - G3/i;
const CERT_EXT = /\.(pem|crt|cer|ca-bundle)$/i;

export function certsIn(text) {
  return (text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((pem) => { try { return new X509Certificate(pem); } catch { return null; } }).filter(Boolean);
}

export function scanCerts(ctx) {
  const out = [];
  const files = new Set();
  for (const root of ctx.projects) for (const f of projectFiles(ctx, root)) if (CERT_EXT.test(f)) files.add(f);
  for (const v of ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE']) if (ctx.env[v]) files.add(ctx.env[v]);
  for (const f of files) {
    const text = readText(f);
    if (!text || !text.includes('BEGIN CERTIFICATE')) continue;
    for (const c of certsIn(text)) {
      const subj = c.subject.replace(/\n/g, ', ');
      const isRoot = EMSIGN.test(c.subject);
      if (!isRoot && !EMSIGN.test(c.issuer)) continue;
      out.push({
        id: 'certs.emsign-ecc-g3', category: 'certs', severity: 'high', incident: 'emudhra',
        title: isRoot ? 'Trusts/pins the distrusted root "emSign ECC Root CA - G3"' : `Certificate issued under "emSign ECC Root CA - G3": ${subj.slice(0, 80)}`,
        location: tilde(ctx, f), fingerprint: 'sha256:' + createHash('sha256').update(c.raw).digest('hex').slice(0, 8),
        detail: isRoot
          ? 'Eight intermediates under this root had weak keys (recoverable by anyone). Browsers distrust the root (Chrome from Oct 27, 2026). Remove it from custom trust bundles; clients that skip CT/revocation could be fooled by forged certs.'
          : 'Chrome removes this root on Oct 27, 2026 and other root programs distrust it. Replace the certificate from another CA now to avoid outages.',
      });
    }
  }
  return out;
}

export const SUPPLY_SCANNERS = {
  malicious: scanMalicious,
  repo: scanRepo,
  'host-persistence': scanHostPersistence,
  php: scanPhp,
  paas: scanPaas,
  certs: scanCerts,
  'install-scripts': scanInstallScripts,
};
