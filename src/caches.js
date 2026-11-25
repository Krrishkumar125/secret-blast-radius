// v0.6: places that keep packages and credentials alive after you rotate:
// private registries and mirrors, credentials baked into lockfile URLs,
// Docker builds that copy npm credentials into image layers, and CI dependency caches.
import { join, basename, relative } from 'node:path';
import { fingerprint, readText, listDir, walk } from './util.js';

const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.turbo', 'vendor', '.venv', 'venv', '__pycache__', 'coverage', '.cache', '.yarn']);
const PUBLIC_REGISTRIES = new Set(['registry.npmjs.org', 'registry.yarnpkg.com', 'registry.npmjs.com']);
const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock']);
const tilde = (ctx, p) => (p.startsWith(ctx.home) ? '~' + p.slice(ctx.home.length).replace(/\\/g, '/') : p);
const rel = (root, p) => relative(root, p).replace(/\\/g, '/');

/** Which product a registry URL most likely belongs to, for a more specific fix. */
export function registryProduct(url) {
  const u = String(url).toLowerCase();
  if (u.includes('npm.pkg.github.com')) return 'GitHub Packages';
  if (/jfrog\.io|\/artifactory\//.test(u)) return 'Artifactory';
  if (/\/repository\/[^/]+/.test(u) || u.includes('nexus')) return 'Nexus';
  if (u.includes('verdaccio') || /:4873\b/.test(u)) return 'Verdaccio';
  if (u.includes('.codeartifact.')) return 'AWS CodeArtifact';
  if (u.includes('pkgs.dev.azure.com') || u.includes('pkgs.visualstudio.com')) return 'Azure Artifacts';
  if (/\/api\/v4\/(projects|groups)\/[^/]+\/packages\/npm/.test(u)) return 'GitLab package registry';
  return null;
}

export function registryHost(url) {
  try { return new URL(String(url).trim().replace(/^["']|["']$/g, '')).host.toLowerCase(); } catch { return null; }
}

/** Registry URLs configured in .npmrc / .yarnrc.yml / bunfig.toml text: [{ url, scope, line }]. */
export function parseRegistries(file, text) {
  const base = basename(file);
  const out = [];
  for (const [i, raw] of String(text).split(/\r?\n/).entries()) {
    const line = raw.replace(/^\s*[#;].*$/, '');
    let m;
    if (base === '.npmrc') m = line.match(/^\s*(?:(@[^:\s]+):)?registry\s*=\s*(\S+)/);
    else if (base === '.yarnrc.yml') m = line.match(/^\s*()npmRegistryServer\s*:\s*["']?([^"'\s#]+)/);
    else if (base === 'bunfig.toml') m = line.match(/^\s*()registry\s*=\s*["']([^"']+)["']/);
    if (m) out.push({ scope: m[1] || null, url: m[2], line: i + 1 });
  }
  return out;
}

/** Credentials embedded in URLs inside a lockfile: [{ host, value, line }]. Values are only fingerprinted by callers. */
export function lockfileCredentials(text) {
  const out = [];
  const re = /\bhttps?:\/\/([^\s"'\/@:]+):([^\s"'@\/]+)@([^\s"'\/:]+)|\bhttps?:\/\/([^\s"'\/]+)\/[^\s"']*[?&](?:_authToken|token|access_token)=([^\s"'&#]+)/gi;
  const lines = String(text).split(/\r?\n/);
  for (const [i, l] of lines.entries()) {
    for (const m of l.matchAll(re)) out.push({ host: (m[3] || m[4]).toLowerCase(), value: m[2] || m[5], line: i + 1 });
  }
  return out;
}

const TOKEN_ARG = /^\s*(ARG|ENV)\s+((?:NPM|NODE_AUTH|NPM_AUTH|YARN_NPM_AUTH|GITHUB|GH|ARTIFACTORY|NEXUS|JFROG)_?[A-Z_]*TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN)\b/i;
const COPY_RC = /^\s*(COPY|ADD)\b[^\n]*?(?:^|\s|\/)(\.npmrc|\.yarnrc\.yml|\.yarnrc)(?:\s|$)/i;

/** Dockerfile lines that put a registry credential into an image layer or its history. */
export function dockerCredentialLeaks(text) {
  const out = [];
  const usesSecretMount = /--mount=type=secret/i.test(text);
  for (const [i, line] of String(text).split(/\r?\n/).entries()) {
    const a = line.match(TOKEN_ARG);
    if (a) out.push({ kind: a[1].toUpperCase() === 'ENV' ? 'env' : 'arg', name: a[2], line: i + 1, usesSecretMount });
    const c = line.match(COPY_RC);
    if (c) out.push({ kind: 'copy', name: c[2], line: i + 1, usesSecretMount });
  }
  return out;
}

const CACHE_PATHS = [
  [/(^|[\s'"\/-])node_modules\b/, 'node_modules', 'medium'],
  [/~\/\.npm\b|\$\{\{\s*env\.HOME\s*\}\}\/\.npm\b/, '~/.npm', 'low'],
  [/\.pnpm-store\b|pnpm\/store/, 'pnpm store', 'low'],
  [/\.yarn\/cache\b|~\/\.cache\/yarn\b|yarn-cache/, 'yarn cache', 'low'],
  [/~\/\.bun\/install\/cache\b/, 'bun cache', 'low'],
];

/** Dependency caches a GitHub Actions workflow saves and restores: [{ what, severity, line }]. */
export function workflowCaches(text) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  let inCache = false;
  let inSetupNode = false;
  for (const [i, line] of lines.entries()) {
    const uses = line.match(/uses:\s*['"]?([^@\s'"]+)/);
    if (uses) { inCache = /^actions\/cache(\/restore)?$/.test(uses[1]); inSetupNode = uses[1] === 'actions/setup-node'; continue; }
    if (/^\s*-\s/.test(line)) { inCache = false; inSetupNode = false; }
    if (inSetupNode) {
      const m = line.match(/^\s*cache:\s*['"]?(npm|yarn|pnpm)\b/);
      if (m) out.push({ what: `${m[1]} cache via actions/setup-node`, severity: 'low', line: i + 1 });
    }
    if (inCache) for (const [re, what, severity] of CACHE_PATHS) if (re.test(line) && !/^\s*key:/.test(line)) out.push({ what: `${what} via actions/cache`, severity, line: i + 1 });
  }
  return [...new Map(out.map((x) => [x.what, x])).values()];
}

function projectFiles(ctx, root) {
  return walk(root, { maxDepth: ctx.depth, skip: SKIP });
}

function workflowFiles(root) {
  const dir = join(root, '.github', 'workflows');
  return listDir(dir).filter((e) => e.isFile() && /\.ya?ml$/i.test(e.name)).map((e) => join(dir, e.name));
}

export function scanCaches(ctx) {
  const out = [];
  const seenRegistry = new Set();
  const registryFinding = (file, where) => {
    for (const r of parseRegistries(file, readText(file) ?? '')) {
      const host = registryHost(r.url);
      if (!host || PUBLIC_REGISTRIES.has(host)) continue;
      const key = `${host}|${where}`;
      if (seenRegistry.has(key)) continue;
      seenRegistry.add(key);
      const product = registryProduct(r.url);
      out.push({
        id: 'caches.private-registry', category: 'caches', severity: 'medium',
        title: `Installs${r.scope ? ` for ${r.scope}` : ''} go through ${product ? `${product} at ` : ''}${host}`,
        location: `${where}:${r.line}`,
        detail: 'A registry mirror or proxy keeps its own copy of every version it has served and holds its own upstream credentials. Revoking your npm token does not touch either one.',
        fix: `Rotate the mirror's own access tokens and the upstream credentials it uses, then purge any known-bad versions from its proxy cache${product ? ` in ${product}` : ''}.`,
      });
    }
  };
  for (const name of ['.npmrc', '.yarnrc.yml', 'bunfig.toml']) {
    const f = join(ctx.home, name);
    if (readText(f) != null) registryFinding(f, tilde(ctx, f));
  }
  for (const root of ctx.projects) {
    for (const f of projectFiles(ctx, root)) {
      const base = basename(f);
      if (base === '.npmrc' || base === '.yarnrc.yml' || base === 'bunfig.toml') registryFinding(f, tilde(ctx, f));
      else if (LOCKFILES.has(base)) {
        const creds = lockfileCredentials(readText(f) ?? '');
        const uniq = [...new Map(creds.map((c) => [c.value, c])).values()];
        if (!uniq.length) continue;
        out.push({
          id: 'caches.lockfile-credential', category: 'caches', severity: 'high',
          title: `${uniq.length} credential(s) inside resolved URLs in ${rel(root, f)}`,
          location: `${tilde(ctx, f)}:${uniq[0].line}`, fingerprint: fingerprint(uniq[0].value), fingerprints: uniq.map((c) => fingerprint(c.value)),
          detail: `Hosts: ${[...new Set(uniq.map((c) => c.host))].join(', ')}. The lockfile is committed and copied into every clone, fork, CI cache and Docker build context.`,
          fix: 'Rotate the credential, keep auth in .npmrc as `${NPM_TOKEN}` (never in the URL), regenerate the lockfile, and remember the old value stays in git history.',
        });
      } else if (/^(Dockerfile|Containerfile)(\..+)?$|\.(dockerfile|containerfile)$/i.test(base)) {
        for (const leak of dockerCredentialLeaks(readText(f) ?? '')) {
          const copy = leak.kind === 'copy';
          out.push({
            id: copy ? 'caches.docker-copied-npmrc' : 'caches.docker-build-arg-token', category: 'caches', severity: 'high',
            title: copy ? `${rel(root, f)} copies ${leak.name} into an image layer` : `${rel(root, f)} passes ${leak.name} as a build ${leak.kind === 'env' ? 'ENV' : 'ARG'}`,
            location: `${tilde(ctx, f)}:${leak.line}`,
            detail: copy
              ? 'The file stays in that layer even if a later RUN deletes it, so every pushed image and build cache holds the token.'
              : 'Build args and ENV values are recorded in image metadata and `docker history`, so every pushed image and build cache holds the token.',
            fix: 'Use a BuildKit secret instead: `RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci`, built with `docker build --secret id=npmrc,src=$HOME/.npmrc`. Then rotate the token and rebuild with `--pull --no-cache`.',
          });
        }
      }
    }
    for (const f of workflowFiles(root)) {
      for (const c of workflowCaches(readText(f) ?? '')) {
        out.push({
          id: 'caches.ci-dependency-cache', category: 'caches', severity: c.severity,
          title: `Workflow ${basename(f)} restores the ${c.what}`,
          location: `${tilde(ctx, f)}:${c.line}`,
          detail: c.what.startsWith('node_modules')
            ? 'A cached node_modules holds whatever install scripts wrote during the exposure window and is restored into later runs without reinstalling.'
            : 'A cache saved during the exposure window can restore a known-bad tarball into later runs, even after the lockfile is fixed.',
          fix: 'After an incident, delete the caches (`gh cache delete --all`), change the cache key, and cache the package manager store rather than node_modules.',
        });
      }
    }
  }
  return out;
}

export const CACHE_SCANNERS = { caches: scanCaches };
