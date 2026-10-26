import { join, relative } from 'node:path';
import { fingerprint, readText, listDir, isReference, isSecretPair, tokenKind, walk } from './util.js';

/* ---------------- Secrets shipped to the browser ----------------
 * 1. Public-prefixed env vars (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, ...) in .env files.
 *    Frameworks inline these into the client bundle at build time, so every visitor can read them.
 * 2. Token-shaped secrets inside built/static frontend files (dist, build, out, .next/static, public, ...).
 */

export const PUBLIC_PREFIXES = [
  ['NEXT_PUBLIC_', 'Next.js'], ['VITE_', 'Vite'], ['REACT_APP_', 'Create React App'], ['EXPO_PUBLIC_', 'Expo'],
  ['NUXT_PUBLIC_', 'Nuxt'], ['GATSBY_', 'Gatsby'], ['VUE_APP_', 'Vue CLI'], ['PUBLIC_', 'SvelteKit/Astro'],
];

// Keys that are designed to be public. Flagging them would be noise.
const PUBLIC_BY_DESIGN = [
  /^AIza[0-9A-Za-z_-]{35}$/, // Google/Firebase browser keys: restrict by referrer instead
  /^pk_(live|test)_/, // Stripe publishable
  /^phc_/, // PostHog project key
  /^pk\.[A-Za-z0-9]/, // Mapbox public token
  /^https:\/\/[0-9a-f]+@[a-z0-9.-]*ingest(\.[a-z]+)?\.sentry\.io\//i, // Sentry DSN (public)
];

const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', '.venv', 'venv', '__pycache__', 'coverage', '.cache', '.turbo']);
// Directory name -> sub-path that ships to clients.
const BUILD_DIRS = { dist: '', build: '', out: '', public: '', 'storybook-static': '', '.next': 'static', '.output': 'public', '.svelte-kit': 'output/client' };
const BUILT_EXT = /\.(m?js|cjs|html?|map)$/i;
const MAX_FILES = 5000;

// Unanchored versions of the token formats in util.tokenKind (Google keys left out: public by design).
const B = '(?<![A-Za-z0-9_])';
const E = '(?![A-Za-z0-9_])';
const IN_TEXT = [
  [new RegExp(`${B}npm_[A-Za-z0-9]{36}${E}`, 'g'), 'npm token'],
  [new RegExp(`${B}gh[pousr]_[A-Za-z0-9]{36,}${E}`, 'g'), 'GitHub token'],
  [new RegExp(`${B}github_pat_[A-Za-z0-9_]{60,}`, 'g'), 'GitHub fine-grained token'],
  [new RegExp(`${B}(?:AKIA|ASIA)[A-Z0-9]{16}${E}`, 'g'), 'AWS access key'],
  [new RegExp(`${B}sk-ant-[A-Za-z0-9_-]{20,}`, 'g'), 'Anthropic key'],
  [new RegExp(`${B}sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}`, 'g'), 'OpenAI-style key'],
  [new RegExp(`${B}sk_live_[A-Za-z0-9]{16,}${E}`, 'g'), 'Stripe live secret key'],
  [new RegExp(`${B}rk_live_[A-Za-z0-9]{16,}${E}`, 'g'), 'Stripe restricted key'],
  [new RegExp(`${B}whsec_[A-Za-z0-9]{16,}${E}`, 'g'), 'Stripe webhook secret'],
  [new RegExp(`${B}xox[baprs]-[A-Za-z0-9-]{10,}`, 'g'), 'Slack token'],
  [new RegExp(`${B}glpat-[A-Za-z0-9_-]{20,}`, 'g'), 'GitLab token'],
  [new RegExp(`${B}hf_[A-Za-z0-9]{30,}${E}`, 'g'), 'Hugging Face token'],
  [/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^:\s"'`/@]+:[^@\s"'`]+@(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)[^\s"'`/:]+/g, 'connection string with password'],
];

/** Every token-shaped secret in a blob of text: [{ value, kind }]. */
export function findTokensInText(text) {
  const out = [];
  for (const [re, kind] of IN_TEXT) for (const m of String(text).matchAll(re)) out.push({ value: m[0], kind, index: m.index });
  return out;
}

const tilde = (ctx, p) => (p.startsWith(ctx.home) ? '~' + p.slice(ctx.home.length).replace(/\\/g, '/') : p);
const rel = (root, p) => relative(root, p).replace(/\\/g, '/');

export function publicPrefix(name) {
  return PUBLIC_PREFIXES.find(([p]) => name.startsWith(p) && name.length > p.length) ?? null;
}

/** Is this public-prefixed variable holding something that should not be public? Returns { kind } or null. */
export function exposedSecret(name, value) {
  const pre = publicPrefix(name);
  if (!pre || value == null || isReference(value)) return null;
  const v = String(value).trim();
  if (PUBLIC_BY_DESIGN.some((re) => re.test(v))) return null;
  const kind = tokenKind(v);
  if (kind) return { kind, strong: true };
  // Name-based: strip the prefix so NEXT_PUBLIC_STRIPE_SECRET_KEY is judged as STRIPE_SECRET_KEY.
  // Names that say public/publishable/anon stay excluded by looksLikeSecretName.
  if (isSecretPair(name.slice(pre[0].length), v)) return { kind: null, strong: false };
  return null;
}

function envFindings(ctx, root) {
  const out = [];
  for (const f of walk(root, { maxDepth: ctx.depth, skip: new Set([...SKIP_DIRS, ...Object.keys(BUILD_DIRS)]) })) {
    const base = f.split(/[\\/]/).pop();
    if (!/^\.env(\..+)?$/.test(base) || /\.(example|sample|template|dist|defaults|demo|emulated|emulator|mock)$/i.test(base)) continue;
    const text = readText(f);
    if (!text) continue;
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/);
      if (!m) continue;
      let v = m[2].trim();
      if (/^(['"]).*\1$/.test(v)) v = v.slice(1, -1); else v = v.replace(/\s+#.*$/, '');
      const hit = exposedSecret(m[1], v);
      if (!hit) continue;
      const [prefix, fw] = publicPrefix(m[1]);
      out.push({
        id: 'frontend.public-env', category: 'frontend', severity: hit.strong ? 'critical' : 'medium',
        title: `Secret exposed to the browser: ${m[1]}${hit.kind ? ` (${hit.kind})` : ''}`,
        location: tilde(ctx, f), fingerprint: fingerprint(v), names: [m[1]],
        detail: `${fw} inlines ${prefix}* variables into the client bundle at build time, so anyone who loads the site can read this value` +
          (hit.strong ? '.' : '. The name looks like a secret; if it is really a public/publishable key, rename it to say so.') +
          ` Found in ${rel(root, f) || base}.`,
        fix: `Drop the ${prefix} prefix and read it only in server code (API route, server action, edge function). Rotate the key: every build already deployed contains it.`,
      });
    }
  }
  return out;
}

function buildRoots(root, depth) {
  const roots = [];
  const stack = [[root, 0]];
  while (stack.length) {
    const [dir, d] = stack.pop();
    for (const ent of listDir(dir)) {
      if (!ent.isDirectory() || SKIP_DIRS.has(ent.name)) continue;
      const p = join(dir, ent.name);
      if (Object.hasOwn(BUILD_DIRS, ent.name)) roots.push(BUILD_DIRS[ent.name] ? join(p, BUILD_DIRS[ent.name]) : p);
      else if (d < depth) stack.push([p, d + 1]);
    }
  }
  return roots;
}

function builtFindings(ctx, root) {
  const out = [];
  let budget = MAX_FILES;
  for (const dir of buildRoots(root, ctx.depth)) {
    for (const f of walk(dir, { maxDepth: 8, skip: SKIP_DIRS })) {
      if (!BUILT_EXT.test(f) || budget-- <= 0) continue;
      const text = readText(f);
      if (!text) continue;
      const hits = findTokensInText(text);
      if (!hits.length) continue;
      const uniq = [...new Map(hits.map((h) => [h.value, h])).values()];
      const kinds = [...new Set(uniq.map((h) => h.kind))];
      out.push({
        id: 'frontend.built-secret', category: 'frontend', severity: 'critical',
        title: `${uniq.length} secret(s) in built frontend file ${rel(root, f)}`,
        location: tilde(ctx, f), fingerprint: fingerprint(uniq[0].value),
        fingerprints: uniq.map((h) => fingerprint(h.value)),
        detail: `Recognised: ${kinds.join(', ')}. Files in build/static output are served to every visitor (and often published to npm or a CDN).`,
        fix: 'Move the call that needs this key to a server route, rebuild, redeploy, delete old deployments/previews and CDN copies, and rotate the key.',
      });
    }
  }
  return out;
}

export function scanFrontend(ctx) {
  return ctx.projects.flatMap((root) => [...envFindings(ctx, root), ...builtFindings(ctx, root)]);
}

export const FRONTEND_SCANNERS = { frontend: scanFrontend };
