import { createHash } from 'node:crypto';
import { readFileSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/** Short, non-reversible fingerprint so users can tell secrets apart without seeing them. */
export function fingerprint(value) {
  return 'sha256:' + createHash('sha256').update(String(value)).digest('hex').slice(0, 8);
}

export function readText(path) {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > 5 * 1024 * 1024) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

export function readBytes(path) {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > 1024 * 1024) return null;
    return readFileSync(path);
  } catch {
    return null;
  }
}

export function listDir(path) {
  try {
    return readdirSync(path, { withFileTypes: true });
  } catch {
    return [];
  }
}

export function exists(path) {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

export function mtime(path) {
  try {
    return statSync(path).mtime;
  } catch {
    return null;
  }
}

/** True when a value is an indirection (env reference, keychain helper, empty) rather than a literal secret. */
export function isReference(value) {
  if (value == null) return true;
  const v = String(value).trim();
  if (v === '') return true;
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v)) return true; // $VAR or ${VAR}
  if (/^\$\{(env|input):[^}]+\}$/.test(v)) return true; // ${env:VAR} / ${input:id} (VS Code)
  if (/^(op|vault|keychain|secret|1password):\/\//i.test(v)) return true;
  if (/^<[^>]+>$/.test(v) || /^\[[^\]]+\]$/.test(v)) return true; // <placeholder> / [YOUR_KEY]
  if (/^(your|enter|insert|replace|add)[-_ ]?(your[-_ ]?)?[a-z_ -]*(here)?$/i.test(v) || /_here$/i.test(v)) return true;
  if (/^\$\{\{.*\}\}$/.test(v)) return true; // ${{ secrets.X }} (GitHub Actions)
  if (/^(x{4,}|\*{4,}|your[-_ ].*|changeme|placeholder|todo|redacted)$/i.test(v)) return true;
  if (/^(fake|dummy|mock)[-_]/i.test(v) || /:\/\/[^:@\s]*:(fake|dummy|mock)[-_][^@]*@/i.test(v)) return true;
  if (/not[-_ ]?a[-_ ]?(real[-_ ]?)?secret|^change[-_ ]?me|^dummy|^placeholder|^replace[-_ ]?(me|this)|^example|^sample/i.test(v)) return true;
  return false;
}

const SECRET_NAME = /(^|_|-)(api[-_]?key|apikey|token|secret|password|passwd|pwd|private[-_]?key|access[-_]?key|auth|credentials?|dsn|webhook[-_]?secret|client[-_]?secret|session[-_]?key)($|_|-)|^(database_url|db_url|redis_url|mongodb_uri|mongo_url|postgres_url|pg_url|amqp_url|supabase_service_role_key|stripe_.*|openai_.*key|anthropic_.*key)$/i;
const NOT_SECRET_NAME = /(^|_)(public|publishable|anon|pk|next_public|vite|expo_public|token_url|auth_url|auth_domain|endpoint|region|ttl|expir[a-z]*|length|limit|max|timeout|path|file|enabled|disable|issuer|audience)(_|$)/i;

export function looksLikeSecretName(name) {
  if (/^(OLD)?PWD$/i.test(name)) return false; // shell's working directory, not a password
  return SECRET_NAME.test(name) && !NOT_SECRET_NAME.test(name);
}

const EXAMPLE_WORD = /^(secret|secrets|password|passwd|pass|token|key|apikey|api|jwt|session|cookie|signing|local|localhost|dev|development|test|testing|tests|example|examples|sample|demo|dummy|fake|mock|placeholder|change|changeme|replace|me|xxx|todo|redacted|default|insecure|value|your|here|this|not|real|keyboard|cat|foo|bar|baz|my|super|unsafe|temp|tmp|ci)$/i;
const URL_NAME = /(_url|_uri|_dsn)$|^(dsn)$/i;

/** Does this name/value pair hold a literal secret? URL-style names only count when they embed credentials. */
export function isSecretPair(name, value) {
  if (value == null || isReference(value)) return false;
  const v = String(value);
  // Credentials for a database on this machine (docker-compose dev defaults) are not reachable secrets.
  if (/^[a-z][a-z0-9+.-]*:\/\/[^/\s@]+@(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)([:/?]|$)/i.test(v)) return false;
  if (tokenKind(v)) return true;
  // Prose like "local-secret" or "this-is-a-secret-value-..." is a committed example, not a credential.
  // Word shape alone is not enough: "correct-horse-battery-staple" is a real passphrase. Only discard
  // all-word values that also contain a placeholder/example word.
  const words = v.replace(/[!.]+$/, '').split(/[-_ .]+/);
  if (words.length >= 2 && words.every((w) => /^[a-z]+$|^[A-Z]+$|^\d+$/.test(w)) && words.some((w) => /^[a-z]{3,}$/i.test(w))
    && words.some((w) => EXAMPLE_WORD.test(w))) return false;
  if (URL_NAME.test(name)) return /^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^@\s]+@/i.test(v) || /[?&](password|token|key|secret)=[^&\s]+/i.test(v);
  return looksLikeSecretName(name) && v.length >= 8;
}

/** Recognise well-known token formats. Returns a provider label or null. */
export function tokenKind(value) {
  const v = String(value);
  const rules = [
    [/^npm_[A-Za-z0-9]{36}$/, 'npm token'],
    [/^gh[pousr]_[A-Za-z0-9]{36,}$/, 'GitHub token'],
    [/^github_pat_[A-Za-z0-9_]{60,}$/, 'GitHub fine-grained token'],
    [/^(AKIA|ASIA)[A-Z0-9]{16}$/, 'AWS access key'],
    [/^sk-ant-[A-Za-z0-9_-]{20,}$/, 'Anthropic key'],
    [/^sk-(proj-)?[A-Za-z0-9_-]{20,}$/, 'OpenAI-style key'],
    [/^sk_live_[A-Za-z0-9]{16,}$/, 'Stripe live secret key'],
    [/^rk_live_[A-Za-z0-9]{16,}$/, 'Stripe restricted key'],
    [/^whsec_[A-Za-z0-9]{16,}$/, 'Stripe webhook secret'],
    [/^xox[baprs]-[A-Za-z0-9-]{10,}$/, 'Slack token'],
    [/^AIza[0-9A-Za-z_-]{35}$/, 'Google API key'],
    [/^glpat-[A-Za-z0-9_-]{20,}$/, 'GitLab token'],
    [/^hf_[A-Za-z0-9]{30,}$/, 'Hugging Face token'],
    [/^(postgres(ql)?|mysql|mongodb(\+srv)?|redis|rediss|amqps?):\/\/[^:\s]+:[^@\s]+@/, 'connection string with password'],
  ];
  for (const [re, label] of rules) if (re.test(v)) return label;
  return null;
}

export function walk(root, { maxDepth = 4, skip = new Set() } = {}) {
  const out = [];
  const stack = [[root, 0]];
  while (stack.length) {
    const [dir, depth] = stack.pop();
    for (const ent of listDir(dir)) {
      const p = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (depth < maxDepth && !skip.has(ent.name)) stack.push([p, depth + 1]);
      } else if (ent.isFile()) {
        out.push(p);
      }
    }
  }
  return out;
}
