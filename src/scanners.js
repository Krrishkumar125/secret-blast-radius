import { join, relative } from 'node:path';
import {
  fingerprint, readText, readBytes, listDir, exists, mtime,
  isReference, isSecretPair, tokenKind, walk,
} from './util.js';

const days = (d) => (d ? Math.floor((Date.now() - d.getTime()) / 86400000) : null);
const tilde = (ctx, p) => (p.startsWith(ctx.home) ? '~' + p.slice(ctx.home.length).replace(/\\/g, '/') : p);

/* ---------------- 0. Active worm persistence (Shai-Hulud family) ---------------- */
export function scanPersistence(ctx) {
  const h = ctx.home;
  const iocs = [
    join(h, '.config', 'gh-token-monitor'),
    join(h, '.local', 'bin', 'gh-token-monitor.sh'),
    join(h, '.config', 'systemd', 'user', 'gh-token-monitor.service'),
    join(h, 'Library', 'LaunchAgents', 'com.user.gh-token-monitor.plist'),
    join(h, 'AppData', 'Local', 'gh-token-monitor'),
  ];
  return iocs.filter(exists).map((p) => ({
    id: 'persistence.gh-token-monitor',
    category: 'persistence',
    severity: 'critical',
    title: 'Worm persistence found: gh-token-monitor',
    location: tilde(ctx, p),
    detail:
      'This is the "hostage token" service planted by the Mini Shai-Hulud npm worm (e.g. tensorlake@0.5.144). ' +
      'It wipes your home directory if the stolen GitHub token is revoked. Remove it BEFORE revoking any GitHub token.',
  }));
}

/* ---------------- 1. npm ---------------- */
export function scanNpmrc(ctx) {
  const files = [join(ctx.home, '.npmrc'), ...ctx.projects.map((p) => join(p, '.npmrc'))];
  const out = [];
  for (const f of new Set(files)) {
    const text = readText(f);
    if (!text) continue;
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*([^#;=\s]*(?:_authToken|_auth|_password))\s*=\s*(.+?)\s*$/);
      if (!m) continue;
      const [, key, value] = m;
      if (isReference(value)) continue;
      const registry = key.replace(/:?_(authToken|auth|password)$/, '').replace(/^\/\//, '') || 'registry.npmjs.org (default)';
      const publishable = /registry\.npmjs\.org|^registry\.npmjs\.org \(default\)$/.test(registry);
      out.push({
        id: 'npm.plaintext-token',
        category: 'npm',
        severity: publishable ? 'critical' : 'high',
        title: `Plaintext npm credential for ${registry}`,
        location: tilde(ctx, f),
        fingerprint: fingerprint(value),
        detail:
          (publishable
            ? 'Any install script can read this and republish every package you maintain (this is how Shai-Hulud spreads). '
            : 'Any install script can read this registry credential. ') +
          'Prefer short-lived tokens or npm trusted publishing (OIDC) from CI.' + tokenHint(value),
      });
    }
  }
  return out;
}

export function scanPypirc(ctx) {
  const f = join(ctx.home, '.pypirc');
  const t = readText(f);
  if (!t) return [];
  return [...t.matchAll(/^\s*password\s*[=:]\s*(\S+)/gm)].filter((m) => !isReference(m[1])).map((m) => ({
    id: 'pypi.plaintext-token', category: 'npm', severity: m[1].startsWith('pypi-') ? 'critical' : 'high',
    title: 'Plaintext PyPI credential in ~/.pypirc', location: tilde(ctx, f), fingerprint: fingerprint(m[1]),
    detail: 'Lets a stealer publish to your PyPI projects. Revoke at pypi.org/manage/account/token and use trusted publishing.',
  }));
}

/* ---------------- 2. GitHub ---------------- */
/** Least-privilege hint from the token's public prefix only (never the value). */
export function tokenHint(v) {
  if (/^ghp_/.test(v)) return ' This is a classic PAT (ghp_): classic tokens can reach every repo you can; prefer a fine-grained token with an expiry.';
  if (/^gho_/.test(v)) return ' OAuth token (gho_): it stays valid until revoked or unused for a year.';
  if (/^npm_/.test(v)) return ' Check at npmjs.com → Access Tokens whether it is a granular token with an expiry and 2FA bypass off.';
  if (/^(AKIA)/.test(v)) return ' Long-lived IAM user key (AKIA); temporary credentials (ASIA, via SSO/STS) expire on their own.';
  return '';
}

export function scanGitHub(ctx) {
  const out = [];
  const hosts = [join(ctx.home, '.config', 'gh', 'hosts.yml'), join(ctx.home, 'AppData', 'Roaming', 'GitHub CLI', 'hosts.yml')];
  for (const f of hosts) {
    const text = readText(f);
    if (!text) continue;
    const seen = new Set();
    for (const m of text.matchAll(/oauth_token:\s*(\S+)/g)) {
      if (isReference(m[1]) || seen.has(m[1])) continue;
      seen.add(m[1]);
      out.push({
        id: 'github.gh-cli-plaintext',
        category: 'github',
        severity: 'critical',
        title: 'GitHub CLI token stored in plaintext',
        location: tilde(ctx, f),
        fingerprint: fingerprint(m[1]),
        detail: 'gh fell back to a plaintext file (no OS keyring). Install scripts can read it and push to every repo you can write to.' + tokenHint(m[1]),
      });
    }
  }
  const gitCreds = join(ctx.home, '.git-credentials');
  const gc = readText(gitCreds);
  if (gc) {
    for (const line of gc.split(/\r?\n/)) {
      const m = line.match(/^https?:\/\/([^:]+):([^@]+)@([^/\s]+)/);
      if (!m) continue;
      out.push({
        id: 'github.git-credentials',
        category: 'github',
        severity: 'high',
        title: `Plaintext git credential for ${m[3]}`,
        location: tilde(ctx, gitCreds),
        fingerprint: fingerprint(m[2]),
        detail: 'git credential.helper=store keeps passwords/tokens unencrypted. Switch to the OS credential manager.' + tokenHint(decodeURIComponent(m[2])),
      });
    }
  }
  return out;
}

/* ---------------- 3. Cloud ---------------- */
export function scanCloud(ctx) {
  const out = [];
  const awsF = join(ctx.home, '.aws', 'credentials');
  const aws = readText(awsF);
  if (aws) {
    let profile = 'default';
    for (const line of aws.split(/\r?\n/)) {
      const p = line.match(/^\s*\[([^\]]+)\]/);
      if (p) profile = p[1];
      const k = line.match(/^\s*aws_access_key_id\s*=\s*(\S+)/);
      if (k && !isReference(k[1])) {
        const permanent = k[1].startsWith('AKIA');
        out.push({
          id: 'cloud.aws-static-key',
          category: 'cloud',
          severity: permanent ? 'critical' : 'medium',
          title: `AWS ${permanent ? 'long-lived' : 'session'} access key (profile "${profile}")`,
          location: tilde(ctx, awsF),
          fingerprint: fingerprint(k[1]),
          ageDays: days(mtime(awsF)),
          detail: permanent
            ? 'Long-lived IAM user keys never expire. Prefer `aws sso login` / IAM Identity Center so a stolen file is useless within hours.'
            : 'Temporary credentials: lower risk, but still usable until they expire.',
        });
      }
    }
  }
  const gcpF = join(ctx.home, '.config', 'gcloud', 'application_default_credentials.json');
  const gcp = readText(gcpF);
  if (gcp) {
    let type = 'unknown';
    try { type = JSON.parse(gcp).type || type; } catch {}
    out.push({
      id: 'cloud.gcp-adc',
      category: 'cloud',
      severity: type === 'service_account' ? 'critical' : 'high',
      title: `Google Cloud application default credentials (${type})`,
      location: tilde(ctx, gcpF),
      detail: type === 'service_account'
        ? 'A service-account key file never expires. Delete it and use workload identity or impersonation.'
        : 'A refresh token: valid until revoked with `gcloud auth application-default revoke`.',
    });
  }
  const azF = join(ctx.home, '.azure', 'msal_token_cache.json');
  if (exists(azF)) {
    out.push({
      id: 'cloud.azure-token-cache', category: 'cloud', severity: 'high',
      title: 'Azure CLI token cache', location: tilde(ctx, azF),
      detail: 'Refresh tokens for your Azure tenant(s). Revoke sessions with `az logout` and in Entra ID if exposed.',
    });
  }
  return out;
}

/* ---------------- 4. Kubernetes & container registries ---------------- */
export function scanKubeDocker(ctx) {
  const out = [];
  const kubeF = join(ctx.home, '.kube', 'config');
  const kube = readText(kubeF);
  if (kube) {
    const embedded = (kube.match(/^\s*(token|client-key-data|password):\s*\S+/gm) || []).length;
    if (embedded) {
      out.push({
        id: 'k8s.embedded-credentials', category: 'kubernetes', severity: 'high',
        title: `kubeconfig with ${embedded} embedded credential(s)`, location: tilde(ctx, kubeF),
        detail: 'Static tokens or client keys give cluster access to anyone who copies this file. Prefer exec-based auth plugins (short-lived).',
      });
    }
  }
  const dockerF = join(ctx.home, '.docker', 'config.json');
  const docker = readText(dockerF);
  if (docker) {
    try {
      const cfg = JSON.parse(docker);
      for (const [registry, v] of Object.entries(cfg.auths || {})) {
        if (v && (v.auth || v.identitytoken)) {
          out.push({
            id: 'registry.docker-plaintext', category: 'kubernetes', severity: 'high',
            title: `Container registry credential for ${registry} (base64, not encrypted)`,
            location: tilde(ctx, dockerF), fingerprint: fingerprint(v.auth || v.identitytoken),
            detail: 'Set "credsStore" (osxkeychain / wincred / pass / secretservice) so docker keeps this out of the file.',
          });
        }
      }
    } catch {}
  }
  return out;
}

/* ---------------- 5. Environment variables (what a CI install step sees) ---------------- */
export function scanEnv(ctx) {
  const out = [];
  for (const [name, value] of Object.entries(ctx.env)) {
    if (!value || isReference(value)) continue;
    const kind = tokenKind(value);
    if (!isSecretPair(name, value)) continue;
    out.push({
      id: 'env.secret', category: 'env', severity: kind && /npm|GitHub|AWS/.test(kind) ? 'critical' : 'high',
      title: `Secret in environment: ${name}${kind ? ` (${kind})` : ''}`,
      location: 'process environment', fingerprint: fingerprint(value),
      detail: 'Every install script and child process inherits this. In CI, scope secrets to the steps that need them, not the install step.',
    });
  }
  return out;
}

/* ---------------- 6. AI tools & MCP configs ---------------- */
function mcpServersFrom(obj, path = []) {
  // Collect {name, env, headers, args} objects found under any "mcpServers" / "servers" / "mcp_servers" key.
  const found = [];
  if (!obj || typeof obj !== 'object') return found;
  for (const [k, v] of Object.entries(obj)) {
    if (/^(mcpServers|mcp_servers|servers)$/.test(k) && v && typeof v === 'object' && !Array.isArray(v)) {
      for (const [name, s] of Object.entries(v)) if (s && typeof s === 'object') found.push({ name, server: s, path: [...path, k, name] });
    } else if (v && typeof v === 'object') {
      found.push(...mcpServersFrom(v, [...path, k]));
    }
  }
  return found;
}

export function unpinnedNpx(server) {
  if (typeof server?.command !== 'string' || !/(^|[\\/])(npx|bunx|pnpx)(\.cmd|\.exe)?$/i.test(server.command)) return null;
  const args = (server.args || []).filter((a) => typeof a === 'string');
  const pkg = args.find((a) => !a.startsWith('-'));
  if (!pkg || /^[./]/.test(pkg)) return null;
  const at = pkg.lastIndexOf('@');
  const hasVersion = at > 0 && /^\d/.test(pkg.slice(at + 1));
  return hasVersion ? null : pkg;
}

function literalSecretsInServer(server) {
  const hits = [];
  for (const bag of ['env', 'headers', 'http_headers']) {
    for (const [k, v] of Object.entries(server[bag] || {})) {
      if (typeof v !== 'string' || isReference(v)) continue;
      const val = v.replace(/^Bearer\s+/i, '');
      if (isReference(val)) continue;
      if (isSecretPair(k, val) || /^authorization$/i.test(k)) hits.push({ key: `${bag}.${k}`, value: val });
    }
  }
  for (const a of server.args || []) {
    if (typeof a !== 'string') continue;
    const m = a.match(/^--?[\w-]*(key|token|secret)[\w-]*=(.+)$/i);
    const val = m ? m[2] : a;
    if ((m && !isReference(val)) || tokenKind(a)) hits.push({ key: 'args', value: val });
  }
  if (typeof server.url === 'string') {
    const m = server.url.match(/[?&](api[_-]?key|token|key)=([^&]+)/i);
    if (m && !isReference(m[2])) hits.push({ key: 'url query', value: m[2] });
  }
  return hits;
}

export function aiConfigPaths(ctx) {
  const h = ctx.home;
  const appData = join(h, 'AppData', 'Roaming');
  return [
    join(h, '.claude.json'),
    join(h, '.claude', 'settings.json'),
    join(h, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    join(appData, 'Claude', 'claude_desktop_config.json'),
    join(h, '.config', 'Claude', 'claude_desktop_config.json'),
    join(h, '.cursor', 'mcp.json'),
    join(h, '.codeium', 'windsurf', 'mcp_config.json'),
    join(h, '.config', 'zed', 'settings.json'),
    join(h, '.kiro', 'settings', 'mcp.json'),
    join(h, '.gemini', 'settings.json'),
    join(h, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'),
    join(appData, 'Code', 'User', 'mcp.json'),
    join(h, '.config', 'Code', 'User', 'mcp.json'),
    ...ctx.projects.flatMap((p) => [join(p, '.mcp.json'), join(p, '.cursor', 'mcp.json'), join(p, '.vscode', 'mcp.json')]),
  ];
}

export function scanAiConfigs(ctx) {
  const out = [];
  for (const f of new Set(aiConfigPaths(ctx))) {
    const text = readText(f);
    if (!text) continue;
    let json;
    try { json = JSON.parse(text); } catch { continue; }
    for (const { name, server } of mcpServersFrom(json)) {
      const pkg = unpinnedNpx(server);
      if (pkg) out.push({ id: 'ai.mcp-unpinned', category: 'ai', severity: 'low', title: `MCP server "${name}" runs an unpinned package (${pkg})`, location: tilde(ctx, f), fix: `Change the arg to "${pkg}@<exact version>" (find it with \`npm view ${pkg} version\`).`,
        detail: '`npx -y <pkg>` fetches whatever version is latest every time the agent starts, with your agent\'s environment. Pin an exact version (pkg@1.2.3) so a hijacked release is not pulled in automatically.' });
      for (const hit of literalSecretsInServer(server)) {
        out.push({
          id: 'ai.mcp-literal-secret', category: 'ai', severity: 'high',
          title: `MCP server "${name}" has a literal secret in ${hit.key}`,
          location: tilde(ctx, f), fingerprint: fingerprint(hit.value),
          detail: 'Coding-agent and MCP configs are now an explicit target of npm worms. Reference an env var (e.g. "${VAR}") or your OS keychain instead.',
        });
      }
    }
  }
  for (const [rel, label] of [['.claude/.credentials.json', 'Claude Code login'], ['.gemini/oauth_creds.json', 'Gemini CLI OAuth tokens']]) {
    const f = join(ctx.home, ...rel.split('/'));
    if (readText(f)) out.push({ id: 'ai.cli-login', category: 'ai', severity: 'medium', title: `${label} stored in a file`, location: tilde(ctx, f), detail: 'Read verbatim by the GhostAction fake-font stealer. Sign out and back in to rotate if this machine is exposed.' });
  }
  // Codex CLI auth file stores an API key / refresh token.
  for (const f of [join(ctx.home, '.codex', 'auth.json')]) {
    const t = readText(f);
    if (!t) continue;
    try {
      const j = JSON.parse(t);
      if (j.OPENAI_API_KEY || j.tokens) {
        out.push({
          id: 'ai.codex-auth', category: 'ai', severity: 'medium',
          title: 'Codex CLI credentials file', location: tilde(ctx, f),
          detail: 'Contains an API key or refresh token. Sign out (`codex logout`) and back in to rotate if exposed.',
        });
      }
    } catch {}
  }
  return out;
}

/* ---------------- 7. SSH keys ---------------- */
export function sshKeyEncrypted(buf) {
  const text = buf.toString('latin1');
  if (/-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----/.test(text)) return /Proc-Type:\s*4,ENCRYPTED/.test(text);
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text)) return true;
  if (/-----BEGIN PRIVATE KEY-----/.test(text)) return false;
  const m = text.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/);
  if (!m) return null;
  const raw = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
  const magic = 'openssh-key-v1\0';
  if (raw.subarray(0, magic.length).toString('latin1') !== magic) return null;
  const len = raw.readUInt32BE(magic.length);
  const cipher = raw.subarray(magic.length + 4, magic.length + 4 + len).toString('latin1');
  return cipher !== 'none';
}

export function scanSsh(ctx) {
  const out = [];
  const dir = join(ctx.home, '.ssh');
  for (const ent of listDir(dir)) {
    if (!ent.isFile() || ent.name.endsWith('.pub') || /^(known_hosts|config|authorized_keys)/.test(ent.name)) continue;
    const p = join(dir, ent.name);
    const buf = readBytes(p);
    if (!buf || !buf.includes('PRIVATE KEY-----')) continue;
    const enc = sshKeyEncrypted(buf);
    if (enc) continue;
    out.push({
      id: 'ssh.unencrypted-key', category: 'ssh', severity: 'high',
      title: `SSH private key without a passphrase: ${ent.name}`, location: tilde(ctx, p),
      ageDays: days(mtime(p)),
      detail: 'A copied file is a working key. Add a passphrase (`ssh-keygen -p -f <key>`) and use ssh-agent, or a hardware-backed key.',
    });
  }
  return out;
}

/* ---------------- 8. .env files in your projects ---------------- */
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.turbo', 'vendor', '.venv', 'venv', '__pycache__', 'coverage', '.cache']);

export function parseDotenv(text) {
  const pairs = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if (/^(['"]).*\1$/.test(v)) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, '');
    pairs.push([m[1], v]);
  }
  return pairs;
}

export function scanDotenv(ctx) {
  const out = [];
  for (const root of ctx.projects) {
    for (const f of walk(root, { maxDepth: ctx.depth, skip: SKIP_DIRS })) {
      const base = f.split(/[\\/]/).pop();
      if (!/^\.env(\..+)?$/.test(base) || /\.(example|sample|template|dist|defaults|demo|emulated|emulator|mock)$/i.test(base)) continue;
      const text = readText(f);
      if (!text) continue;
      const secrets = parseDotenv(text).filter(([k, v]) => isSecretPair(k, v));
      if (!secrets.length) continue;
      const kinds = [...new Set(secrets.map(([, v]) => tokenKind(v)).filter(Boolean))];
      const live = kinds.some((k) => /live|AWS|npm|GitHub|connection string/.test(k));
      out.push({
        id: 'dotenv.secrets', category: 'dotenv', severity: live ? 'high' : 'medium',
        title: `${secrets.length} secret(s) in ${relative(root, f).replace(/\\/g, '/') || base}`,
        location: tilde(ctx, f),
        names: secrets.map(([k]) => k),
        detail: `Keys: ${secrets.map(([k]) => k).join(', ')}${kinds.length ? ` — recognised: ${kinds.join(', ')}` : ''}. ` +
          'Install scripts run with your project as cwd, so .env files are the first thing they read.',
      });
    }
  }
  return out;
}

/* ---------------- Hardening checks (not secrets, but they shrink the blast radius) ---------------- */
export function scanHardening(ctx) {
  const out = [];
  const npmrcs = [join(ctx.home, '.npmrc'), ...ctx.projects.map((p) => join(p, '.npmrc'))].map(readText).filter(Boolean).join('\n');
  if (!/^\s*ignore-scripts\s*=\s*true/m.test(npmrcs)) {
    out.push({
      id: 'hardening.ignore-scripts', category: 'hardening', severity: 'low',
      title: 'npm runs dependency install scripts', location: '~/.npmrc',
      detail: 'Every malicious package this year ran from preinstall/postinstall. Consider `ignore-scripts=true` (or pnpm, which blocks dependency builds by default) and allow-list the few that need it.',
      fix: '`npm config set ignore-scripts true` (user-wide) or add `ignore-scripts=true` to the project .npmrc; run needed builds explicitly (`npm rebuild <pkg>`).',
    });
  }
  const pnpmWs = ctx.projects.map((p) => readText(join(p, 'pnpm-workspace.yaml'))).filter(Boolean).join('\n');
  const yarnrc = [join(ctx.home, '.yarnrc.yml'), ...ctx.projects.map((p) => join(p, '.yarnrc.yml'))].map(readText).filter(Boolean).join('\n');
  const bunfig = [join(ctx.home, '.bunfig.toml'), ...ctx.projects.map((p) => join(p, 'bunfig.toml'))].map(readText).filter(Boolean).join('\n');
  const configured = /^\s*min-release-age\s*=/m.test(npmrcs) || /minimumReleaseAge\s*:/.test(pnpmWs) || /npmMinimalAgeGate\s*:/.test(yarnrc) || /^\s*minimumReleaseAge\s*=/m.test(bunfig);
  if (!configured) {
    const has = (f) => ctx.projects.some((p) => exists(join(p, f)));
    const tips = [];
    if (has('package-lock.json') || !(has('pnpm-lock.yaml') || has('yarn.lock') || has('bun.lock'))) tips.push('npm ≥ 11.10: `min-release-age=3` in .npmrc (days)');
    if (has('pnpm-lock.yaml')) tips.push('pnpm ≥ 10.16: `minimumReleaseAge: 4320` in pnpm-workspace.yaml (minutes; pnpm 11 defaults to 1440)');
    if (has('yarn.lock')) tips.push('Yarn Berry: `npmMinimalAgeGate: 4320` in .yarnrc.yml (minutes)');
    if (has('bun.lock')) tips.push('Bun ≥ 1.3: `[install] minimumReleaseAge = 259200` in bunfig.toml (seconds)');
    out.push({
      id: 'hardening.release-age', category: 'hardening', severity: 'low',
      title: 'No dependency cooldown configured', location: 'package manager config',
      detail: 'Malicious versions are usually pulled within hours (litellm 1.107.0: under 2h; tensorlake 0.5.144: under 2h). A cooldown would not catch a compromise that goes unnoticed for longer.',
      fix: tips.join('; ') + '.',
    });
  }
  return out;
}

export const SCANNERS = {
  persistence: scanPersistence,
  npm: (ctx) => [...scanNpmrc(ctx), ...scanPypirc(ctx)],
  github: scanGitHub,
  cloud: scanCloud,
  kubernetes: scanKubeDocker,
  env: scanEnv,
  ai: scanAiConfigs,
  ssh: scanSsh,
  dotenv: scanDotenv,
  hardening: scanHardening,
};
