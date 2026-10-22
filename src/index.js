import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { SCANNERS } from './scanners.js';
import { SUPPLY_SCANNERS, loadIocs } from './supply.js';
import { INCIDENTS } from './incidents.js';

export const ALL_SCANNERS = { ...SCANNERS, ...SUPPLY_SCANNERS };

function defaultExec(cmd, args) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 4000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    return r.status === 0 ? r.stdout : null;
  } catch {
    return null;
  }
}

export const SEVERITY = ['critical', 'high', 'medium', 'low'];

/** Order in which to rotate after a suspected compromise. Lower = earlier. */
export const ROTATION = {
  persistence: {
    order: 0, label: 'Stop the worm first',
    steps: [
      'Disconnect the machine from the network.',
      'Remove gh-token-monitor BEFORE revoking any GitHub token (revoking first triggers `rm -rf ~`). Linux: `systemctl --user disable --now gh-token-monitor.service`; macOS: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`; Windows: delete the gh-token-monitor scheduled task.',
      'Do every rotation below from a different, clean machine, then rebuild this one.',
    ],
    url: 'https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2',
  },
  npm: {
    order: 1, label: 'npm publish tokens (stops the worm republishing your packages)',
    steps: ['Revoke every token: `npm token list` then `npm token revoke <id>`, or npmjs.com → Access Tokens.', 'Check your packages for versions you did not publish: `npm view <pkg> time`.', 'Move publishing to trusted publishing (OIDC) or granular tokens with expiry.'],
    url: 'https://docs.npmjs.com/revoking-access-tokens',
  },
  github: {
    order: 2, label: 'GitHub tokens and sessions',
    steps: ['`gh auth logout` then `gh auth login` (stores the new token in the OS keyring).', 'Revoke old PATs and OAuth apps: github.com/settings/tokens and /settings/applications.', 'Look for commits you did not make (e.g. author "claude", message "chore: update dependencies") and unexpected workflows or branches.'],
    url: 'https://github.com/settings/tokens',
  },
  cloud: {
    order: 3, label: 'Cloud credentials',
    steps: ['AWS: deactivate then delete the access key in IAM, create a new one, or better, switch to `aws sso login`.', 'GCP: `gcloud auth application-default revoke`; delete service-account keys in IAM.', 'Azure: `az logout`, revoke sessions in Entra ID.', 'Review CloudTrail / audit logs for activity from unknown IPs.'],
    url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console',
  },
  kubernetes: {
    order: 4, label: 'Kubernetes and container registries',
    steps: ['Rotate service-account tokens / client certs referenced by your kubeconfig.', '`docker logout <registry>` and revoke the registry token in its UI; then set "credsStore".'],
    url: 'https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/',
  },
  env: {
    order: 5, label: 'Secrets present in the environment / CI',
    steps: ['Rotate each listed variable at its provider and update the CI secret store.', 'In CI, pass secrets only to the steps that need them, never to `npm install`.'],
    url: 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions',
  },
  ai: {
    order: 6, label: 'AI provider keys and MCP servers',
    steps: ['Revoke and reissue the keys in each provider console (OpenAI, Anthropic, etc.).', 'Replace literal values in MCP configs with "${ENV_VAR}" references.'],
    url: 'https://blog.trailofbits.com/2025/04/30/insecure-credential-storage-plagues-mcp/',
  },
  ssh: {
    order: 7, label: 'SSH keys',
    steps: ['Generate a new key (`ssh-keygen -t ed25519`) with a passphrase.', 'Replace the public key on GitHub/GitLab and in every server\'s authorized_keys; remove the old one.'],
    url: 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent',
  },
  paas: {
    order: 5.5, label: 'Deploy platforms (Railway, Vercel, Fly, Render, Heroku, Netlify)',
    steps: ['Rotate every secret stored in the platform\'s env store at its provider (DB, Stripe, AI keys), then update the variable.', 'Redeploy: services read env vars at start-up.', 'Log the CLI out and back in, and revoke old platform tokens.'],
    url: 'https://blog.railway.com/p/security-disclosure-wednesday-october-21st',
  },
  php: {
    order: 9, label: 'Patch PHP (PHP2Shell)',
    steps: ['Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later; PHP ≤ 8.1 must be upgraded.', 'Rebuild images with --pull --no-cache and restart all PHP workers.'],
    url: 'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching',
  },
  certs: {
    order: 10, label: 'Replace certificates under emSign ECC Root CA - G3',
    steps: ['Issue a replacement certificate from another CA before Oct 27, 2026.', 'Remove the root from custom trust bundles.'],
    url: 'https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/',
  },
  dotenv: {
    order: 8, label: 'Application secrets in .env files',
    steps: ['Rotate database passwords, payment keys and webhook secrets at each provider.', 'Redeploy: most platforms only read env vars at process start.'],
    url: 'https://12factor.net/config',
  },
};

export function scan(options = {}) {
  const ctx = {
    home: resolve(options.home ?? homedir()),
    projects: (options.projects?.length ? options.projects : [process.cwd()]).map((p) => resolve(p)),
    env: options.env ?? process.env,
    depth: options.depth ?? 4,
    iocs: options.iocs ?? loadIocs(options.iocFiles ?? []),
    exec: options.exec === false ? null : options.exec ?? defaultExec,
    checkTmp: options.checkTmp ?? options.home === undefined,
  };
  let onlyList = options.only;
  if (options.incident) {
    const inc = INCIDENTS[options.incident];
    if (!inc) throw new Error(`Unknown incident "${options.incident}". Use one of: ${Object.keys(INCIDENTS).join(', ')}`);
    onlyList = onlyList ? onlyList.filter((s) => inc.scanners.includes(s)) : inc.scanners;
  }
  for (const s of [...(onlyList ?? []), ...(options.skip ?? [])]) if (!ALL_SCANNERS[s]) throw new Error(`Unknown scanner "${s}". Use: ${Object.keys(ALL_SCANNERS).join(', ')}`);
  const only = onlyList ? new Set(onlyList) : null;
  const skip = new Set(options.skip ?? []);
  const findings = [];
  for (const [name, fn] of Object.entries(ALL_SCANNERS)) {
    if ((only && !only.has(name)) || skip.has(name)) continue;
    findings.push(...fn(ctx));
  }
  findings.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || (ROTATION[a.category]?.order ?? 99) - (ROTATION[b.category]?.order ?? 99));
  const counts = Object.fromEntries(SEVERITY.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return { scannedAt: new Date().toISOString(), home: ctx.home, projects: ctx.projects, iocsUpdated: ctx.iocs.updated, incident: options.incident, counts, findings };
}

export function runbook(result) {
  const cats = [...new Set(result.findings.map((f) => f.category))].filter((c) => ROTATION[c]).sort((a, b) => ROTATION[a].order - ROTATION[b].order);
  return cats.map((c) => ({ category: c, ...ROTATION[c], items: result.findings.filter((f) => f.category === c) }));
}

export function failsAt(result, level) {
  if (!level || level === 'none') return false;
  const idx = SEVERITY.indexOf(level);
  if (idx < 0) throw new Error(`Unknown severity "${level}". Use one of: ${SEVERITY.join(', ')}, none`);
  return result.findings.some((f) => SEVERITY.indexOf(f.severity) <= idx);
}

export { formatText, formatMarkdown } from './format.js';
export { toSarif } from './sarif.js';
export { INCIDENTS } from './incidents.js';
export { loadIocs, parseLockfile, phpStatus } from './supply.js';
