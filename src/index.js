import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { SCANNERS } from './scanners.js';
import { SUPPLY_SCANNERS, loadIocs } from './supply.js';
import { INCIDENTS } from './incidents.js';
import { V3_SCANNERS, osvMalicious } from './v3.js';
import { V4_SCANNERS } from './v4.js';

export const ALL_SCANNERS = { ...SCANNERS, ...SUPPLY_SCANNERS, ...V3_SCANNERS, ...V4_SCANNERS };

function defaultExec(cmd, args) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: cmd === 'git' ? 30000 : 4000, maxBuffer: 256 * 1024 * 1024, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    return r.status === 0 ? r.stdout : null;
  } catch {
    return null;
  }
}

export const SEVERITY = ['critical', 'high', 'medium', 'low'];

/**
 * Rotation plan v2. Order = what to do first after a suspected compromise (lower = earlier).
 * steps: what to do; verify: how to confirm the old credential is dead; docs: provider docs the text is based on.
 */
export const ROTATION = {
  persistence: {
    order: 0, label: 'Stop the malware first (worm services, malicious packages/extensions)',
    steps: [
      'Disconnect the machine from the network. Do every rotation below from a different, clean machine.',
      'Remove gh-token-monitor BEFORE revoking any GitHub token (revoking first triggers `rm -rf ~`). Linux: `systemctl --user disable --now gh-token-monitor.service`; macOS: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`; Windows: delete the gh-token-monitor scheduled task.',
      'Uninstall flagged editor extensions and remove known-bad package versions; check crontab, systemd user units, LaunchAgents and .vscode/tasks.json for anything you did not add.',
      'Then rebuild or reimage the machine; removing the package does not undo what its install script already did.',
    ],
    verify: ['`systemctl --user list-units | grep -i token`, `crontab -l`, `ls ~/Library/LaunchAgents` show nothing unexpected.'],
    docs: [['tensorlake advisory (GHSA-8g63-53c9-65j2)', 'https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2'], ['CISA: widespread npm supply chain compromise', 'https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem']],
  },
  npm: {
    order: 1, label: 'Package registry tokens: npm, PyPI, RubyGems, crates.io, Composer (stops a worm republishing your packages)',
    steps: [
      'npm: `npm token list`, then `npm token delete <id>` for each (use the token ID, not the truncated token), or npmjs.com → Access Tokens. npm notes revocation can take up to an hour.',
      'PyPI: delete the token under Account settings → API tokens; recreate it scoped to one project, or switch to Trusted Publishing.',
      'RubyGems: delete the key at rubygems.org → Settings → API keys (delete `legacy-key` if present); `gem signout` then `gem signin` with a gem-scoped key with an expiry and MFA.',
      'crates.io: revoke at crates.io/settings/tokens; `cargo logout`, set `registry.global-credential-providers` to an OS keychain provider, `cargo login`.',
      'Look for versions you did not publish: `npm view <pkg> time`, your PyPI/RubyGems/crates.io project history.',
      'Move CI publishing to trusted publishing (OIDC). Provenance proves where a package was built, not that it is safe: @subql/common@5.8.3 and tensorlake@0.5.144 both shipped with valid provenance.',
    ],
    verify: ['`npm token list` no longer shows the old ID; `npm whoami` with the old token fails (allow up to an hour).'],
    docs: [['npm: Revoking access tokens', 'https://docs.npmjs.com/revoking-access-tokens'], ['PyPI help: API tokens', 'https://pypi.org/help/#apitoken'], ['RubyGems: API key scopes', 'https://guides.rubygems.org/api-key-scopes/'], ['Cargo: registry authentication', 'https://doc.rust-lang.org/cargo/reference/registry-authentication.html'], ['npm trusted publishing', 'https://docs.npmjs.com/trusted-publishers']],
  },
  github: {
    order: 2, label: 'GitHub tokens and sessions',
    steps: [
      'Make sure persistence is gone first (step above).',
      'Revoke PATs at github.com/settings/tokens and OAuth/GitHub App authorizations at /settings/applications; `gh auth logout` then `gh auth login` (stores the new token in the OS keyring).',
      'Replace classic `ghp_` tokens with fine-grained tokens that have an expiry and only the repos they need.',
      'Review your security log for `oauth_authorization` and token events, and repos for commits, branches or workflows you did not create.',
    ],
    verify: ['`gh api user` with the old token returns 401; the token is gone from /settings/tokens.'],
    docs: [['GitHub: token expiration and revocation', 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation'], ['GitHub: managing personal access tokens', 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens']],
  },
  cloud: {
    order: 3, label: 'Cloud and IaC credentials (AWS, GCP, Azure, Terraform, Pulumi)',
    steps: [
      'AWS: create a new access key, update users of it, deactivate the old key, confirm nothing breaks, then delete it. Better: `aws sso login` (short-lived).',
      'GCP: `gcloud auth application-default revoke`; delete exposed service-account keys in IAM.',
      'Azure: `az logout`; revoke sessions for the user in Entra ID.',
      'Terraform/Pulumi: `terraform logout` / `pulumi logout`, delete the token in HCP Terraform / Pulumi Cloud, log in again. Rotate secrets that sit in local .tfstate files.',
      'Review CloudTrail / audit logs (including SSM Parameter Store and Secrets Manager reads) from the exposure window.',
    ],
    verify: ['`aws iam list-access-keys` shows the old key as deleted; calls with it return InvalidClientTokenId.'],
    docs: [['AWS: rotate access keys', 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console'], ['gcloud auth application-default revoke', 'https://cloud.google.com/sdk/gcloud/reference/auth/application-default/revoke']],
  },
  kubernetes: {
    order: 4, label: 'Kubernetes and container registries',
    steps: ['Rotate service-account tokens / client certs referenced by your kubeconfig.', '`docker logout <registry>`, revoke the registry token in its UI, then set "credsStore" so new logins go to the OS keychain.'],
    verify: ['`kubectl auth whoami` with the old credential fails.'],
    docs: [['Kubernetes: service accounts', 'https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/'], ['Docker: credential stores', 'https://docs.docker.com/reference/cli/docker/login/#credential-stores']],
  },
  paas: {
    order: 5, label: 'Deploy platforms (Railway, Vercel, Fly, Render, Heroku, Netlify)', redeploy: true,
    steps: ['Rotate every secret stored in the platform\'s env store at its provider (DB, Stripe, AI keys), then update the variable.', 'Redeploy: services read env vars at start-up.', 'Log the CLI out and back in, and revoke old platform tokens.'],
    verify: ['The old DB password / API key is rejected by its provider; the redeployed service is healthy.'],
    docs: [['Railway security disclosure (Oct 21, 2026)', 'https://blog.railway.com/p/security-disclosure-wednesday-october-21st']],
  },
  env: {
    order: 6, label: 'Secrets present in the environment / CI', redeploy: true,
    steps: ['Rotate each listed variable at its provider and update the CI secret store.', 'In CI, pass secrets only to the steps that need them, never to `npm install`.'],
    verify: ['Re-run this tool in CI: the variable no longer appears in the install step.'],
    docs: [['GitHub Actions: using secrets', 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions']],
  },
  ai: {
    order: 7, label: 'AI provider keys and MCP servers',
    steps: ['Revoke and reissue the keys in each provider console (OpenAI, Anthropic, etc.).', 'Replace literal values in MCP configs with "${ENV_VAR}" references; pin MCP server package versions instead of `npx -y <pkg>`.'],
    verify: ['A request with the old key returns 401.'],
    docs: [['Trail of Bits: insecure credential storage in MCP', 'https://blog.trailofbits.com/2025/04/30/insecure-credential-storage-plagues-mcp/']],
  },
  ssh: {
    order: 8, label: 'SSH keys',
    steps: ['Generate a new key (`ssh-keygen -t ed25519`) with a passphrase.', 'Replace the public key on GitHub/GitLab and in every server\'s authorized_keys; remove the old one.'],
    verify: ['`ssh -i <old key> git@github.com` is denied.'],
    docs: [['GitHub: generating a new SSH key', 'https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent']],
  },
  dotenv: {
    order: 9, label: 'Application secrets in .env files', redeploy: true,
    steps: ['Rotate database passwords, payment keys and webhook secrets at each provider.', 'Redeploy: most platforms only read env vars at process start.'],
    verify: ['The old value is rejected by its provider.'],
    docs: [['The Twelve-Factor App: config', 'https://12factor.net/config']],
  },
  php: {
    order: 10, label: 'Patch PHP (PHP2Shell)', redeploy: true,
    steps: ['Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later; PHP ≤ 8.1 must be upgraded.', 'Rebuild images with --pull --no-cache and restart all PHP workers.'],
    verify: ['`php -v` in each running container shows a fixed version.'],
    docs: [['CISA alert (Oct 21, 2026)', 'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching']],
  },
  certs: {
    order: 11, label: 'Replace certificates under emSign ECC Root CA - G3',
    steps: ['Issue a replacement certificate from another CA before Oct 27, 2026.', 'Remove the root from custom trust bundles.'],
    verify: ['`openssl s_client -connect host:443` shows the new issuer.'],
    docs: [['Google: compromised eMudhra intermediates', 'https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/']],
  },
};
for (const r of Object.values(ROTATION)) r.url = r.docs[0][1];

export function scan(options = {}) {
  const ctx = {
    home: resolve(options.home ?? homedir()),
    projects: (options.projects?.length ? options.projects : [process.cwd()]).map((p) => resolve(p)),
    env: options.env ?? process.env,
    depth: options.depth ?? 4,
    iocs: options.iocs ?? loadIocs(options.iocFiles ?? []),
    exec: options.exec === false ? null : options.exec ?? defaultExec,
    checkTmp: options.checkTmp ?? options.home === undefined,
    history: options.history ?? null, // {since?: string}
    harden: !!options.harden || !!options.only?.includes('harden'),
  };
  let onlyList = options.only;
  if (options.harden) onlyList = ['hardening', 'harden', 'ai'];
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
  return finish(ctx, options, options.harden ? findings.filter((f) => f.category === 'hardening' || f.id === 'ai.mcp-unpinned') : findings);
}

/** Same as scan(), plus the opt-in OSV lookup (network) when options.osv is set. */
export async function scanAsync(options = {}) {
  const result = scan(options);
  if (!options.osv) return result;
  const ctx = { home: result.home, projects: result.projects, depth: options.depth ?? 4, iocs: { updated: result.iocsUpdated } };
  const { findings: osv, queried } = await osvMalicious(ctx, options.osvOptions);
  const known = new Set(result.findings.filter((f) => f.id === 'supply.malicious-version').map((f) => f.title.split(' ')[2].replace('==', '@') + '|' + f.location));
  const findings = osv.filter((f) => !known.has(f.title.split(' ')[2] + '|' + f.location));
  return { ...finish(ctx, options, [...result.findings, ...findings]), osvQueried: queried };
}

function finish(ctx, options, findings) {
  findings.sort((a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity) || (ROTATION[a.category]?.order ?? 99) - (ROTATION[b.category]?.order ?? 99));
  const counts = Object.fromEntries(SEVERITY.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return { scannedAt: new Date().toISOString(), home: ctx.home, projects: ctx.projects, iocsUpdated: ctx.iocs?.updated ?? options.iocsUpdated, incident: options.incident, harden: !!options.harden, counts, findings };
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
