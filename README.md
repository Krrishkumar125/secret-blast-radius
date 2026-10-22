# secret-blast-radius

[![CI](https://github.com/Krrishkumar125/secret-blast-radius/actions/workflows/ci.yml/badge.svg)](https://github.com/Krrishkumar125/secret-blast-radius/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/secret-blast-radius)](https://www.npmjs.com/package/secret-blast-radius)

**One bad `npm install` can read every secret on your laptop. This tells you what it would get, whether it already happened, and what to rotate first.**

```bash
npx secret-blast-radius
```

```
✖ CRITICAL Known-malicious package @subql/common@5.8.3 (subql)
  ~/code/indexer/package-lock.json
  Resolved in this lockfile. Treat every machine/CI runner that installed it as compromised…

✖ CRITICAL Plaintext npm credential for registry.npmjs.org
  ~/.npmrc  sha256:3f1c9a0b
  Any install script can read this and republish every package you maintain (this is how Shai-Hulud spreads).

✖ CRITICAL VS Code task "eslint-check" auto-runs on folder open and executes a non-code file
  ~/code/old-portfolio/.vscode/tasks.json
  Matches the GhostAction / PolinRider launcher (tasks.json → `node public/fonts/*.woff2`)…

▲ HIGH     MCP server "github" has a literal secret in env.GITHUB_PERSONAL_ACCESS_TOKEN
  ~/.cursor/mcp.json  sha256:9b07e6c1

● MEDIUM   api deploys to Railway (railway.toml)
  Railway disclosed on Oct 21, 2026 that env vars may have been read and decrypted…

Summary: 3 critical, 1 high, 1 medium, 0 low.
Rotation order if this machine is ever compromised: 1. persistence  2. npm  3. ai  4. paas
```

*(Illustrative output: fingerprints and paths are examples.)*

## Why this exists

The last few weeks, in order:

| When (2026) | What | What it took |
|---|---|---|
| Oct 5 | [`@subql/common@5.8.3`](https://osv.dev/vulnerability/MAL-2026-17571) shipped through the project's own trusted-publishing workflow | AWS (SSM + Secrets Manager, all regions), GitHub, npm, SSH, K8s, Vault. Runs on import too, so `--ignore-scripts` isn't enough |
| Oct 7–15 | [GhostAction](https://thehackernews.com/2026/10/credential-stealing-github-actions.html): ~1,900 hijacked GitHub accounts pushed "security audit" workflows to 30,000+ repos, then a [VS Code fake-font stealer](https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file) | Actions secrets, everything in git history, `~/.npmrc`, `~/.aws`, `~/.netrc`, SSH keys, Claude/Gemini logins, plus a cron backdoor |
| Oct 8 | [`tensorlake@0.5.144`](https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2) (Mini Shai-Hulud) | Everything above plus AI-tool and MCP configs. Installs `gh-token-monitor`, which **wipes your home directory if you revoke the stolen GitHub token** |
| Oct 21 | [Railway](https://blog.railway.com/p/security-disclosure-wednesday-october-21st): customer env vars may have been decrypted | Every secret you stored on the platform |
| Oct 21 | [PHP2Shell](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) (CVE-2026-109618/-109619), unauthenticated RCE | Whatever your PHP servers can reach |

Every advisory ends the same way: *"rotate everything the machine could access."* Hardly anyone has that list. This tool builds it, checks for the known infections, and puts the steps in an order that won't make things worse.

## What it checks

**Your credentials** (what a stealer reads first):

| Scanner | Looks at |
|---|---|
| `npm` | `~/.npmrc`, project `.npmrc`, `~/.pypirc`: literal tokens (not `${VAR}`) |
| `github` | gh `hosts.yml` (plaintext fallback), `~/.git-credentials`, `~/.netrc` |
| `cloud` | `~/.aws/credentials` (long-lived vs session), gcloud ADC, Azure token cache |
| `kubernetes` | `~/.kube/config` embedded tokens/keys, `~/.docker/config.json` without `credsStore` |
| `ai` | MCP configs for Claude Code/Desktop, Cursor, Windsurf, VS Code, Zed, Kiro, Gemini; Claude, Gemini and Codex CLI logins |
| `ssh` | Private keys without a passphrase (PEM, PKCS#8, OpenSSH) |
| `dotenv` | `.env*` files in your projects (names only, never values) |
| `env` | Variables a CI step inherits (`NPM_TOKEN`, `AWS_*`, recognised token formats) |
| `paas` | Railway, Vercel, Fly, Render, Netlify CLI tokens; Heroku in `~/.netrc`; which projects deploy where |

**Signs you're already hit:**

| Scanner | Detects |
|---|---|
| `malicious` | Known-bad versions in `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic + Berry), `bun.lock`, and in `node_modules`: tensorlake + native packages, `@subql/common@5.8.3`, `@7nohe/openapi-react-query-codegen` (10 versions), the keyv/cacheable wave; the `@opensearch/setup` worm marker |
| `persistence` | `gh-token-monitor` (systemd unit, LaunchAgent, Windows dir, script) |
| `host-persistence` | Crontab lines that pipe a server into `bash` (GhostAction `#ghc2`), the `manifest-cache.js --warm` process and `/tmp/tmp.ts018051808.lock` (@subql) |
| `repo` | Workflows that contact GhostAction infrastructure, dump `git log -p --all`, or serialise `toJSON(secrets)` to the network; `.vscode/tasks.json` that auto-runs a "font"/image; Claude Code hooks that run disguised files; the tensorlake worm branch |

**Exposure to this month's other incidents:**

| Scanner | Detects |
|---|---|
| `php` | PHP2Shell-vulnerable PHP in Dockerfiles, compose files, `composer.json` platform pins and the local `php` binary. Distro builds are flagged *high, verify backport* rather than critical |
| `certs` | PEM/CRT files and `NODE_EXTRA_CA_CERTS` bundles containing or chaining to the distrusted **emSign ECC Root CA - G3** (eMudhra) |
| `install-scripts` | Which dependencies run install scripts, straight from the lockfile |
| `hardening` | No `ignore-scripts`, no dependency cooldown (`min-release-age` / `minimumReleaseAge`) |

## Incident mode

```bash
npx secret-blast-radius --list-incidents
npx secret-blast-radius --incident tensorlake     # or: shai-hulud, subql, ghostaction, railway, php2shell, emudhra, sbi
```

Runs only the checks that matter for that incident and prints a sourced checklist, marking what's confirmed and what's still under investigation. `--runbook` turns it into a Markdown checklist you can paste into an incident ticket.

## In CI and GitHub code scanning

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Krrishkumar125/secret-blast-radius@v0.2.0
    with:
      fail-on: critical
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: secret-blast-radius.sarif
```

Or without the action: `npx secret-blast-radius@0 --only malicious,repo,php,env --fail-on critical --sarif-file sbr.sarif`.
SARIF only gets file locations for findings inside the repo. Home-directory findings are reported without a path.

## Safety

- **Read-only.** It only writes files you name (`--runbook-file`, `--sarif-file`).
- **Offline.** It makes no network requests. The IOC list is bundled (`src/iocs.json`, dated). Add your own with `--ioc-file extra.json`.
- **Secret values are never printed.** Findings show a location and a `sha256:xxxxxxxx` fingerprint. Every output format is tested for leaks.
- **Zero dependencies.** Helper commands (`php -r`, `crontab -l`, `ps -eo args`) are run read-only with a timeout; `--no-exec` disables them.

## Options

| Option | Meaning |
|---|---|
| `[project-dir…]` | Projects to scan for `.env`, lockfiles, Dockerfiles, workflows (default: cwd) |
| `--incident <name>`, `--list-incidents` | Incident checklists |
| `--json`, `--sarif`, `--sarif-file <f>` | Machine output |
| `--runbook`, `--runbook-file <f>` | Markdown rotation checklist |
| `--fail-on <level>` | Exit 1 at/above `critical`, `high`, `medium`, `low` (default `none`) |
| `--only` / `--skip <list>` | Choose scanners (names in the tables above) |
| `--ioc-file <f>` | Extra IOCs, same shape as `src/iocs.json` (repeatable) |
| `--no-env`, `--no-exec`, `--depth <n>`, `--home <dir>`, `--no-color` | Tuning |

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` usage error.

## Keeping false positives low

These are skipped on purpose: `${VAR}`, `${{ secrets.X }}`, `op://…`, `[YOUR_KEY]`, `your_api_key_here`, `not-a-secret`, prose values like `this-is-a-secret-value`, credential-free URLs (`redis://localhost`, `file:./dev.db`), `.env.example/.sample/.template/.demo`, `node_modules`, ordinary `folderOpen` tasks, and Claude hooks that run normal tools. Every rule above came from running the tool on real repos (TanStack Router, symfony/demo, vercel/next.js, docker-library/wordpress, Railway templates). If you hit a false positive, please open an issue.

## Limits

- It checks well-known locations. It can't see your OS keychain (that's the point) or browser profiles.
- The IOC list covers the incidents above, not every malicious package ever published. Pair it with `npm audit`, OSV or Socket.
- For distro PHP builds it can't tell whether your vendor backported the fix.
- A clean report shrinks your blast radius. It doesn't prove a machine is clean.

## Programmatic API

```js
import { scan, runbook, toSarif, INCIDENTS } from 'secret-blast-radius';
const result = scan({ projects: ['.'], incident: 'railway', exec: false });
```

MIT © Krrish Kumar
