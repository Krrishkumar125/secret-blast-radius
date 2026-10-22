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

**New in 0.4:** `--harden` audits the settings that would have blunted this month's attacks and prints the exact fix: cooldowns, `--require-hashes`, uv `exclude-newer`, digest-pinned images, OIDC instead of long-lived publish/cloud keys, unpinned MCP servers, `.env` files with secrets committed to git. Also new: Python lockfiles and virtualenvs (requirements, poetry.lock, uv.lock, Pipfile.lock, pylock.toml), Docker image references, and `--incident litellm` / `--incident zeabur`.

**New in 0.3:** `--history` shows the dates a bad version sat in your lockfile; GlassWorm editor-extension check; npm cache check; RubyGems/Cargo/Composer/Terraform/Pulumi credential files; opt-in `--osv` malicious-package lookup; a rotation plan with verify steps and provider docs.

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
| `ecosystems` | RubyGems `~/.gem/credentials`, Cargo `credentials.toml` (the plaintext `cargo:token` store), Composer `auth.json` (global and project), Terraform `credentials.tfrc.json`, Pulumi `credentials.json`, local `.tfstate` files |

**Signs you're already hit:**

| Scanner | Detects |
|---|---|
| `malicious` | Known-bad versions in `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic + Berry), `bun.lock`, and in `node_modules`: tensorlake + native packages, `@subql/common@5.8.3`, `@7nohe/openapi-react-query-codegen` (10 versions), the keyv/cacheable wave; the `@opensearch/setup` worm marker |
| `extensions` | Installed VS Code / Cursor / Windsurf / VSCodium / Kiro / remote-server extensions against 149 GlassWorm IOCs from Socket (malicious, version-scoped, and flagged sleepers), including ones pulled in through `extensionPack` |
| `npm-cache` | Tarballs of known-bad versions in the npm cache index: proof the machine downloaded one even if no lockfile shows it today |
| `history` (`--history`) | **Exposure window.** Walks each lockfile's git history and reports when a known-bad version entered and left (`2026-10-08 → 2026-10-10`), so you know which CI runs and machines to treat as exposed. `--since 2026-09-01` narrows it |
| `python` | Known-bad PyPI versions (litellm 1.107.0, 1.82.7/1.82.8) in requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, pdm.lock, pylock.toml and project virtualenvs; the litellm `cook.pth` startup hook |
| `images` | Dockerfile `FROM` and compose `image:` references to compromised image digests/tags, and floating tags (`latest`, `main-stable`) that pointed at a compromised image during a known window |
| `persistence` | `gh-token-monitor` (systemd unit, LaunchAgent, Windows dir, script) |
| `host-persistence` | Crontab lines that pipe a server into `bash` (GhostAction `#ghc2`), the `manifest-cache.js --warm` process and `/tmp/tmp.ts018051808.lock` (@subql) |
| `repo` | Workflows that contact GhostAction infrastructure, dump `git log -p --all`, or serialise `toJSON(secrets)` to the network; `.vscode/tasks.json` that auto-runs a "font"/image; Claude Code hooks that run disguised files; the tensorlake worm branch |

**Exposure to this month's other incidents:**

| Scanner | Detects |
|---|---|
| `php` | PHP2Shell-vulnerable PHP in Dockerfiles, compose files, `composer.json` platform pins and the local `php` binary. Distro builds are flagged *high, verify backport* rather than critical |
| `certs` | PEM/CRT files and `NODE_EXTRA_CA_CERTS` bundles containing or chaining to the distrusted **emSign ECC Root CA - G3** (eMudhra) |
| `install-scripts` | Which dependencies run install scripts, straight from the lockfile |
| `hardening` | No `ignore-scripts`; no dependency cooldown, with the right setting for the package manager you use (npm `min-release-age`, pnpm `minimumReleaseAge`, Yarn `npmMinimalAgeGate`, Bun `install.minimumReleaseAge`) |

**Opt-in online check:** `--osv` sends the package names and versions from your lockfiles (nothing else) to the [OSV API](https://google.github.io/osv.dev/post-v1-querybatch/) and reports `MAL-` advisories from the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) feed. That covers far more than the bundled list. Vulnerability (CVE/GHSA) results are ignored on purpose; use OSV-Scanner for those.

**Small extras:** least-privilege hints from a token's public prefix (classic `ghp_` PAT, long-lived `AKIA` key), and MCP servers started with an unpinned `npx -y <pkg>`.

## `--harden`: prevent the next one

```bash
npx secret-blast-radius --harden
```

Read-only audit of preventive settings. Every finding has a `fix:` line with the exact change:

| Check | Why (Oct 2026 evidence) | Fix it prints |
|---|---|---|
| npm `ignore-scripts`, cooldown for npm/pnpm/Yarn/Bun | tensorlake ran from `preinstall` and was live under 2h | `ignore-scripts=true`, `min-release-age=3`, `minimumReleaseAge: 4320`, … |
| pnpm `dangerouslyAllowAllBuilds: true` | pnpm blocks dependency builds by default; this turns that off | remove it, allow-list with `allowBuilds`/`onlyBuiltDependencies` |
| requirements not pinned / no `--hash` | an unpinned `litellm` resolved to 1.107.0 | `uv pip compile --generate-hashes`, `pip install --require-hashes` |
| uv without `exclude-newer` | litellm 1.107.0 was live ~2h | `exclude-newer = "3 days"` under `[tool.uv]` |
| images not pinned by digest | litellm's `latest`/`main-stable` served a stealer for ~2.5h | `image:tag@sha256:…` + Renovate/Dependabot |
| long-lived `NPM_TOKEN`, PyPI `password:`, AWS keys in workflows | stolen long-lived tokens drove LiteLLM, tensorlake, GhostAction | npm/PyPI trusted publishing, AWS `role-to-assume` (OIDC) |
| MCP servers run with `npx -y <pkg>` | pulls whatever is latest on every start | pin `pkg@x.y.z` |
| `.env` with secret-looking values committed or not ignored (needs git) | CERT-In Oct 15: agents got in via plaintext credentials in repos | `git rm --cached`, `.gitignore`, rotate |

Checks only fire on files you have. Settings that are already safe by default (pnpm build blocking) are not nagged about. Cargo cooldowns land in Rust 1.100 (Nov 12), so they aren't checked yet.

## Rotation plan

`--runbook` writes an ordered plan: stop the malware, then registry tokens (npm, PyPI, RubyGems, crates.io), GitHub, cloud and IaC, Kubernetes, deploy platforms, CI env, AI keys, SSH, app secrets. Each step has the exact commands, a **verify** check that the old credential is dead, a **redeploy** reminder where running processes keep old values, and links to the provider's own docs. One example of why the details matter: npm says token revocation can take up to an hour.

Trusted publishing and provenance tell you *where* a package was built. They don't tell you it's safe: `@subql/common@5.8.3` and `tensorlake@0.5.144` both had valid provenance.

## Incident mode

```bash
npx secret-blast-radius --list-incidents
npx secret-blast-radius --incident tensorlake     # or: glassworm, shai-hulud, subql, ghostaction, railway, php2shell, emudhra, sbi
```

Runs only the checks that matter for that incident and prints a sourced checklist, marking what's confirmed and what's still under investigation. `--runbook` turns it into a Markdown checklist you can paste into an incident ticket.

## In CI and GitHub code scanning

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: Krrishkumar125/secret-blast-radius@v0.4.1
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
- **Offline by default.** It makes no network requests unless you pass `--osv`, which sends package names and versions only. The IOC lists are bundled (`src/iocs.json`, `src/extension-iocs.json`, dated). Add your own with `--ioc-file extra.json` (`packages` and `extensions` keys).
- **Secret values are never printed.** Findings show a location and a `sha256:xxxxxxxx` fingerprint. Every output format is tested for leaks.
- **Zero dependencies.** Helper commands (`php -v`, `crontab -l`, `ps -eo args`, and `git log`/`git show` for `--history`) are run read-only with a timeout; `--no-exec` disables them.

## Options

| Option | Meaning |
|---|---|
| `[project-dir…]` | Projects to scan for `.env`, lockfiles, Dockerfiles, workflows (default: cwd) |
| `--incident <name>`, `--list-incidents` | Incident checklists |
| `--json`, `--sarif`, `--sarif-file <f>` | Machine output |
| `--runbook`, `--runbook-file <f>` | Markdown rotation checklist |
| `--fail-on <level>` | Exit 1 at/above `critical`, `high`, `medium`, `low` (default `none`) |
| `--only` / `--skip <list>` | Choose scanners (names in the tables above) |
| `--history`, `--since <date>` | Lockfile exposure window from git history |
| `--osv` | Online, opt-in OSV malicious-package lookup |
| `--ioc-file <f>` | Extra IOCs, same shape as `src/iocs.json` (repeatable) |
| `--no-env`, `--no-exec`, `--depth <n>`, `--home <dir>`, `--no-color` | Tuning |

Exit codes: `0` ok, `1` findings at/above `--fail-on`, `2` usage error.

## Keeping false positives low

These are skipped on purpose: `${VAR}`, `${{ secrets.X }}`, `op://…`, `[YOUR_KEY]`, `your_api_key_here`, `not-a-secret`, prose values like `this-is-a-secret-value`, credential-free URLs (`redis://localhost`, `file:./dev.db`), `.env.example/.sample/.template/.demo`, `node_modules`, ordinary `folderOpen` tasks, and Claude hooks that run normal tools. Every rule above came from running the tool on real repos (TanStack Router, symfony/demo, vercel/next.js, docker-library/wordpress, Railway templates). If you hit a false positive, please open an issue.

## Use it with these tools

secret-blast-radius answers one question: *what could have been stolen, and what do I rotate first?* For the rest, use the tools built for it:

| Need | Use |
|---|---|
| Secrets committed to git history | [gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) (TruffleHog can also verify whether a key is live) |
| Vulnerable dependencies (CVEs) across ecosystems | [OSV-Scanner](https://github.com/google/osv-scanner) |
| GitHub Actions risks: `pull_request_target`, unpinned actions, template injection, excessive permissions | [zizmor](https://github.com/zizmorcore/zizmor) |
| Blocking exfiltration from CI runners at runtime | [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) |
| Vetting packages before you install them | [Socket](https://socket.dev) |

## Limits

- It checks well-known locations. It can't see your OS keychain (that's the point) or browser profiles.
- The bundled IOC lists cover the incidents above, not every malicious package ever published. Use `--osv` for the full OpenSSF feed.
- `--history` follows lockfiles that exist today; a lockfile that was deleted or renamed is not followed. On partial (`--filter=blob:none`) clones it fetches old blobs and is slow.
- Sleeper extensions were benign when Socket found them. They're flagged as high risk, not proven malicious.
- For distro PHP builds it can't tell whether your vendor backported the fix.
- A clean report shrinks your blast radius. It doesn't prove a machine is clean.

## Programmatic API

```js
import { scan, scanAsync, runbook, toSarif, INCIDENTS } from 'secret-blast-radius';
const result = scan({ projects: ['.'], incident: 'railway', exec: false });
const withOsv = await scanAsync({ projects: ['.'], osv: true, history: { since: '2026-09-01' } });
```

MIT © Krrish Kumar

## Sibling packages

Other tools by the same author:

- [zod-india](https://www.npmjs.com/package/zod-india): Zod schemas for GSTIN, PAN, IFSC, UPI and Aadhaar
- [create-bullmq-app](https://www.npmjs.com/package/create-bullmq-app): scaffold a production BullMQ + TypeScript service
- [webhook-crash-lab](https://www.npmjs.com/package/webhook-crash-lab): crash-test webhook handlers against duplicates and races
- [webhook-crash-lab-mcp](https://www.npmjs.com/package/webhook-crash-lab-mcp): MCP server so coding agents can run webhook-crash-lab
- [eslint-plugin-bullmq](https://www.npmjs.com/package/eslint-plugin-bullmq): lint rules for BullMQ production pitfalls
- [eslint-plugin-webhook-safety](https://www.npmjs.com/package/eslint-plugin-webhook-safety): lint rules for unsafe Stripe webhook handlers
