# secret-blast-radius

[![CI](https://github.com/Krrishkumar125/secret-blast-radius/actions/workflows/ci.yml/badge.svg)](https://github.com/Krrishkumar125/secret-blast-radius/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/secret-blast-radius)](https://www.npmjs.com/package/secret-blast-radius)

**If a malicious `npm install` ran on this machine right now, what would it get, and what would you rotate first?**

```bash
npx secret-blast-radius
```

```
✖ CRITICAL Plaintext npm credential for registry.npmjs.org
  ~/.npmrc  sha256:3f1c9a0b
  Any install script can read this and republish every package you maintain (this is how Shai-Hulud spreads).

✖ CRITICAL GitHub CLI token stored in plaintext
  ~/.config/gh/hosts.yml  sha256:a81d22e4
  gh fell back to a plaintext file (no OS keyring). Install scripts can read it and push to every repo you can write to.

▲ HIGH     MCP server "github" has a literal secret in env.GITHUB_PERSONAL_ACCESS_TOKEN
  ~/.cursor/mcp.json  sha256:9b07e6c1

● MEDIUM   2 secret(s) in apps/api/.env
  Keys: DATABASE_URL, STRIPE_SECRET_KEY — recognised: connection string with password, Stripe live secret key.

Summary: 2 critical, 1 high, 1 medium, 0 low.
Rotation order if this machine is ever compromised: 1. npm  2. github  3. ai  4. dotenv
```

## Why

October 2026 alone: `tensorlake@0.5.144` and other "Mini Shai-Hulud" releases ran a `preinstall` hook that harvested
npm, GitHub, cloud, Kubernetes, SSH, `.env` **and coding-agent/MCP config** credentials, then used the npm token to
republish itself ([advisory](https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2),
[StepSecurity](https://www.stepsecurity.io/blog/tensorlake-npm-compromised-hostage-token-worm)). Railway told every
customer to rotate secrets after env vars may have been decrypted
([disclosure](https://blog.railway.com/p/security-disclosure-wednesday-october-21st)).

Advisories say "rotate everything the machine could access". Few people know what that list is. This tool writes it
for you, **before** an incident (so you can shrink it) and **during** one (so you rotate in the right order).

What's different from existing tools:

- **Not a malware/IOC scanner** ([shai-hulud-detect](https://github.com/cobenian/shai-hulud-detect) does that well) and
  **not a repo secret scanner** (gitleaks, trufflehog scan git history). It inventories the credentials *reachable on the
  machine or CI runner*, which is exactly what an install script can read.
- **One report across every place:** npm, GitHub CLI and git, AWS/GCP/Azure, kubeconfig and docker, SSH keys, MCP configs for
  Claude, Cursor, Windsurf, VS Code, Zed, Kiro and Gemini, project `.env` files, and the environment variables a CI step inherits.
- **An ordered rotation runbook.** Order matters: the worm's `gh-token-monitor` wipes your home directory when you revoke
  the stolen GitHub token, so persistence comes first, then the credentials a worm spreads with (npm, GitHub), then the rest.

## Safety

- Read-only. It never writes anywhere except an optional runbook file you name.
- **No network requests**. Zero dependencies.
- **Secret values are never printed.** Findings show a location and a `sha256:xxxxxxxx` fingerprint so you can tell keys apart.
  The test suite checks every output format for leaks.

## Usage

```bash
npx secret-blast-radius                       # scan home dir + current project
npx secret-blast-radius ~/code/api ~/code/web # scan specific projects for .env files
npx secret-blast-radius --runbook             # Markdown rotation checklist to stdout
npx secret-blast-radius --runbook-file rotate.md --runbook
npx secret-blast-radius --json                # machine-readable
npx secret-blast-radius --fail-on high        # exit 1 if anything high or critical (CI gate)
npx secret-blast-radius --only npm,github,ai  # pick scanners
```

| Option | Meaning |
|---|---|
| `--json` | JSON report including the ordered runbook |
| `--runbook`, `--runbook-file <f>` | Markdown rotation checklist |
| `--fail-on <level>` | `critical`, `high`, `medium`, `low` or `none` (default) |
| `--only` / `--skip <list>` | `persistence,npm,github,cloud,kubernetes,env,ai,ssh,dotenv,hardening` |
| `--no-env` | Skip environment variables |
| `--depth <n>` | How deep to search project dirs for `.env*` (default 4; skips `node_modules`, `.git`, build dirs) |
| `--home <dir>` | Inspect another home directory (e.g. a mounted disk image) |

### In CI: what does `npm install` get to see?

```yaml
- run: npx secret-blast-radius@0 --only env,npm --fail-on critical
```

If that fails, a secret such as `NPM_TOKEN` is exposed to every dependency's install script in that job. Move it to the
publish step only, or switch to [trusted publishing](https://docs.npmjs.com/trusted-publishers).

## What it checks

| Scanner | Looks at | Flags |
|---|---|---|
| `persistence` | `gh-token-monitor` files (Linux, macOS, Windows) | Active Shai-Hulud "hostage token" service |
| `npm` | `~/.npmrc`, project `.npmrc` | Literal `_authToken` / `_auth` / `_password` (not `${VAR}`) |
| `github` | gh `hosts.yml`, `~/.git-credentials` | Tokens stored in plaintext instead of the keyring |
| `cloud` | `~/.aws/credentials`, gcloud ADC, Azure token cache | Long-lived keys (critical) vs session keys |
| `kubernetes` | `~/.kube/config`, `~/.docker/config.json` | Embedded tokens/client keys, registry auth without `credsStore` |
| `env` | Current process environment | Known token formats and secret-named variables |
| `ai` | MCP configs for Claude Code/Desktop, Cursor, Windsurf, VS Code, Zed, Kiro, Gemini; Codex auth | Literal keys in `env`, `headers`, `args`, URL query |
| `ssh` | `~/.ssh/*` private keys | Keys without a passphrase (PEM, PKCS#8 and OpenSSH formats) |
| `dotenv` | `.env*` in project dirs (not `.env.example`) | Secret-named keys and recognised tokens; URLs only when they embed a password |
| `hardening` | `.npmrc`, `pnpm-workspace.yaml` | No `ignore-scripts`, no dependency cooldown (`min-release-age` / `minimumReleaseAge`) |

Placeholders such as `${VAR}`, `${{ secrets.X }}`, `${env:X}`, `op://…`, `<token>`, `[YOUR_KEY]` and `your_api_key_here` are ignored.

## Programmatic API

```js
import { scan, runbook, failsAt, formatMarkdown } from 'secret-blast-radius';

const result = scan({ projects: ['.'], skip: ['env'] });
console.log(result.counts);            // { critical, high, medium, low }
console.log(runbook(result)[0].label); // first thing to rotate
```

## Limits

It checks well-known locations; it can't see secrets in your OS keychain (which is the point), browser profiles, or files
in unusual paths. A clean report shrinks your blast radius; it doesn't prove a machine is uncompromised.

## License

MIT © Krrish Kumar
