# Changelog

## 0.6.0 (2026-11-26)

- Rotation plan: new step "Caches, mirrors and artifact stores", right after registry tokens. It covers npm, pnpm, Yarn and Bun caches, CI caches (`gh cache delete --all`), rotating a private mirror's own tokens and upstream credentials and purging bad versions from it (Verdaccio, Artifactory, Nexus, GitHub Packages, CodeArtifact), and rebuilding images with `--pull --no-cache` and BuildKit secret mounts. Its verify check: revoke every token, clear the caches, rebuild; if private installs still work, something still holds a credential.
- The step is added to the runbook whenever registry tokens or known-bad packages are found, not only when the new scanner finds something.
- New `caches` scanner (read-only, offline): non-npmjs registries in `.npmrc`, `.yarnrc.yml` and `bunfig.toml`; credentials in lockfile `resolved` URLs (fingerprinted, never printed); Dockerfiles with `ARG`/`ENV` npm tokens or `COPY .npmrc`; GitHub Actions workflows that cache `~/.npm`, pnpm/Yarn/Bun stores or `node_modules`. Included in the tensorlake and subql incident checklists.
- SARIF: findings that point at a line (`file:12`, used by the images and caches checks) now give code scanning a clean repo-relative path plus a `startLine` region. Before, the `:12` ended up inside the file path.
- Rotation steps after the new one are renumbered by one. No new dependencies.

## 0.5.1 (2026-11-22)

- Text output, the Markdown runbook, the HTML report, incident titles and details, and the README no longer use em or en dashes. Titles use a colon and date ranges use "to".
- Test: a new check fails if an em or en dash appears in incident data, source files, the README or any report format.

## 0.5.0 (2026-10-26)

- `--html <file>`: self-contained offline HTML report. The rotation plan is the top section, then every finding. No scripts or external assets (a Content-Security-Policy blocks them), token-shaped values are replaced by `[redacted sha256:…]`, URL passwords by `***`, and all dynamic text is HTML-escaped.
- New `frontend` scanner (rotation category "Secrets shipped to the browser", ordered right after deploy platforms): secrets in `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`, `VUE_APP_` and `PUBLIC_` variables in `.env` files, and recognised tokens inside built JS/HTML in `dist`, `build`, `out`, `.next/static`, `.output/public`, `.svelte-kit/output/client`, `public`. Publishable keys (Stripe `pk_`, Google/Firebase `AIza`, Supabase anon, PostHog, Mapbox, Sentry DSN) are not flagged.
- Library: `formatHtml`, `redact`, `escapeHtml`, `scanFrontend`, `findTokensInText` exported.
- Tests for redaction, HTML escaping (secrets with `<script>` and quotes, paths with `&`, `<`, `>`) and the frontend check. Removed unused imports.

## 0.4.3 (2026-10-25)

- Runbook: adds "0. Before revoking any GitHub token" (check for and remove gh-token-monitor) when GitHub tokens are found but no worm persistence was detected.
- README: says it checks for known signs of compromise, instead of claiming to tell whether a compromise already happened.
