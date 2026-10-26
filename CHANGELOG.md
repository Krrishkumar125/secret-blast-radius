# Changelog

## 0.5.0 (2026-10-26)

- `--html <file>`: self-contained offline HTML report. The rotation plan is the top section, then every finding. No scripts or external assets (a Content-Security-Policy blocks them), token-shaped values are replaced by `[redacted sha256:…]`, URL passwords by `***`, and all dynamic text is HTML-escaped.
- New `frontend` scanner (rotation category "Secrets shipped to the browser", ordered right after deploy platforms): secrets in `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`, `VUE_APP_` and `PUBLIC_` variables in `.env` files, and recognised tokens inside built JS/HTML in `dist`, `build`, `out`, `.next/static`, `.output/public`, `.svelte-kit/output/client`, `public`. Publishable keys (Stripe `pk_`, Google/Firebase `AIza`, Supabase anon, PostHog, Mapbox, Sentry DSN) are not flagged.
- Library: `formatHtml`, `redact`, `escapeHtml`, `scanFrontend`, `findTokensInText` exported.
- Tests for redaction, HTML escaping (secrets with `<script>` and quotes, paths with `&`, `<`, `>`) and the frontend check. Removed unused imports.

## 0.4.3 (2026-10-25)

- Runbook: adds "0. Before revoking any GitHub token" (check for and remove gh-token-monitor) when GitHub tokens are found but no worm persistence was detected.
- README: says it checks for known signs of compromise, instead of claiming to tell whether a compromise already happened.
