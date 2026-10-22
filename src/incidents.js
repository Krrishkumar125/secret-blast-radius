/** Incident playbooks. Every claim here is sourced; `status` marks what is confirmed vs still under investigation. */
export const INCIDENTS = {
  php2shell: {
    title: 'PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (Oct 21, 2026)',
    status: 'Confirmed by the PHP project and CISA. CISA had not observed exploitation at publication; public PoCs were circulating.',
    scanners: ['php'],
    checklist: [
      'Inventory every PHP runtime: servers, containers, base images, and products that bundle PHP (CISA: "prevalence may not be directly observable").',
      'Update to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your distro\'s patched build) and restart every PHP-FPM pool / Apache worker.',
      'PHP 8.1 and older get no fix: upgrade, or take internet-facing systems offline until you can (CISA).',
      'Rebuild images with `--pull --no-cache`; a floating `php:8.3` tag does not update images you already built.',
      'Watch for PHP worker processes spawning shells or downloading tools.',
    ],
    refs: ['https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/', 'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching'],
  },
  railway: {
    title: 'Railway environment-variable exposure (disclosed Oct 21, 2026)',
    status: 'Confirmed by Railway; scope still being determined ("may be limited to a subset of users"). Railway advises all users to act.',
    scanners: ['paas', 'dotenv', 'env'],
    checklist: [
      'Roll every environment variable stored in Railway: API keys, database passwords, webhook secrets, OAuth client secrets.',
      'Rotate private container-registry credentials configured in Railway.',
      'Review provider logs (database, Stripe, cloud, AI providers) for use of the old keys from unknown IPs.',
      'Redeploy once builds resume: running services keep the old values until restart.',
      'Watch for Railway\'s direct email if your account is in the confirmed set, and status.railway.com for updates.',
    ],
    refs: ['https://blog.railway.com/p/security-disclosure-wednesday-october-21st'],
  },
  tensorlake: {
    title: 'tensorlake@0.5.144 — Mini Shai-Hulud worm with gh-token-monitor dead-man\'s switch (Oct 8, 2026)',
    status: 'Confirmed by the maintainer (GHSA-8g63-53c9-65j2), Socket, StepSecurity and Aikido.',
    scanners: ['malicious', 'persistence', 'host-persistence', 'repo', 'npm', 'github', 'cloud', 'kubernetes', 'ssh', 'ai', 'dotenv', 'env'],
    checklist: [
      'Search lockfiles and CI logs for tensorlake@0.5.144 and tensorlake-native-*@0.5.144 (live 01:12–02:54 UTC, Oct 8).',
      'If it ran: disconnect, then REMOVE gh-token-monitor before revoking any GitHub token (revocation triggers `rm -rf ~`).',
      'From a clean machine rotate npm, GitHub, cloud, Kubernetes, Vault, SSH/GPG, .env, AI-tool/MCP credentials.',
      'Check packages you publish for versions you did not release; check repos for commits by claude@users.noreply.github.com and the branch dependabot/github_actions/format/setup-formatter.',
      'Rebuild the machine from a trusted image.',
    ],
    refs: ['https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2', 'https://www.stepsecurity.io/blog/tensorlake-npm-compromised-hostage-token-worm'],
  },
  subql: {
    title: '@subql/common@5.8.3 — credential stealer + remote shell (Oct 5, 2026)',
    status: 'Confirmed: GHSA-9333-3c4x-x3h5 / MAL-2026-17571; analysed by StepSecurity and GMO Flatt Security.',
    scanners: ['malicious', 'host-persistence', 'cloud', 'github', 'npm', 'ssh', 'kubernetes', 'env', 'dotenv'],
    checklist: [
      'Search lockfiles, caches and CI logs for @subql/common@5.8.3. 5.8.2 is the last known-good release.',
      '`--ignore-scripts` is NOT enough: importing the package also starts the payload.',
      'Look for a running `manifest-cache.js --warm` process and /tmp/tmp.ts018051808.lock; block ci-artifacts.dev.',
      'Rotate AWS credentials first (SSM Parameter Store and Secrets Manager were read across all regions), then GitHub, npm, SSH, Kubernetes, Vault.',
      'Rebuild affected hosts/runners; uninstalling does not stop the detached worker.',
    ],
    refs: ['https://osv.dev/vulnerability/MAL-2026-17571', 'https://www.stepsecurity.io/blog/subql-ecosystem-compromised', 'https://flatt.tech/research/posts/subql-common-npm-supply-chain-attack/'],
  },
  ghostaction: {
    title: 'GhostAction — malicious "security audit" workflows + VS Code fake-font stealer (Oct 7–15, 2026)',
    status: 'Confirmed by StepSecurity, Socket, GitGuardian and OpenSourceMalware. ~1,900 accounts, 30,000+ repos targeted.',
    scanners: ['repo', 'host-persistence', 'github', 'npm', 'cloud', 'kubernetes', 'ssh', 'ai'],
    checklist: [
      'Revoke GitHub sessions, PATs, OAuth grants (incl. client ID Ov23ctrqCqZ79UaYKwyq), SSH and deploy keys FIRST: deleting the workflow does not revoke the token that pushed it.',
      'In every repo you can write to, remove workflows contacting 193.32.204.199 (security-audit.yml, lint.yml, ci-check.yml, …), .vscode/tasks.json "eslint-check" tasks and public/fonts/*.woff2 files that are really JS.',
      'Rotate the repo\'s Actions secrets and every credential ever committed to any branch (Stage 1 reads `git log -p --all`).',
      'If you opened an infected repo in VS Code with automatic tasks allowed: run `crontab -l` and remove lines ending in #ghc2, then rotate from a clean device.',
      'Require approval for workflow runs and protect .github/workflows with required reviews.',
    ],
    refs: ['https://thehackernews.com/2026/10/credential-stealing-github-actions.html', 'https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file', 'https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/'],
  },
  emudhra: {
    title: 'eMudhra — weak keys in 8 intermediates under emSign ECC Root CA - G3 (reported Oct 17–18, 2026)',
    status: 'Confirmed by Google, Mozilla and eMudhra. eMudhra says no certificates were issued from the intermediates; root cause still under investigation.',
    scanners: ['certs'],
    checklist: [
      'Website operators: if your TLS chain ends at emSign ECC Root CA - G3, get a certificate from another CA before Chrome removes the root (Oct 27, 2026 PDT).',
      'Remove emSign ECC Root CA - G3 from custom CA bundles (NODE_EXTRA_CA_CERTS, Java truststores, pinned bundles in apps/IoT).',
      'Clients that do not enforce Certificate Transparency or consume CRLSets/OneCRL need a trust-store update to stop trusting the intermediates.',
      'eMudhra states its Indian DSC/eSign services run on separate hierarchies and are unaffected.',
    ],
    refs: ['https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/', 'https://emudhra.com/en/post/certificate-security-incident/'],
  },
  sbi: {
    title: 'SBI — customer records found on the dark web (disclosed Oct 21, 2026)',
    status: 'Under investigation. SBI\'s preliminary analysis of ~375,000 records found 3,897 customer records with PII; source not yet determined.',
    scanners: ['dotenv', 'env', 'ai'],
    checklist: [
      'Nothing to scan on a developer machine for this one: it is a data exposure, not a software flaw.',
      'Customers: expect targeted calls/SMS using real names, phone numbers, addresses and loan details. Banks never ask for OTP, PIN or remote-access apps.',
      'Fintech/lending developers: CERT-In\'s Oct 9 and Oct 15 advisories cite exposed credentials, test APIs and plaintext payment-API keys. The secrets inventory below is where to start.',
    ],
    refs: ['https://economictimes.indiatimes.com/industry/banking/finance/banking/sbi-probes-suspected-data-breach-after-3-75-lakh-records-surface-on-dark-web/articleshow/135083347.cms'],
  },
};
INCIDENTS['shai-hulud'] = { ...INCIDENTS.tensorlake, title: 'Mini Shai-Hulud npm worm family (keyv/cacheable Aug 2026, @7nohe/openapi-react-query-codegen, tensorlake Oct 2026)' };
