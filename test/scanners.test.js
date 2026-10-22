import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { scan, runbook, failsAt, formatText, formatMarkdown } from '../src/index.js';
import { isReference, looksLikeSecretName, tokenKind } from '../src/util.js';
import { sshKeyEncrypted, parseDotenv } from '../src/scanners.js';
import { fixture, FAKE } from './helpers.js';

const run = (root, only, extra = {}) => scan({ home: join(root, 'home'), projects: [join(root, 'proj')], env: {}, only, ...extra });
const allValues = Object.values(FAKE);
const assertNoLeak = (s) => { for (const v of allValues) assert.ok(!s.includes(v), `leaked ${v.slice(0, 6)}…`); assert.ok(!s.includes('hunter2')); };

test('npm: plaintext registry token is critical, env reference is ignored', (t) => {
  const f = fixture({
    'home/.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.npm}\n//npm.pkg.github.com/:_authToken=\${GITHUB_TOKEN}\n`,
    'proj/.npmrc': `@corp:registry=https://npm.corp.dev/\n//npm.corp.dev/:_authToken=abcdef123456\n`,
  });
  t.after(f.cleanup);
  const r = run(f.root, ['npm']);
  assert.equal(r.findings.length, 2);
  assert.equal(r.findings[0].severity, 'critical');
  assert.match(r.findings[0].title, /registry\.npmjs\.org/);
  assert.equal(r.findings[1].severity, 'high');
  assert.match(r.findings[0].fingerprint, /^sha256:[0-9a-f]{8}$/);
  assertNoLeak(JSON.stringify(r));
});

test('github: gh hosts.yml plaintext token and .git-credentials', (t) => {
  const f = fixture({
    'home/.config/gh/hosts.yml': `github.com:\n    user: me\n    oauth_token: ${FAKE.ghp}\n    git_protocol: https\n`,
    'home/.git-credentials': `https://me:${FAKE.ghp}@github.com\n`,
    'proj/x': '',
  });
  t.after(f.cleanup);
  const r = run(f.root, ['github']);
  assert.deepEqual(r.findings.map((x) => x.id).sort(), ['github.gh-cli-plaintext', 'github.git-credentials']);
  assertNoLeak(formatText(r));
});

test('github: keyring-backed gh (no oauth_token) is not reported', (t) => {
  const f = fixture({ 'home/.config/gh/hosts.yml': 'github.com:\n    user: me\n    git_protocol: https\n', 'proj/x': '' });
  t.after(f.cleanup);
  assert.equal(run(f.root, ['github']).findings.length, 0);
});

test('cloud: long-lived AWS key is critical, session key is medium, GCP service account is critical', (t) => {
  const f = fixture({
    'home/.aws/credentials': `[default]\naws_access_key_id = ${FAKE.akia}\naws_secret_access_key = x\n[tmp]\naws_access_key_id=${FAKE.asia}\n`,
    'home/.config/gcloud/application_default_credentials.json': JSON.stringify({ type: 'service_account', private_key: 'x' }),
    'proj/x': '',
  });
  t.after(f.cleanup);
  const r = run(f.root, ['cloud']);
  const sev = Object.fromEntries(r.findings.map((x) => [x.title, x.severity]));
  assert.equal(sev['AWS long-lived access key (profile "default")'], 'critical');
  assert.equal(sev['AWS session access key (profile "tmp")'], 'medium');
  assert.equal(sev['Google Cloud application default credentials (service_account)'], 'critical');
});

test('kubernetes & docker: embedded creds flagged, credsStore-only config is clean', (t) => {
  const f = fixture({
    'home/.kube/config': 'users:\n- name: a\n  user:\n    token: abc\n- name: b\n  user:\n    client-key-data: LS0t\n',
    'home/.docker/config.json': JSON.stringify({ auths: { 'ghcr.io': { auth: Buffer.from('u:p').toString('base64') }, 'docker.io': {} }, credsStore: 'desktop' }),
    'proj/x': '',
  });
  t.after(f.cleanup);
  const r = run(f.root, ['kubernetes']);
  assert.equal(r.findings.length, 2);
  assert.match(r.findings.find((x) => x.id === 'k8s.embedded-credentials').title, /2 embedded/);
  assert.match(r.findings.find((x) => x.id === 'registry.docker-plaintext').title, /ghcr\.io/);
});

test('env: recognises token formats and secret-like names, skips public/short values', () => {
  const r = scan({
    home: '/nonexistent-home', projects: ['/nonexistent-proj'], only: ['env'],
    env: { NPM_TOKEN: FAKE.npm, OPENAI_API_KEY: FAKE.openai, NEXT_PUBLIC_SUPABASE_ANON_KEY: 'eyJhbGciOiJIUzI1NiJ9.public', DEBUG_TOKEN: 'x', PATH: '/usr/bin', HOME: '/root', GITHUB_TOKEN: '${{ secrets.X }}' },
  });
  const names = r.findings.map((x) => x.title.split(':')[1].trim().split(' ')[0]).sort();
  assert.deepEqual(names, ['NPM_TOKEN', 'OPENAI_API_KEY']);
  assert.equal(r.findings.find((x) => x.title.includes('NPM_TOKEN')).severity, 'critical');
  assertNoLeak(JSON.stringify(r));
});

test('ai: literal secrets in MCP env/headers/args/url are found; ${VAR} references are not', (t) => {
  const f = fixture({
    'home/.cursor/mcp.json': JSON.stringify({ mcpServers: {
      github: { command: 'npx', args: ['-y', 'server-github'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: FAKE.ghp } },
      safe: { command: 'npx', env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${GITHUB_TOKEN}' } },
      remote: { url: 'https://mcp.example.com/sse?api_key=abc123def456', headers: { Authorization: 'Bearer ' + FAKE.openai } },
      cli: { command: 'tool', args: ['--api-key=' + FAKE.stripe] },
    } }),
    'home/.claude.json': JSON.stringify({ projects: { '/p': { mcpServers: { db: { command: 'pg', env: { DATABASE_URL: FAKE.pg } } } } } }),
    'proj/.vscode/mcp.json': JSON.stringify({ servers: { x: { env: { API_KEY: '${input:key}' } } } }),
  });
  t.after(f.cleanup);
  const r = run(f.root, ['ai']);
  const titles = r.findings.map((x) => x.title).sort();
  assert.deepEqual(titles, [
    'MCP server "cli" has a literal secret in args',
    'MCP server "db" has a literal secret in env.DATABASE_URL',
    'MCP server "github" has a literal secret in env.GITHUB_PERSONAL_ACCESS_TOKEN',
    'MCP server "remote" has a literal secret in headers.Authorization',
    'MCP server "remote" has a literal secret in url query',
  ]);
  assertNoLeak(JSON.stringify(r) + formatText(r) + formatMarkdown(r));
});

test('ssh: unencrypted keys flagged, passphrase-protected keys and public keys ignored', (t) => {
  const plain = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
  const enc = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'pw' });
  // Minimal openssh-key-v1 blobs: magic + cipher name.
  const blob = (cipher) => {
    const magic = Buffer.from('openssh-key-v1\0', 'latin1');
    const len = Buffer.alloc(4); len.writeUInt32BE(cipher.length);
    const b64 = Buffer.concat([magic, len, Buffer.from(cipher), Buffer.alloc(32)]).toString('base64');
    return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
  };
  const f = fixture({
    'home/.ssh/id_plain': plain, 'home/.ssh/id_enc': enc,
    'home/.ssh/id_ed25519': blob('none'), 'home/.ssh/id_ok': blob('aes256-ctr'),
    'home/.ssh/id_ed25519.pub': 'ssh-ed25519 AAAA', 'home/.ssh/known_hosts': 'x', 'proj/x': '',
  });
  t.after(f.cleanup);
  const r = run(f.root, ['ssh']);
  assert.deepEqual(r.findings.map((x) => x.location.split('/').pop()).sort(), ['id_ed25519', 'id_plain']);
  assert.equal(sshKeyEncrypted(Buffer.from(blob('aes256-ctr'))), true);
  assert.equal(sshKeyEncrypted(Buffer.from('not a key')), null);
});

test('dotenv: finds secrets in nested .env files, skips examples and node_modules', (t) => {
  const f = fixture({
    'proj/.env': `# comment\nPORT=3000\nDATABASE_URL="${FAKE.pg}"\nSTRIPE_SECRET_KEY=${FAKE.stripe}\nNEXT_PUBLIC_API_URL=https://x\n`,
    'proj/apps/api/.env.local': 'export JWT_SECRET=supersecretvalue123\nREDIS_URL=${REDIS_URL}\n',
    'proj/.env.example': `STRIPE_SECRET_KEY=${FAKE.stripe}\n`,
    'proj/node_modules/pkg/.env': `TOKEN=${FAKE.npm}\n`,
    'home/x': '',
  });
  t.after(f.cleanup);
  const r = run(f.root, ['dotenv']);
  assert.equal(r.findings.length, 2);
  const root = r.findings.find((x) => x.title.endsWith(' .env'));
  assert.deepEqual(root.names, ['DATABASE_URL', 'STRIPE_SECRET_KEY']);
  assert.equal(root.severity, 'high');
  const nested = r.findings.find((x) => x.title.includes('apps/api/.env.local'));
  assert.deepEqual(nested.names, ['JWT_SECRET']);
  assert.equal(nested.severity, 'medium');
  assertNoLeak(JSON.stringify(r));
});

test('persistence: gh-token-monitor puts "stop the worm" first in the runbook', (t) => {
  const f = fixture({
    'home/.local/bin/gh-token-monitor.sh': '#!/bin/sh',
    'home/.config/gh/hosts.yml': `github.com:\n    oauth_token: ${FAKE.ghp}\n`,
    'home/.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.npm}\n`,
    'proj/.env': `STRIPE_SECRET_KEY=${FAKE.stripe}\n`,
  });
  t.after(f.cleanup);
  const r = run(f.root, ['persistence', 'npm', 'github', 'dotenv']);
  assert.deepEqual(runbook(r).map((s) => s.category), ['persistence', 'npm', 'github', 'dotenv']);
  const md = formatMarkdown(r);
  assert.ok(md.indexOf('BEFORE revoking') < md.indexOf('npm token revoke'));
  assertNoLeak(md);
});

test('hardening: suggestions disappear when ignore-scripts and release age are set', (t) => {
  const f = fixture({ 'home/.npmrc': 'ignore-scripts=true\nmin-release-age=3\n', 'proj/x': '' });
  t.after(f.cleanup);
  assert.equal(run(f.root, ['hardening']).findings.length, 0);
  const g = fixture({ 'home/x': '', 'proj/x': '' });
  t.after(g.cleanup);
  assert.equal(run(g.root, ['hardening']).findings.length, 2);
});

test('failsAt and severity ordering', (t) => {
  const f = fixture({ 'home/.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.npm}\n`, 'proj/.env': 'JWT_SECRET=supersecretvalue123\n' });
  t.after(f.cleanup);
  const r = run(f.root, ['npm', 'dotenv']);
  assert.deepEqual(r.findings.map((x) => x.severity), ['critical', 'medium']);
  assert.equal(failsAt(r, 'critical'), true);
  assert.equal(failsAt(r, 'none'), false);
  assert.throws(() => failsAt(r, 'bogus'), /Unknown severity/);
  assert.deepEqual(r.counts, { critical: 1, high: 0, medium: 1, low: 0 });
});

test('empty machine produces a clean report', (t) => {
  const f = fixture({ 'home/x': '', 'proj/x': '' });
  t.after(f.cleanup);
  const r = run(f.root, ['npm', 'github', 'cloud', 'ai', 'ssh', 'dotenv']);
  assert.equal(r.findings.length, 0);
  assert.match(formatText(r), /No reachable secrets/);
  assert.match(formatMarkdown(r), /Nothing to rotate/);
});

test('util helpers', () => {
  for (const v of ['${X}', '$X', '${env:X}', '${input:k}', '', 'your-api-key', 'xxxxxxxx', '<token>', 'op://vault/item']) assert.ok(isReference(v), v);
  for (const v of ['abc123', FAKE.npm]) assert.ok(!isReference(v), v);
  assert.ok(looksLikeSecretName('STRIPE_SECRET_KEY'));
  assert.ok(looksLikeSecretName('DATABASE_URL'));
  assert.ok(!looksLikeSecretName('NEXT_PUBLIC_API_KEY'));
  assert.ok(!looksLikeSecretName('TOKEN_EXPIRY'));
  assert.ok(!looksLikeSecretName('PORT'));
  assert.equal(tokenKind(FAKE.npm), 'npm token');
  assert.equal(tokenKind(FAKE.pg), 'connection string with password');
  assert.equal(tokenKind('postgres://localhost/db'), null);
  assert.deepEqual(parseDotenv('A=1 # c\nexport B="x y"\n#C=2\n'), [['A', '1'], ['B', 'x y']]);
});

test('github: the same token listed twice in hosts.yml (gh ≥ 2.40 users map) is reported once', (t) => {
  const f = fixture({ 'home/.config/gh/hosts.yml': `github.com:\n    users:\n        me:\n            oauth_token: ${FAKE.ghp}\n    oauth_token: ${FAKE.ghp}\n    user: me\n`, 'proj/x': '' });
  t.after(f.cleanup);
  assert.equal(run(f.root, ['github']).findings.length, 1);
});

test('dotenv: placeholders and credential-free URLs are not secrets (seen in TanStack Router examples)', (t) => {
  const f = fixture({
    'proj/.env': 'CLERK_SECRET_KEY=[YOUR_CLERK_SECRET_KEY]\nVITE_CLERK_PUBLISHABLE_KEY=[YOUR_KEY]\nDATABASE_URL="file:./dev.db"\nREDIS_URL=redis://localhost:6379\nOPENAI_API_KEY=your_api_key_here\nAPI_TOKEN=insert-your-token-here\n',
    'home/x': '',
  });
  t.after(f.cleanup);
  assert.equal(run(f.root, ['dotenv']).findings.length, 0);
});
