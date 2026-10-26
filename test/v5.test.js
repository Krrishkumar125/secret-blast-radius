import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scan, formatHtml, redact, escapeHtml, findTokensInText, runbook, ROTATION } from '../src/index.js';
import { exposedSecret } from '../src/frontend.js';
import { fixture, FAKE } from './helpers.js';

const CLI = fileURLToPath(new URL('../bin/cli.js', import.meta.url));
const cli = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } });
const ALL_FAKES = Object.values(FAKE);
const PG_PASSWORD = 'hunter2hunter2';

/* ---------------- redaction ---------------- */

test('redact: every token format is replaced by a fingerprint, never kept in full', () => {
  for (const v of ALL_FAKES) {
    const out = redact(`before ${v} after`);
    assert.ok(!out.includes(v), v.slice(0, 6));
    assert.match(out, /\[redacted sha256:[0-9a-f]{8}\]|:\*\*\*@/);
    assert.match(out, /^before .* after$/);
  }
  assert.ok(!redact(FAKE.pg).includes(PG_PASSWORD));
  assert.ok(!redact('https://user:s3cr3tpass@api.example.com/x').includes('s3cr3tpass'));
  assert.equal(redact('plain text, nothing secret'), 'plain text, nothing secret');
});

test('html: a secret that leaks into any field is redacted, and markup in it is escaped', () => {
  const evil = `${FAKE.stripe}"><script>alert('x')</script>`;
  const result = {
    scannedAt: '2026-10-26T00:00:00.000Z', projects: ['/tmp/a&b<c>'], counts: { critical: 1, high: 1, medium: 0, low: 0 },
    findings: [
      { id: 'dotenv.secrets', category: 'dotenv', severity: 'critical', title: `leaked ${evil}`, location: '/srv/x&y/<img src=x onerror=alert(1)>/.env', fingerprint: 'sha256:deadbeef', detail: `value ${FAKE.npm} and ${FAKE.pg} and ${FAKE.ghp}`, fix: `use \`${FAKE.akia}\` <b>never</b>` },
      { id: 'env.secret', category: 'env', severity: 'high', title: `"quoted" 'single' & ampersand ${FAKE.openai}`, location: 'process environment', detail: `${FAKE.asia}` },
    ],
  };
  const html = formatHtml(result, { version: '0.5.0' });
  for (const v of ALL_FAKES) assert.ok(!html.includes(v), `leaked ${v.slice(0, 6)}`);
  assert.ok(!html.includes(PG_PASSWORD));
  assert.ok(!/<script/i.test(html), 'no script tag at all');
  assert.ok(!html.includes('<img'), 'no injected img');
  assert.ok(!html.includes('<b>never'), 'no injected markup from fix text');
  assert.ok(html.includes('&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;'));
  assert.ok(html.includes('&quot;&gt;'));
  assert.ok(html.includes('/srv/x&amp;y/&lt;img src=x onerror=alert(1)&gt;/.env'));
  assert.ok(html.includes('/tmp/a&amp;b&lt;c&gt;'));
  assert.ok(html.includes('&quot;quoted&quot; &#39;single&#39; &amp; ampersand'));
  assert.match(html, /\[redacted sha256:[0-9a-f]{8}\]/);
});

test('escapeHtml covers the five HTML specials and backticks', () => {
  assert.equal(escapeHtml(`<a href="x" title='y'>&\`</a>`), '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&#96;&lt;/a&gt;');
  assert.equal(escapeHtml(null), '');
});

/* ---------------- html structure ---------------- */

test('html: offline, rotation plan comes first, then findings', () => {
  const result = { scannedAt: 'x', projects: [], counts: { critical: 1, high: 0, medium: 0, low: 1 }, findings: [
    { id: 'npm.token', category: 'npm', severity: 'critical', title: 'Plaintext npm credential', location: '~/.npmrc', fingerprint: 'sha256:12345678', detail: 'd' },
    { id: 'hardening.ignore-scripts', category: 'hardening', severity: 'low', title: 'npm runs dependency install scripts', location: '~/.npmrc', detail: 'd' },
  ] };
  const html = formatHtml(result);
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
  // No external resources: no <script>, <link>, <img src=http>, @import, url(http)
  assert.ok(!/<script|<link|<iframe|<object|@import|url\(\s*['"]?https?:|src=["']?https?:/i.test(html));
  const plan = html.indexOf('id="plan"'), findings = html.indexOf('id="findings"');
  assert.ok(plan > 0 && findings > plan, 'plan before findings');
  assert.match(html, /<h3>1\. Package registry tokens/);
  assert.match(html, /<code>npm token list<\/code>/);
  assert.match(html, /Verify the old credential is dead/);
  // Docs are plain links, not loaded resources
  assert.match(html, /<a href="https:\/\/docs\.npmjs\.com\/revoking-access-tokens" rel="noreferrer">/);
  // GitHub without persistence gets step 0 here too
  const gh = formatHtml({ scannedAt: 'x', findings: [{ category: 'github', severity: 'high', title: 't', location: 'l', detail: '' }] });
  assert.match(gh, /0\. Before revoking any GitHub token/);
  assert.match(formatHtml({ scannedAt: 'x', findings: [] }), /Nothing to rotate/);
});

test('cli --html: writes a redacted, escaped report for paths with & < > and secrets with quotes/<script>', (t) => {
  // Windows forbids < > " in file names; still cover & there.
  const dir = process.platform === 'win32' ? 'a&b proj' : 'a&b<c>"d proj';
  const evilValue = `${FAKE.stripe}`;
  const f = fixture({
    'home/.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.npm}\n`,
    [`${dir}/.env`]: `STRIPE_SECRET_KEY=${evilValue}\nSESSION_SECRET="q'u\\"<script>alert(1)</script>zz9Kp2"\nNEXT_PUBLIC_OPENAI_KEY=${FAKE.openai}\n`,
  });
  t.after(f.cleanup);
  const out = join(f.root, 'report.html');
  const r = cli(['--html', out, '--home', join(f.root, 'home'), '--no-env', '--no-exec', join(f.root, dir)]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /HTML report written to/);
  const html = readFileSync(out, 'utf8');
  for (const v of ALL_FAKES) assert.ok(!html.includes(v), `leaked ${v.slice(0, 6)}`);
  assert.ok(!html.includes('zz9Kp2') && !/<script/i.test(html));
  assert.ok(html.includes('a&amp;b'));
  if (process.platform !== 'win32') assert.ok(html.includes('a&amp;b&lt;c&gt;&quot;d proj'));
  assert.match(html, /Secrets shipped to the browser/);
  assert.match(html, /NEXT_PUBLIC_OPENAI_KEY/);
  // Plan order: npm before frontend before dotenv
  const i = (s) => html.indexOf(s);
  assert.ok(i('Package registry tokens') < i('Secrets shipped to the browser') && i('Secrets shipped to the browser') < i('Application secrets in .env files'));
});

/* ---------------- frontend check ---------------- */

test('frontend: public-prefixed env vars with secrets are flagged, public-by-design keys are not', (t) => {
  const f = fixture({
    'web/.env.local': [
      `NEXT_PUBLIC_STRIPE_SECRET_KEY=${FAKE.stripe}`,
      `VITE_OPENAI_API_KEY=${FAKE.openai}`,
      `REACT_APP_AWS_KEY=${FAKE.akia}`,
      `EXPO_PUBLIC_DB_PASSWORD=Xq7rT2vLp9Wm`,
      'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_' + 'A'.repeat(24),
      'NEXT_PUBLIC_FIREBASE_API_KEY=AIza' + 'B'.repeat(35),
      'NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.e30.abc',
      'NEXT_PUBLIC_API_URL=https://api.example.com',
      'VITE_API_KEY=${API_KEY}',
      `STRIPE_SECRET_KEY=${FAKE.stripe}`, // server-only: dotenv's job, not frontend
    ].join('\n'),
    'web/.env.example': `NEXT_PUBLIC_STRIPE_SECRET_KEY=${FAKE.stripe}\n`,
  });
  t.after(f.cleanup);
  const r = scan({ home: join(f.root, 'home'), projects: [f.root], only: ['frontend'], exec: false, env: {} });
  const names = r.findings.filter((x) => x.id === 'frontend.public-env').map((x) => x.names[0]).sort();
  assert.deepEqual(names, ['EXPO_PUBLIC_DB_PASSWORD', 'NEXT_PUBLIC_STRIPE_SECRET_KEY', 'REACT_APP_AWS_KEY', 'VITE_OPENAI_API_KEY']);
  const sev = Object.fromEntries(r.findings.map((x) => [x.names[0], x.severity]));
  assert.equal(sev.NEXT_PUBLIC_STRIPE_SECRET_KEY, 'critical');
  assert.equal(sev.EXPO_PUBLIC_DB_PASSWORD, 'medium');
  assert.match(r.findings.find((x) => x.names[0] === 'VITE_OPENAI_API_KEY').detail, /Vite inlines VITE_\*/);
  const json = JSON.stringify(r);
  for (const v of ALL_FAKES) assert.ok(!json.includes(v));
  assert.ok(!json.includes('Xq7rT2vLp9Wm'));
  assert.equal(runbook(r)[0].category, 'frontend');
});

test('frontend: secrets inside built JS (dist, .next/static, nested app build) are flagged; server output and node_modules are not', (t) => {
  const f = fixture({
    'dist/assets/index-abc.js': `const k="${FAKE.stripe}";fetch("x",{headers:{a:"${FAKE.openai}"}});const k2="${FAKE.stripe}";`,
    '.next/static/chunks/page.js': `var t="${FAKE.ghp}"`,
    '.next/server/app/page.js': `var server="${FAKE.npm}"`,
    'apps/web/build/static/js/main.js': `x="${FAKE.pg}"`,
    'dist/clean.js': 'console.log("pk_live_' + 'A'.repeat(24) + '", "AIza' + 'B'.repeat(35) + '")',
    'node_modules/pkg/dist/x.js': `y="${FAKE.akia}"`,
    'dist/readme.txt': `z="${FAKE.akia}"`,
    'src/app.js': `w="${FAKE.akia}"`,
  });
  t.after(f.cleanup);
  const r = scan({ home: join(f.root, 'home'), projects: [f.root], only: ['frontend'], exec: false, env: {} });
  const built = r.findings.filter((x) => x.id === 'frontend.built-secret');
  const where = built.map((x) => x.title.replace(/^.* file /, '')).sort();
  assert.deepEqual(where, ['.next/static/chunks/page.js', 'apps/web/build/static/js/main.js', 'dist/assets/index-abc.js']);
  const idx = built.find((x) => x.title.includes('index-abc'));
  assert.match(idx.title, /^2 secret\(s\)/);
  assert.match(idx.detail, /Stripe live secret key/);
  assert.equal(idx.fingerprints.length, 2);
  assert.ok(built.every((x) => x.severity === 'critical'));
  const json = JSON.stringify(r);
  for (const v of ALL_FAKES) assert.ok(!json.includes(v));
});

test('frontend: helpers', () => {
  assert.equal(exposedSecret('STRIPE_SECRET_KEY', FAKE.stripe), null, 'no public prefix');
  assert.equal(exposedSecret('NEXT_PUBLIC_', FAKE.stripe), null);
  assert.equal(exposedSecret('NEXT_PUBLIC_TOKEN', '${TOKEN}'), null);
  assert.ok(exposedSecret('PUBLIC_GITHUB_TOKEN', FAKE.ghp).strong);
  assert.deepEqual(findTokensInText(`a ${FAKE.npm} b ${FAKE.akia}`).map((h) => h.kind), ['npm token', 'AWS access key']);
  assert.deepEqual(findTokensInText('postgres://u:p4ss@localhost:5432/db'), []);
  assert.ok(ROTATION.frontend.steps.length && ROTATION.frontend.verify.length && ROTATION.frontend.docs.length);
});
