import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, runbook, ROTATION, formatMarkdown } from '../src/index.js';
import { parseRegistries, registryProduct, lockfileCredentials, dockerCredentialLeaks, workflowCaches } from '../src/caches.js';
import { fixture, FAKE } from './helpers.js';

const only = (root, home = root) => scan({ projects: [root], home, only: ['caches'], exec: false, env: {} });
const ids = (r) => r.findings.map((f) => f.id).sort();
const PASS = 'p4ss' + 'w0rd' + 'zz';

/* ---------------- parsers ---------------- */

test('parseRegistries: default and scoped registries in .npmrc, .yarnrc.yml and bunfig.toml; comments ignored', () => {
  const npmrc = ['registry=https://npm.corp.example.com/repository/npm-group/', '@acme:registry=https://npm.pkg.github.com', '# registry=https://ignored.example.com', '; @x:registry=https://ignored2.example.com'].join('\n');
  assert.deepEqual(parseRegistries('/p/.npmrc', npmrc).map((r) => [r.scope, r.url]), [[null, 'https://npm.corp.example.com/repository/npm-group/'], ['@acme', 'https://npm.pkg.github.com']]);
  const yarnrc = 'npmRegistryServer: "https://acme.jfrog.io/artifactory/api/npm/npm/"\nnpmScopes:\n  acme:\n    npmRegistryServer: https://npm.pkg.github.com\n';
  assert.equal(parseRegistries('/p/.yarnrc.yml', yarnrc).length, 2);
  assert.equal(parseRegistries('/p/bunfig.toml', '[install]\nregistry = "https://verdaccio.internal:4873/"\n')[0].url, 'https://verdaccio.internal:4873/');
});

test('registryProduct: recognises common mirrors from the URL', () => {
  assert.equal(registryProduct('https://npm.pkg.github.com'), 'GitHub Packages');
  assert.equal(registryProduct('https://acme.jfrog.io/artifactory/api/npm/npm/'), 'Artifactory');
  assert.equal(registryProduct('https://nexus.corp/repository/npm-proxy/'), 'Nexus');
  assert.equal(registryProduct('http://localhost:4873/'), 'Verdaccio');
  assert.equal(registryProduct('https://d-1234.d.codeartifact.us-east-1.amazonaws.com/npm/repo/'), 'AWS CodeArtifact');
  assert.equal(registryProduct('https://registry.example.com/'), null);
});

test('lockfileCredentials: user:pass@ and token query params, never plain URLs', () => {
  const lock = JSON.stringify({ packages: {
    'node_modules/a': { resolved: `https://ci:${PASS}@npm.corp.example.com/a/-/a-1.0.0.tgz` },
    'node_modules/b': { resolved: `https://npm.corp.example.com/b/-/b-1.0.0.tgz?_authToken=${FAKE.npm}` },
    'node_modules/c': { resolved: 'https://registry.npmjs.org/c/-/c-1.0.0.tgz' },
  } }, null, 2);
  const c = lockfileCredentials(lock);
  assert.deepEqual(c.map((x) => x.value), [PASS, FAKE.npm]);
  assert.ok(c.every((x) => x.host === 'npm.corp.example.com'));
});

test('dockerCredentialLeaks: ARG/ENV tokens and COPY .npmrc are flagged, ordinary lines are not', () => {
  const df = ['FROM node:22', 'ARG NPM_TOKEN', 'ENV NODE_AUTH_TOKEN=$NPM_TOKEN', 'COPY package.json .npmrc ./', 'ARG BUILD_DATE', 'COPY src ./src', 'RUN npm ci'].join('\n');
  assert.deepEqual(dockerCredentialLeaks(df).map((l) => [l.kind, l.name, l.line]), [['arg', 'NPM_TOKEN', 2], ['env', 'NODE_AUTH_TOKEN', 3], ['copy', '.npmrc', 4]]);
  assert.deepEqual(dockerCredentialLeaks('FROM node:22\nRUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci\n'), []);
});

test('workflowCaches: actions/cache paths and setup-node cache, one entry per kind', () => {
  const wf = [
    'jobs:', '  t:', '    steps:',
    '      - uses: actions/checkout@v4',
    '        with:', '          path: node_modules_docs',
    '      - uses: actions/setup-node@v4', '        with:', '          node-version: 22', '          cache: npm',
    '      - uses: actions/cache@v4', '        with:', '          path: |', '            ~/.npm', '            node_modules', '          key: deps-${{ hashFiles(\'package-lock.json\') }}',
    '      - name: build', '        run: echo node_modules',
  ].join('\n');
  const c = workflowCaches(wf);
  assert.deepEqual(c.map((x) => [x.what, x.severity]), [['npm cache via actions/setup-node', 'low'], ['~/.npm via actions/cache', 'low'], ['node_modules via actions/cache', 'medium']]);
});

/* ---------------- scanner ---------------- */

test('caches scanner: a project with a mirror, a credential lockfile, a leaky Dockerfile and a cached node_modules', (t) => {
  const f = fixture({
    'app/.npmrc': '@acme:registry=https://npm.pkg.github.com\nregistry=https://registry.npmjs.org/\n',
    'app/package-lock.json': JSON.stringify({ packages: { 'node_modules/a': { resolved: `https://ci:${PASS}@nexus.corp/repository/npm/a/-/a-1.0.0.tgz` } } }),
    'app/Dockerfile': 'FROM node:22\nARG NPM_TOKEN\nCOPY .npmrc ./\nRUN npm ci\n',
    '.github/workflows/ci.yml': 'jobs:\n  t:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          path: node_modules\n          key: x\n',
  });
  t.after(f.cleanup);
  const r = only(f.root);
  assert.deepEqual(ids(r), ['caches.ci-dependency-cache', 'caches.docker-build-arg-token', 'caches.docker-copied-npmrc', 'caches.lockfile-credential', 'caches.private-registry']);
  const reg = r.findings.find((x) => x.id === 'caches.private-registry');
  assert.match(reg.title, /@acme go through GitHub Packages at npm\.pkg\.github\.com/);
  const lock = r.findings.find((x) => x.id === 'caches.lockfile-credential');
  assert.equal(lock.severity, 'high');
  assert.match(lock.fingerprint, /^sha256:[0-9a-f]{8}$/);
  assert.ok(!JSON.stringify(r).includes(PASS), 'the password is never in the result');
});

test('caches scanner: a plain npmjs project with no caches reports nothing', (t) => {
  const f = fixture({ 'app/.npmrc': 'registry=https://registry.npmjs.org/\n', 'app/package-lock.json': '{"packages":{}}', 'app/Dockerfile': 'FROM node:22\nRUN npm ci\n' });
  t.after(f.cleanup);
  assert.deepEqual(only(f.root).findings, []);
});

test('caches scanner: node_modules inside the project is never walked', (t) => {
  const f = fixture({ 'app/node_modules/x/.npmrc': 'registry=https://evil.example.com/\n' });
  t.after(f.cleanup);
  assert.deepEqual(only(f.root).findings, []);
});

/* ---------------- rotation plan ---------------- */

test('rotation: caches step sits right after registry tokens and before GitHub', () => {
  assert.equal(ROTATION.caches.order, ROTATION.npm.order + 1);
  assert.ok(ROTATION.caches.order < ROTATION.github.order);
  const text = JSON.stringify(ROTATION.caches);
  for (const s of ['gh cache delete --all', 'npm cache clean --force', 'Verdaccio', 'Artifactory', 'Nexus', 'GitHub Packages', '--pull --no-cache']) assert.ok(text.includes(s), s);
  assert.match(ROTATION.caches.verify[0], /Revoke every token, clear the caches, then rebuild/);
});

test('runbook: the caches step appears when registry tokens or known-bad packages are found, even with no cache finding', () => {
  const npmOnly = { findings: [{ id: 'npm.token', category: 'npm', severity: 'critical' }] };
  assert.deepEqual(runbook(npmOnly).map((s) => s.category), ['npm', 'caches']);
  const bad = { findings: [{ id: 'supply.malicious-version', category: 'persistence', severity: 'critical' }] };
  assert.deepEqual(runbook(bad).map((s) => s.category), ['persistence', 'caches']);
  const unrelated = { findings: [{ id: 'ssh.key', category: 'ssh', severity: 'high' }] };
  assert.deepEqual(runbook(unrelated).map((s) => s.category), ['ssh']);
  assert.ok(!('alsoWhen' in runbook(npmOnly)[1]), 'internal trigger is not part of the runbook output');
});

test('markdown runbook prints the caches step in order', (t) => {
  const f = fixture({ 'app/.npmrc': 'registry=https://acme.jfrog.io/artifactory/api/npm/npm/\n' });
  t.after(f.cleanup);
  const md = formatMarkdown(only(f.root));
  assert.match(md, /Caches, mirrors and artifact stores/);
  assert.match(md, /Artifactory at acme\.jfrog\.io/);
});
