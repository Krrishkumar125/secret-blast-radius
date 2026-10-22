import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { fixture, FAKE } from './helpers.js';
import { scan, scanAsync, formatText, formatMarkdown, toSarif, loadIocs, INCIDENTS } from '../src/index.js';
import { parsePyLock, scanPython, scanImages, parseImage, imageRefs } from '../src/v4.js';

const ctxFor = (root, extra = {}) => ({ home: root, projects: [join(root, 'proj')], env: {}, depth: 4, iocs: loadIocs(), exec: null, ...extra });
const all = (r) => JSON.stringify(r) + formatText(r) + formatMarkdown(r) + JSON.stringify(toSarif(r, 't'));

test('python lockfiles: requirements, poetry.lock, uv.lock, Pipfile.lock, pylock.toml', () => {
  assert.deepEqual(parsePyLock('requirements.txt', 'LiteLLM[proxy]==1.107.0 ; python_version>"3.9" \\\n  --hash=sha256:abc\nrequests>=2\n# c\n-r other.txt\nfoo_bar==1.0  # pinned\n').map((x) => [x.name, x.version, x.hashed]), [['litellm', '1.107.0', true], ['requests', null, false], ['foo-bar', '1.0', false]]);
  assert.deepEqual(parsePyLock('poetry.lock', '[[package]]\nname = "litellm"\nversion = "1.107.0"\n\n[[package]]\nname = "x"\nversion = "2"\n').map((x) => x.name + '@' + x.version), ['litellm@1.107.0', 'x@2']);
  assert.deepEqual(parsePyLock('uv.lock', 'version = 1\n[[package]]\nname = "litellm"\nversion = "1.106.2"\nsource = { registry = "https://pypi.org/simple" }\nwheels = [{ url = "x", hash = "sha256:aa" }]\n').map((x) => [x.name, x.version, x.hashed]), [['litellm', '1.106.2', true]]);
  assert.deepEqual(parsePyLock('Pipfile.lock', JSON.stringify({ default: { LiteLLM: { version: '==1.82.8', hashes: ['sha256:x'] } }, develop: { pytest: { version: '*' } } })).map((x) => x.name + '@' + x.version), ['litellm@1.82.8']);
  assert.equal(parsePyLock('pylock.toml', '[[packages]]\nname = "litellm"\nversion = "1.107.0"\n')[0].version, '1.107.0');
  assert.deepEqual(parsePyLock('Pipfile.lock', '{bad'), []);
});

test('python: bad litellm in lockfiles and venvs, cook.pth hook; safe versions ignored', (t) => {
  const { root, cleanup } = fixture({
    'proj/requirements.txt': 'litellm==1.107.0\n',
    'proj/svc/poetry.lock': '[[package]]\nname = "litellm"\nversion = "1.106.2"\n',
    'proj/svc2/uv.lock': '[[package]]\nname = "litellm"\nversion = "1.82.7"\n',
    'proj/.venv/pyvenv.cfg': 'home = /usr/bin\n',
    'proj/.venv/lib/python3.12/site-packages/litellm-1.107.0.dist-info/METADATA': 'Name: litellm\n',
    'proj/.venv/lib/python3.12/site-packages/cook.pth': 'import cook\n',
    'proj/.venv/lib/python3.12/site-packages/requests-2.32.0.dist-info/METADATA': '',
  });
  t.after(cleanup);
  const f = scanPython(ctxFor(root));
  const titles = f.map((x) => x.title);
  assert.equal(f.length, 4, titles.join('\n'));
  assert.ok(titles.includes('Known-malicious package litellm==1.107.0 (litellm release compromise (Oct 21, 2026))'));
  assert.ok(titles.some((x) => x.includes('litellm==1.82.7')));
  assert.ok(titles.includes('litellm 1.107.0 startup hook cook.pth is installed'));
  assert.ok(!titles.some((x) => x.includes('1.106.2')));
});

test('images: compromised digests/tags, floating tags, multi-stage aliases, registries', (t) => {
  const D = 'sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e';
  const { root, cleanup } = fixture({
    'proj/Dockerfile': `FROM ghcr.io/berriai/litellm:v1.107.0 AS base\nFROM base\nFROM python:3.12-slim\n`,
    'proj/docker-compose.yml': `services:\n  proxy:\n    image: ghcr.io/berriai/litellm:main-stable\n  db:\n    image: "litellm/litellm@${D}"\n  ok:\n    image: ghcr.io/berriai/litellm:v1.106.2\n  pinned:\n    image: ghcr.io/berriai/litellm:main-stable@sha256:${'0'.repeat(64)}\n`,
  });
  t.after(cleanup);
  const f = scanImages(ctxFor(root));
  assert.deepEqual(f.map((x) => [x.id, x.location.split(':').pop()]).sort(), [['supply.floating-image-exposed', '3'], ['supply.malicious-image', '1'], ['supply.malicious-image', '5']].sort());
  assert.deepEqual(imageRefs('Dockerfile', 'FROM node:20 AS build\nFROM build AS test\nFROM --platform=$BUILDPLATFORM alpine\n').map((r) => r.ref), ['node:20', 'alpine']);
  assert.equal(parseImage('python').repo, 'docker.io/library/python');
  assert.equal(parseImage('litellm/litellm:latest').repo, 'docker.io/litellm/litellm');
  assert.equal(parseImage('localhost:5000/x:1').repo, 'localhost:5000/x');
});

test('litellm incident mode and host markers', (t) => {
  assert.ok(INCIDENTS.litellm && INCIDENTS.zeabur);
  const { root, cleanup } = fixture({ 'proj/requirements.txt': 'litellm==1.107.0\n' });
  t.after(cleanup);
  const r = scan({ home: root, projects: [join(root, 'proj')], env: {}, exec: false, incident: 'litellm' });
  assert.ok(r.findings.some((f) => f.incident === 'litellm'));
  assert.match(formatText(r), /Do NOT start Python or pip/);
});

const git = (cwd, ...a) => execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], { cwd, stdio: 'pipe' });
const exec = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return null; } };

test('--harden: every check fires with a fix, and goes quiet when configured; never leaks', (t) => {
  const secret = 'Zx9' + 'q'.repeat(30);
  const { root, cleanup } = fixture({
    'proj/Dockerfile': 'FROM node:20 AS build\nFROM build\nFROM gcr.io/distroless/nodejs20@sha256:' + 'a'.repeat(64) + '\n',
    'proj/requirements.txt': 'litellm\nrequests==2.32.0\n',
    'proj/api/requirements.txt': 'requests==2.32.0\n',
    'proj/pyproject.toml': '[project]\nname="x"\n[tool.uv]\n',
    'proj/pnpm-workspace.yaml': 'dangerouslyAllowAllBuilds: true\n',
    'proj/.github/workflows/rel.yml': 'jobs:\n  p:\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          password: ${{ secrets.PYPI }}\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          aws-secret-access-key: ${{ secrets.AWS }}\n',
    'proj/.env': `STRIPE_KEY=${FAKE.stripe}\n`,
    'proj/web/.env.local': `SECRET=${secret}\n`,
    'proj/.gitignore': 'web/.env.local\n',
    '.cursor/mcp.json': JSON.stringify({ mcpServers: { x: { command: 'npx', args: ['-y', 'some-mcp'] } } }),
  });
  t.after(cleanup);
  const p = join(root, 'proj');
  git(p, 'init', '-q'); git(p, 'add', '-f', '.env'); git(p, 'commit', '-qm', 'x');
  const r = scan({ home: root, projects: [p], env: {}, exec, harden: true });
  const ids = r.findings.map((f) => f.id).sort();
  for (const id of ['hardening.image-digest', 'hardening.python-pin', 'hardening.python-hashes', 'hardening.python-cooldown', 'hardening.pnpm-builds', 'hardening.oidc', 'hardening.env-tracked', 'hardening.ignore-scripts', 'hardening.release-age', 'ai.mcp-unpinned']) assert.ok(ids.includes(id), `missing ${id}: ${ids}`);
  assert.equal(ids.filter((x) => x === 'hardening.oidc').length, 3);
  assert.ok(!ids.includes('hardening.env-ignore'), 'web/.env.local is ignored');
  assert.ok(r.findings.every((f) => f.fix), 'every harden finding has a fix');
  assert.ok(r.findings.every((f) => f.category === 'hardening' || f.id === 'ai.mcp-unpinned'), 'harden mode shows only preventive findings');
  assert.match(r.findings.find((f) => f.id === 'hardening.image-digest').detail, /node:20\./);
  const out = all(r);
  for (const v of [FAKE.stripe, secret]) assert.ok(!out.includes(v), 'leak');
  assert.match(formatText(r), /fix:/);

  const good = fixture({
    'proj/Dockerfile': 'FROM node:20@sha256:' + 'b'.repeat(64) + '\n',
    'proj/requirements.txt': 'requests==2.32.0 --hash=sha256:' + 'c'.repeat(64) + '\n',
    'proj/pyproject.toml': '[tool.uv]\nexclude-newer = "3 days"\n',
    'proj/.npmrc': 'ignore-scripts=true\nmin-release-age=3\n',
  });
  t.after(good.cleanup);
  const g = scan({ home: good.root, projects: [join(good.root, 'proj')], env: {}, exec, harden: true });
  assert.deepEqual(g.findings, []);
  assert.match(formatText(g), /All checked preventive settings are in place/);
});

test('harden is off by default; osv also covers PyPI lockfiles', async (t) => {
  const { root, cleanup } = fixture({ 'proj/Dockerfile': 'FROM node:20\n', 'proj/requirements.txt': 'evilpy==1.0\nlitellm==1.107.0\n' });
  t.after(cleanup);
  const r = scan({ home: root, projects: [join(root, 'proj')], env: {}, exec: false });
  assert.ok(!r.findings.some((f) => f.id === 'hardening.image-digest'));
  let q;
  const fetchImpl = async (u, init) => { q = JSON.parse(init.body).queries; return { ok: true, json: async () => ({ results: q.map((x) => ({ vulns: x.package.ecosystem === 'PyPI' ? [{ id: 'MAL-2026-9' }] : [] })) }) }; };
  const o = await scanAsync({ home: root, projects: [join(root, 'proj')], env: {}, exec: false, osv: true, osvOptions: { fetchImpl } });
  assert.deepEqual(q.map((x) => `${x.package.ecosystem}:${x.package.name}@${x.version}`).sort(), ['PyPI:evilpy@1.0', 'PyPI:litellm@1.107.0']);
  assert.deepEqual(o.findings.filter((f) => f.id === 'supply.osv-malicious').map((f) => f.title), ['OSV lists evilpy@1.0 as malicious (MAL-2026-9)'], 'bundled litellm hit not duplicated');
});

test('false-positive rules from real repos: fake-* values and localhost DB URLs', async () => {
  const { isSecretPair } = await import('../src/util.js');
  assert.equal(isSecretPair('OPENAI_API_KEY', 'fake-openai-key1'), false);
  assert.equal(isSecretPair('MONGODB_URI', 'mongodb://test:test@localhost:27017/db'), false);
  assert.equal(isSecretPair('DATABASE_URL', 'postgres://app:S3cr3t-pw@db.example.com/app'), true);
  assert.equal(isSecretPair('API_KEY', 'test-but-real-9f8a7b6c'), true, 'only fake/dummy/mock prefixes are skipped');
});
