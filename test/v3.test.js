import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fixture, FAKE } from './helpers.js';
import { scan, scanAsync, formatText, formatMarkdown, toSarif, runbook, ROTATION, loadIocs } from '../src/index.js';
import { scanEcosystems, scanExtensions, scanNpmCache, scanHistory, collectPackages } from '../src/v3.js';
import { unpinnedNpx, tokenHint } from '../src/scanners.js';

const ctxFor = (root, extra = {}) => ({ home: root, projects: [join(root, 'proj')], env: {}, depth: 4, iocs: loadIocs(), exec: null, ...extra });
const noLeak = (result, values) => {
  const all = JSON.stringify(result) + formatText(result) + formatMarkdown(result) + JSON.stringify(toSarif(result, 't'));
  for (const v of values) assert.ok(!all.includes(v), `leaked ${v.slice(0, 6)}…`);
};
const gemKey = 'rubygems_' + 'a1'.repeat(24);
const cargoTok = 'cio' + 'Z9'.repeat(16);

test('ecosystems: RubyGems, Cargo, Composer, Terraform, Pulumi, tfstate — and never leaks', (t) => {
  const { root, cleanup } = fixture({
    '.gem/credentials': `---\n:rubygems_api_key: ${gemKey}\n`,
    '.cargo/credentials.toml': `[registry]\ntoken = "${cargoTok}"\n`,
    '.config/composer/auth.json': JSON.stringify({ 'github-oauth': { 'github.com': FAKE.ghp }, 'http-basic': { 'repo.example.org': { username: 'u', password: 'Pa55-word-x1' } } }),
    '.terraform.d/credentials.tfrc.json': JSON.stringify({ credentials: { 'app.terraform.io': { token: 'tfx.atlasv1.' + 'Q'.repeat(40) } } }),
    '.pulumi/credentials.json': JSON.stringify({ current: 'https://api.pulumi.com', accessTokens: { 'https://api.pulumi.com': 'pul-' + 'b'.repeat(40) } }),
    'proj/auth.json': JSON.stringify({ bearer: { 'pkgs.example.com': '${COMPOSER_TOKEN}' } }),
    'proj/infra/terraform.tfstate': JSON.stringify({ version: 4, resources: [{ type: 'aws_db_instance', instances: [{ attributes: { password: 'x' } }] }] }),
    'proj/empty.tfstate': JSON.stringify({ version: 4, resources: [] }),
  });
  t.after(cleanup);
  const f = scanEcosystems(ctxFor(root));
  const titles = f.map((x) => x.title).sort();
  assert.ok(titles.includes('Plaintext RubyGems API key'));
  assert.ok(titles.includes('Plaintext crates.io / Cargo registry token'));
  assert.ok(titles.includes('Composer github-oauth credential for github.com'));
  assert.ok(titles.includes('Composer http-basic credential for repo.example.org'));
  assert.ok(titles.includes('Terraform token for app.terraform.io'));
  assert.ok(titles.includes('Pulumi access token for https://api.pulumi.com'));
  assert.equal(f.filter((x) => x.id === 'cloud.tfstate').length, 1, 'empty state is ignored');
  assert.ok(!titles.some((x) => x.includes('pkgs.example.com')), '${VAR} reference ignored');
  assert.equal(f.find((x) => x.title.startsWith('Composer github')).category, 'github');
  const r = scan({ home: root, projects: [join(root, 'proj')], env: {}, exec: false, only: ['ecosystems'] });
  noLeak(r, [gemKey, cargoTok, FAKE.ghp, 'Pa55-word-x1', 'Q'.repeat(40), 'b'.repeat(40)]);
});

test('extensions: exact IDs, version-scoped IOCs, extension packs, sleeper severity', (t) => {
  const ext = (dir, publisher, name, version, extra = {}) => [`${dir}/${publisher}.${name}-${version}/package.json`, JSON.stringify({ publisher, name, version, ...extra })];
  const { root, cleanup } = fixture(Object.fromEntries([
    ext('.vscode/extensions', 'aadarkcode', 'one-dark-material', '1.0.0'),
    ext('.cursor/extensions', 'oorzc', 'ssh-tools', '0.5.1'),
    ext('.cursor/extensions', 'oorzc', 'mind-map', '1.0.60'), // not the bad version
    ext('.windsurf/extensions', 'stadiumgripier', 'vscode-onedark-theme', '0.0.1'),
    ext('.vscode/extensions', 'nice', 'pack', '1.0.0', { extensionPack: ['AadarkCode.One-Dark-Material'] }),
    ext('.vscode/extensions', 'esbenp', 'prettier-vscode', '11.0.0'),
    ['.vscode/extensions/broken/package.json', '{not json'],
    ['proj/.keep', ''],
  ]));
  t.after(cleanup);
  const f = scanExtensions(ctxFor(root));
  const t2 = f.map((x) => x.title);
  assert.equal(f.length, 4, t2.join('\n'));
  assert.ok(t2.some((x) => /Known-malicious VS Code extension aadarkcode\.one-dark-material@1\.0\.0$/.test(x)));
  assert.ok(t2.some((x) => /Cursor extension oorzc\.ssh-tools@0\.5\.1/.test(x)));
  assert.ok(!t2.some((x) => x.includes('mind-map')));
  assert.equal(f.find((x) => x.title.includes('onedark')).severity, 'high');
  assert.ok(t2.some((x) => x.includes('pulled in by nice.pack')));
});

test('extensions: --ioc-file can add extension IOCs', (t) => {
  const { root, cleanup } = fixture({ '.vscode/extensions/acme.thing-2.0.0/package.json': JSON.stringify({ publisher: 'acme', name: 'thing', version: '2.0.0' }), 'iocs.json': JSON.stringify({ extensions: [{ id: 'acme.thing', versions: ['2.0.0'], status: 'malicious', ref: 'https://example.org' }] }) });
  t.after(cleanup);
  const f = scanExtensions(ctxFor(root, { iocs: loadIocs([join(root, 'iocs.json')]) }));
  assert.equal(f.length, 1);
});

test('npm cache: finds IOC tarball URLs in the cacache index', (t) => {
  const line = (u) => `deadbeef\t${JSON.stringify({ key: `make-fetch-happen:request-cache:${u}`, integrity: 'sha512-x', time: 1 })}`;
  const { root, cleanup } = fixture({
    '.npm/_cacache/index-v5/aa/bb/1': line('https://registry.npmjs.org/tensorlake/-/tensorlake-0.5.144.tgz'),
    '.npm/_cacache/index-v5/cc/dd/2': line('https://registry.npmjs.org/@subql/common/-/common-5.8.2.tgz'),
    '.npm/_cacache/index-v5/ee/ff/3': line('https://registry.npmjs.org/@subql/common/-/common-5.8.3.tgz'),
    'proj/.keep': '',
  });
  t.after(cleanup);
  const f = scanNpmCache(ctxFor(root));
  assert.deepEqual(f.map((x) => x.title).sort(), ['npm cache holds @subql/common@5.8.3 (subql)', 'npm cache holds tensorlake@0.5.144 (mini-shai-hulud)']);
});

const git = (cwd, ...a) => execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], { cwd, stdio: 'pipe' });
const exec = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return null; } };
const lock = (v) => JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'p' }, 'node_modules/tensorlake': { version: v } } });

test('history: reports the window a bad version sat in the lockfile', (t) => {
  const { root, cleanup } = fixture({ 'proj/package-lock.json': lock('0.5.143') });
  t.after(cleanup);
  const p = join(root, 'proj');
  const commit = (v, date) => { writeFileSync(join(p, 'package-lock.json'), lock(v)); git(p, 'add', '.'); execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', 'commit', '-qm', v, '--allow-empty'], { cwd: p, env: { ...process.env, GIT_COMMITTER_DATE: date, GIT_AUTHOR_DATE: date } }); };
  git(p, 'init', '-q');
  commit('0.5.143', '2026-10-01T10:00:00Z');
  commit('0.5.144', '2026-10-08T10:00:00Z');
  commit('0.5.145', '2026-10-10T10:00:00Z');
  const f = scanHistory(ctxFor(root, { exec, history: {} }));
  assert.equal(f.length, 1, JSON.stringify(f));
  assert.equal(f[0].title, 'tensorlake@0.5.144 was in package-lock.json 2026-10-08 → 2026-10-10');
  assert.equal(f[0].severity, 'high');
  commit('0.5.144', '2026-10-12T10:00:00Z');
  const g = scanHistory(ctxFor(root, { exec, history: {} }));
  assert.equal(g.length, 2);
  assert.ok(g.some((x) => x.severity === 'critical' && x.title.endsWith('now (still present)')));
  assert.equal(scanHistory(ctxFor(root, { exec, history: { since: '2026-10-11' } })).length, 1, '--since narrows the window');
  assert.equal(scanHistory(ctxFor(root, { exec: null, history: {} })).length, 0, '--no-exec disables it');
  assert.equal(scanHistory(ctxFor(root, { exec })).length, 0, 'off unless --history');
});

test('osv: opt-in, sends only names+versions, reports MAL- only, dedupes bundled hits', async (t) => {
  const { root, cleanup } = fixture({ 'proj/package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/left-pad': { version: '1.3.0' }, 'node_modules/evil-pkg': { version: '9.9.9' }, 'node_modules/tensorlake': { version: '0.5.144' } } }), 'proj/.env': `NPM_TOKEN=${FAKE.npm}\n` });
  t.after(cleanup);
  let body = null;
  const fetchImpl = async (url, init) => {
    body = init.body;
    const q = JSON.parse(init.body).queries;
    return { ok: true, json: async () => ({ results: q.map((x) => ({ vulns: x.package.name === 'left-pad' ? [{ id: 'GHSA-xxxx' }] : x.package.name === 'evil-pkg' ? [{ id: 'MAL-2026-1' }] : x.package.name === 'tensorlake' ? [{ id: 'MAL-2026-17650' }] : [] })) }) };
  };
  const opts = { home: root, projects: [join(root, 'proj')], env: {}, exec: false };
  const off = await scanAsync({ ...opts, osvOptions: { fetchImpl } });
  assert.equal(body, null, 'no network without --osv');
  assert.equal(off.osvQueried, undefined);
  const r = await scanAsync({ ...opts, osv: true, osvOptions: { fetchImpl } });
  assert.equal(r.osvQueried, 3);
  const osv = r.findings.filter((f) => f.id === 'supply.osv-malicious');
  assert.deepEqual(osv.map((f) => f.title), ['OSV lists evil-pkg@9.9.9 as malicious (MAL-2026-1)'], 'GHSA ignored, bundled tensorlake hit not duplicated');
  assert.ok(!body.includes(FAKE.npm) && !body.includes('.env'), 'only package coordinates leave the machine');
  assert.deepEqual(Object.keys(JSON.parse(body).queries[0]).sort(), ['package', 'version']);
  await assert.rejects(scanAsync({ ...opts, osv: true, osvOptions: { fetchImpl: async () => ({ ok: false, status: 503 }) } }), /HTTP 503/);
  assert.equal(collectPackages({ projects: [join(root, 'proj')], depth: 4, home: root }).length, 3);
});

test('rotation v2: every category has steps, verify and docs; provenance is never called safe', () => {
  for (const [k, r] of Object.entries(ROTATION)) {
    assert.ok(r.steps.length && r.verify.length && r.docs.length, k);
    for (const [, u] of r.docs) assert.match(u, /^https:\/\//);
  }
  const text = JSON.stringify(ROTATION);
  assert.ok(!/provenance (means|=|is) safe|provenance guarantees/i.test(text));
  assert.match(ROTATION.npm.steps.join(' '), /npm token delete/);
  const md = formatMarkdown({ scannedAt: 'x', findings: [{ category: 'paas', title: 't', location: 'l', severity: 'high' }] });
  assert.match(md, /Verify the old credential is dead/);
  assert.match(md, /\*\*Redeploy\*\*/);
  assert.match(md, /Docs: \[Railway/);
});

test('extras: token hints use prefixes only; unpinned npx MCP servers; PWD is not a password', (t) => {
  assert.match(tokenHint(FAKE.ghp), /classic PAT/);
  assert.ok(!tokenHint(FAKE.ghp).includes(FAKE.ghp));
  assert.equal(tokenHint('abc'), '');
  assert.equal(unpinnedNpx({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] }), '@modelcontextprotocol/server-github');
  assert.equal(unpinnedNpx({ command: 'npx', args: ['-y', 'pkg@1.2.3'] }), null);
  assert.equal(unpinnedNpx({ command: 'C:\\\\nodejs\\\\npx.cmd', args: ['-y', 'pkg'] }), 'pkg');
  assert.equal(unpinnedNpx({ command: 'node', args: ['server.js'] }), null);
  assert.equal(unpinnedNpx({ command: 'npx', args: ['./local'] }), null);
  const { root, cleanup } = fixture({ '.cursor/mcp.json': JSON.stringify({ mcpServers: { gh: { command: 'npx', args: ['-y', 'some-mcp'] } } }), 'proj/.keep': '' });
  t.after(cleanup);
  const r = scan({ home: root, projects: [join(root, 'proj')], env: { PWD: '/home/user/some-project', OLDPWD: '/tmp/x' }, exec: false, only: ['ai', 'env'] });
  assert.deepEqual(r.findings.map((f) => f.id), ['ai.mcp-unpinned']);
});

test('cooldown advice is tailored to the package manager in use and recognises yarn/bun settings', (t) => {
  const { root, cleanup } = fixture({ 'proj/yarn.lock': '', 'b/bun.lock': '{}', 'b/bunfig.toml': '[install]\nminimumReleaseAge = 259200\n' });
  t.after(cleanup);
  const yarn = scan({ home: root, projects: [join(root, 'proj')], env: {}, exec: false, only: ['hardening'] }).findings.find((f) => f.id === 'hardening.release-age');
  assert.match(yarn.fix, /npmMinimalAgeGate/);
  assert.ok(!/min-release-age/.test(yarn.fix));
  const bun = scan({ home: root, projects: [join(root, 'b')], env: {}, exec: false, only: ['hardening'] }).findings.find((f) => f.id === 'hardening.release-age');
  assert.equal(bun, undefined);
});
