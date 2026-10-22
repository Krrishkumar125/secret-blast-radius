import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { fixture, FAKE } from './helpers.js';

const CLI = fileURLToPath(new URL('../bin/cli.js', import.meta.url));
const cli = (args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });

test('cli: text report, json, runbook file and exit codes', (t) => {
  const f = fixture({ 'home/.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.npm}\n`, 'proj/.env': `STRIPE_SECRET_KEY=${FAKE.stripe}\n` });
  t.after(f.cleanup);
  const base = ['--home', join(f.root, 'home'), '--no-env', '--no-exec', join(f.root, 'proj')];

  const txt = cli(base);
  assert.equal(txt.status, 0, txt.stderr);
  assert.match(txt.stdout, /CRITICAL/);
  assert.ok(!txt.stdout.includes(FAKE.npm) && !txt.stdout.includes(FAKE.stripe));

  const js = cli(['--json', ...base]);
  const parsed = JSON.parse(js.stdout);
  assert.equal(parsed.counts.critical, 1);
  assert.equal(parsed.runbook[0].category, 'npm');

  assert.equal(cli(['--fail-on', 'high', ...base]).status, 1);
  assert.equal(cli(['--fail-on', 'critical', '--only', 'dotenv', ...base]).status, 0);
  assert.equal(cli(['--fail-on', 'nope', ...base]).status, 2);

  const out = join(f.root, 'runbook.md');
  const rb = cli(['--runbook-file', out, '--runbook', ...base]);
  assert.equal(rb.status, 0, rb.stderr);
  const md = readFileSync(out, 'utf8');
  assert.match(md, /## 1\. Package registry tokens/);
  assert.ok(!md.includes(FAKE.npm));
});

test('cli: env scanning sees CI-style secrets', () => {
  const r = cli(['--json', '--only', 'env'], { NPM_TOKEN: FAKE.npm });
  assert.equal(JSON.parse(r.stdout).findings[0].severity, 'critical');
  assert.ok(!r.stdout.includes(FAKE.npm));
});

test('cli: --help and --version', () => {
  assert.match(cli(['--help']).stdout, /Usage: secret-blast-radius/);
  assert.match(cli(['--version']).stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('cli: --incident, --list-incidents, --sarif-file, --no-exec, bad incident', (t) => {
  const f = fixture({ 'home/x': '', 'proj/railway.toml': '', 'proj/.env': `STRIPE_SECRET_KEY=${FAKE.stripe}\n`, 'proj/Dockerfile': 'FROM php:8.3.1-fpm\n' });
  t.after(f.cleanup);
  const base = ['--home', join(f.root, 'home'), '--no-env', '--no-exec', join(f.root, 'proj')];
  const inc = cli(['--incident', 'railway', ...base]);
  assert.equal(inc.status, 0, inc.stderr);
  assert.match(inc.stdout, /Roll every environment variable/);
  assert.ok(!inc.stdout.includes('PHP2Shell'));
  assert.ok(!inc.stdout.includes(FAKE.stripe));
  assert.match(cli(['--list-incidents']).stdout, /php2shell[\s\S]*emudhra[\s\S]*sbi/);
  assert.equal(cli(['--incident', 'nope', ...base]).status, 2);
  const out = join(f.root, 'r.sarif');
  const s = cli(['--sarif-file', out, '--fail-on', 'critical', ...base]);
  assert.equal(s.status, 1);
  const sarif = JSON.parse(readFileSync(out, 'utf8'));
  assert.ok(sarif.runs[0].results.some((r) => r.ruleId === 'php.php2shell' && r.locations[0].physicalLocation.artifactLocation.uri === 'Dockerfile'));
  assert.ok(!readFileSync(out, 'utf8').includes(FAKE.stripe));
  const stdoutSarif = JSON.parse(cli(['--sarif', ...base]).stdout);
  assert.equal(stdoutSarif.version, '2.1.0');
});

test('cli: --history/--since/--osv flags parse and validate', () => {
  const r = spawnSync(process.execPath, [CLI, '--since', 'yesterday', '--no-exec'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--since expects a date/);
  const ok = spawnSync(process.execPath, [CLI, '--history', '--since', '2026-09-01', '--only', 'history', '--json', '--no-exec'], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.deepEqual(JSON.parse(ok.stdout).findings, []);
  assert.match(spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' }).stdout, /--osv +ONLINE, opt-in/);
});
