import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { fixture, FAKE } from './helpers.js';
import { INCIDENTS } from '../src/incidents.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'bin', 'cli.js');
const cli = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } });
const DASH = /[\u2013\u2014]/;

test('no em or en dashes in incident titles and details', () => {
  for (const [id, inc] of Object.entries(INCIDENTS)) {
    assert.ok(!DASH.test(JSON.stringify(inc)), `incident ${id} has an em or en dash`);
  }
});

test('no em or en dashes in source files or the README', () => {
  const files = [join(ROOT, 'README.md'), join(ROOT, 'bin', 'cli.js')];
  for (const f of readdirSync(join(ROOT, 'src'))) files.push(join(ROOT, 'src', f));
  for (const f of files) assert.ok(!DASH.test(readFileSync(f, 'utf8')), `${f} has an em or en dash`);
});

test('text, runbook, harden and HTML output have no em or en dashes', (t) => {
  const f = fixture({ 'home/.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.npm}\n`, 'proj/.env': `STRIPE_SECRET_KEY=${FAKE.stripe}\n` });
  t.after(f.cleanup);
  const base = ['--home', join(f.root, 'home'), '--no-env', '--no-exec', join(f.root, 'proj')];
  const html = join(f.root, 'report.html');

  const txt = cli(base);
  assert.equal(txt.status, 0, txt.stderr);
  assert.ok(!DASH.test(txt.stdout), 'text report');

  assert.ok(!DASH.test(cli(['--harden', ...base]).stdout), '--harden report');

  const rb = cli(['--runbook', ...base]);
  assert.equal(rb.status, 0, rb.stderr);
  assert.match(rb.stdout, /- \[ \] \*\*/);
  assert.ok(!DASH.test(rb.stdout), 'runbook markdown');

  const h = cli(['--html', html, ...base]);
  assert.equal(h.status, 0, h.stderr);
  assert.ok(!DASH.test(readFileSync(html, 'utf8')), 'html report');

  for (const id of Object.keys(INCIDENTS)) {
    const out = join(f.root, `${id}.html`);
    const r = cli(['--incident', id, '--html', out, ...base]);
    assert.equal(r.status, 0, `${id}: ${r.stderr}`);
    assert.ok(!DASH.test(r.stdout), `incident ${id} text`);
    assert.ok(!DASH.test(readFileSync(out, 'utf8')), `incident ${id} html`);
  }
});
