import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan, toSarif } from '../src/index.js';
import { splitLine } from '../src/sarif.js';
import { fixture } from './helpers.js';

const only = (root) => scan({ projects: [root], home: root, only: ['caches'], exec: false, env: {} });

test('sarif: a "file:line" location becomes a repo-relative uri plus a startLine region', (t) => {
  const f = fixture({ 'app/Dockerfile': 'FROM node:22\nARG NPM_TOKEN\n' });
  t.after(f.cleanup);
  const s = toSarif(only(f.root), '0.6.0');
  const loc = s.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, 'app/Dockerfile');
  assert.deepEqual(loc.region, { startLine: 2 });
  assert.deepEqual(splitLine('C:/x/y'), { path: 'C:/x/y', line: null });
});
