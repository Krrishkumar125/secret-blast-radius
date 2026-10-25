import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatMarkdown } from '../src/index.js';

const result = (findings) => ({ scannedAt: 't', findings, counts: {} });
const gh = { id: 'github.token', category: 'github', severity: 'high', title: 'GitHub token', location: '~/.config/gh/hosts.yml' };
const per = { id: 'persistence.gh-token-monitor', category: 'persistence', severity: 'critical', title: 'Worm persistence found: gh-token-monitor', location: '~/.config/gh-token-monitor' };

test('runbook adds step 0 (check gh-token-monitor) before GitHub rotation when no persistence was found', () => {
  const md = formatMarkdown(result([gh]));
  const zero = md.indexOf('## 0. Before revoking any GitHub token');
  assert.ok(zero > 0, md);
  assert.ok(zero < md.indexOf('## 1. GitHub tokens'), md);
  assert.match(md, /gh-token-monitor wipes your home directory/);
});

test('no extra step 0 when persistence is already step 1, or when no GitHub token is involved', () => {
  assert.ok(!formatMarkdown(result([per, gh])).includes('## 0.'));
  assert.ok(!formatMarkdown(result([{ ...gh, category: 'npm', id: 'npm.token' }])).includes('## 0.'));
});
