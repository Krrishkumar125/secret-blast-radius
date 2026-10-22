import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

// Token-shaped fixtures are assembled at runtime so no real-looking secret is committed.
const rep = (ch, n) => ch.repeat(n);
export const FAKE = {
  npm: 'npm' + '_' + rep('A', 36),
  ghp: 'gh' + 'p_' + rep('B', 36),
  akia: 'AK' + 'IA' + rep('C', 16),
  asia: 'AS' + 'IA' + rep('D', 16),
  openai: 's' + 'k-proj-' + rep('E', 40),
  stripe: 's' + 'k_live_' + rep('F', 24),
  pg: 'postgres://app:' + 'hunter2hunter2' + '@db.example.com:5432/app',
};

export function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), 'sbr-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = join(root, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
