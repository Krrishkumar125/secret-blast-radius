const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
const SCORE = { critical: '9.5', high: '7.5', medium: '5.0', low: '2.0' };

import { relative, isAbsolute } from 'node:path';

function repoRelative(result, loc) {
  const abs = loc.startsWith('~') ? result.home + loc.slice(1) : loc;
  if (!isAbsolute(abs)) return null;
  for (const p of result.projects) {
    const r = relative(p, abs);
    if (r && !r.startsWith('..') && !isAbsolute(r)) return r.replace(/\\/g, '/');
  }
  return null;
}

export function toSarif(result, version) {
  const rules = new Map();
  for (const f of result.findings) if (!rules.has(f.id)) rules.set(f.id, f);
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'secret-blast-radius', version, informationUri: 'https://github.com/Krrishkumar125/secret-blast-radius',
        rules: [...rules.values()].map((f) => ({ id: f.id, name: f.id.replace(/[^a-z0-9]+/gi, '_'), shortDescription: { text: f.id }, properties: { 'security-severity': SCORE[f.severity], tags: ['security', f.category] } })) } },
      results: result.findings.map((f) => {
        // Only repo-relative paths are meaningful to code scanning; home-dir findings are reported without a file.
        const uri = repoRelative(result, f.location);
        return {
          ruleId: f.id, level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.detail}` },
          ...(uri ? { locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId: '%SRCROOT%' } } }] } : {}),
          partialFingerprints: { primary: `${f.id}:${f.location}:${f.fingerprint || f.title}` },
        };
      }),
    }],
  };
}
