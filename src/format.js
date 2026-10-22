import { runbook } from './index.js';
import { INCIDENTS } from './incidents.js';

const ICON = { critical: '✖', high: '▲', medium: '●', low: '·' };

export function formatText(result, { color = false } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const sev = { critical: (s) => c('1;31', s), high: (s) => c('31', s), medium: (s) => c('33', s), low: (s) => c('2', s) };
  const lines = [];
  const { counts } = result;
  lines.push(c('1', 'secret-blast-radius') + (result.harden ? ' --harden: settings that would have blunted this month\'s attacks' : ' — what a malicious install script could steal from this machine right now'));
  lines.push('');
  if (result.incident) {
    const inc = INCIDENTS[result.incident];
    lines.push(c('1', inc.title), c('2', inc.status), '');
    inc.checklist.forEach((x, i) => lines.push(`  ${i + 1}. ${x}`));
    lines.push('', ...inc.refs.map((r) => `  ${c('2', r)}`), '', c('1', 'What this machine/project has that matters for this incident:'), '');
  }
  if (result.osvQueried != null) lines.push(c('2', `OSV: checked ${result.osvQueried} package versions against MAL- advisories (online, opt-in).`), '');
  if (!result.findings.length) {
    lines.push(result.harden ? 'All checked preventive settings are in place.' : result.incident ? 'Nothing relevant found by these checks.' : 'No reachable secrets found in the places checked. Nice.');
    return lines.join('\n');
  }
  for (const f of result.findings) {
    lines.push(`${sev[f.severity](`${ICON[f.severity]} ${f.severity.toUpperCase().padEnd(8)}`)} ${f.title}`);
    lines.push(`  ${c('2', f.location + (f.fingerprint ? `  ${f.fingerprint}` : '') + (f.ageDays != null ? `  (${f.ageDays}d old)` : ''))}`);
    lines.push(`  ${f.detail}`);
    if (f.fix) lines.push(`  ${c('32', 'fix:')} ${f.fix}`);
    lines.push('');
  }
  lines.push(`Summary: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low.`);
  const rb = runbook(result);
  if (rb.length) lines.push(`Rotation order if this machine is ever compromised: ${rb.map((r, i) => `${i + 1}. ${r.category}`).join('  ')}`);
  lines.push('Run with --runbook for step-by-step rotation, --json for machine output. Secret values are never printed.');
  return lines.join('\n');
}

export function formatMarkdown(result) {
  const out = ['# Secret rotation runbook', '', `Generated ${result.scannedAt} by secret-blast-radius. Values are never included; fingerprints let you match items.`, ''];
  if (result.incident) {
    const inc = INCIDENTS[result.incident];
    out.push(`## Incident: ${inc.title}`, '', `_${inc.status}_`, '', ...inc.checklist.map((x) => `- [ ] ${x}`), '', ...inc.refs.map((r) => `- ${r}`), '');
  }
  const rb = runbook(result);
  if (!rb.length) return out.concat('Nothing to rotate: no reachable secrets were found.').join('\n');
  out.push('Work top to bottom. The order matters: stop persistence first, then the credentials a worm uses to spread (npm, GitHub), then everything else.', '');
  rb.forEach((step, i) => {
    out.push(`## ${i + 1}. ${step.label}`, '');
    for (const it of step.items) out.push(`- [ ] **${it.title}** — \`${it.location}\`${it.fingerprint ? ` (${it.fingerprint})` : ''}`);
    out.push('', ...step.steps.map((s) => `1. ${s}`), '');
    if (step.verify?.length) out.push('**Verify the old credential is dead:**', '', ...step.verify.map((v) => `- ${v}`), '');
    if (step.redeploy) out.push('**Redeploy** after updating: running processes keep the old value until restart.', '');
    out.push(`Docs: ${step.docs.map(([t, u]) => `[${t}](${u})`).join(' · ')}`, '');
  });
  return out.join('\n');
}
