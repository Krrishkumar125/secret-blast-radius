import { runbook } from './index.js';
import { INCIDENTS } from './incidents.js';
import { PRE_ROTATION } from './format.js';
import { findTokensInText } from './frontend.js';
import { fingerprint, tokenKind } from './util.js';

/**
 * Self-contained HTML report. Offline: no scripts, no external CSS/fonts/images, and a CSP that forbids them.
 * Every dynamic string goes through redact() then esc(), so a secret that slipped into a title or path is
 * never written in full and nothing from the scan can inject markup.
 */

const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, (c) => ENTITIES[c]);
}

/** Replace anything token-shaped with "[redacted sha256:xxxxxxxx]". Keeps the first 4 chars of well-known prefixes. */
export function redact(s) {
  let text = String(s ?? '');
  // Longest first so overlapping matches don't leave pieces behind.
  const hits = findTokensInText(text).sort((a, b) => b.value.length - a.value.length);
  for (const { value } of hits) text = text.split(value).join(`[redacted ${fingerprint(value)}]`);
  // Credentials in URLs (any scheme): keep user and host, hide the password.
  text = text.replace(/([a-z][a-z0-9+.-]*:\/\/[^:\s/@"'<>]+:)([^@\s"'<>]+)@/gi, (m, pre, pw) => (/^\[redacted/.test(pw) || pw === '***' ? m : `${pre}***@`));
  // A whole string that is itself a recognised token (e.g. passed straight through).
  if (tokenKind(text.trim())) text = `[redacted ${fingerprint(text.trim())}]`;
  return text;
}

const t = (s) => escapeHtml(redact(s));
// Inline code spans in the rotation steps (`npm token list`) render as <code>; text is escaped first.
const md = (s) => t(s).split('&#96;').map((part, i, all) => (i % 2 && i < all.length - 1 ? `<code>${part}</code>` : (i % 2 ? '&#96;' + part : part))).join('');
const safeUrl = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u)) ? escapeHtml(u) : null);

const CSS = `
:root{color-scheme:light dark;--fg:#1b1f24;--bg:#fff;--mut:#57606a;--bd:#d0d7de;--card:#f6f8fa;--crit:#cf222e;--high:#d1242f;--med:#9a6700;--low:#57606a;--ok:#1a7f37}
.ok{color:var(--ok)}
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--bg:#0d1117;--mut:#8d96a0;--bd:#30363d;--card:#161b22;--crit:#ff7b72;--high:#ffa198;--med:#d29922;--low:#8d96a0;--ok:#3fb950}}
*{box-sizing:border-box}body{font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);margin:0;padding:24px;max-width:980px;margin:auto}
h1{font-size:1.6em;margin:.2em 0}h2{font-size:1.25em;margin:1.6em 0 .5em;border-bottom:1px solid var(--bd);padding-bottom:.3em}h3{font-size:1.05em;margin:0 0 .4em}
.mut{color:var(--mut)}code{font:.9em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--card);border:1px solid var(--bd);border-radius:4px;padding:0 .3em;word-break:break-all}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}.counts span{border:1px solid var(--bd);border-radius:6px;padding:4px 10px;font-weight:600}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}
ol.plan{list-style:none;padding:0;counter-reset:none}.step{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;margin:12px 0}
.step ol{margin:.3em 0 .6em 1.2em;padding:0}.items{margin:.3em 0 .6em;padding-left:1.2em}.tag{font-size:.8em;font-weight:700;text-transform:uppercase;margin-right:.4em}
table{border-collapse:collapse;width:100%;font-size:.92em}th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--card)}
a{color:inherit}footer{margin-top:2em;font-size:.85em}
@media print{body{padding:0}.step{break-inside:avoid}}
`;

export function formatHtml(result, { version = '' } = {}) {
  const rb = runbook(result);
  const c = result.counts ?? {};
  const out = [];
  out.push('<!doctype html>', '<html lang="en">', '<head>', '<meta charset="utf-8">',
    // No scripts, no network: inline styles only.
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`,
    '<meta name="referrer" content="no-referrer">', '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>secret-blast-radius report${result.incident ? ` – ${t(result.incident)}` : ''}</title>`, `<style>${CSS}</style>`, '</head>', '<body>');
  out.push('<header>', `<h1>${result.harden ? 'Hardening report' : 'Rotation plan'}</h1>`,
    `<p class="mut">secret-blast-radius${version ? ` ${t(version)}` : ''} · generated ${t(result.scannedAt)}${result.projects?.length ? ` · projects: ${result.projects.map((p) => `<code>${t(p)}</code>`).join(', ')}` : ''}</p>`,
    `<p>Secret values are never included. Each item shows where it was found and a <code>sha256:xxxxxxxx</code> fingerprint so you can tell them apart.</p>`,
    `<div class="counts">${['critical', 'high', 'medium', 'low'].map((s) => `<span class="${s}">${Number(c[s] ?? 0)} ${s}</span>`).join('')}</div>`, '</header>');

  out.push('<main>');
  if (result.incident && INCIDENTS[result.incident]) {
    const inc = INCIDENTS[result.incident];
    out.push('<section id="incident">', `<h2>Incident: ${t(inc.title)}</h2>`, `<p class="mut">${t(inc.status)}</p>`,
      `<ol>${inc.checklist.map((x) => `<li>${md(x)}</li>`).join('')}</ol>`,
      `<p class="mut">${inc.refs.map((r) => (safeUrl(r) ? `<a href="${safeUrl(r)}" rel="noreferrer">${t(r)}</a>` : t(r))).join('<br>')}</p>`, '</section>');
  }

  // 1. The rotation plan is the report.
  out.push('<section id="plan">');
  if (!rb.length) {
    out.push(`<h2>Nothing to rotate</h2><p class="ok">${result.findings?.length ? 'No credentials to rotate; see the other findings below.' : 'No reachable secrets were found in the places checked.'}</p>`);
  } else {
    out.push('<h2>Rotate in this order</h2>', '<p>Work top to bottom. Stop persistence first, then the credentials a worm uses to spread (npm, GitHub), then everything else.</p>', '<ol class="plan">');
    if (rb.some((r) => r.category === 'github') && !rb.some((r) => r.category === 'persistence')) {
      out.push('<li class="step"><h3>0. Before revoking any GitHub token</h3>', `<ol>${PRE_ROTATION.map((s) => `<li>${md(s)}</li>`).join('')}</ol></li>`);
    }
    rb.forEach((step, i) => {
      out.push(`<li class="step"><h3>${i + 1}. ${t(step.label)}</h3>`);
      out.push(`<ul class="items">${step.items.map((it) => `<li><span class="tag ${escapeHtml(it.severity)}">${escapeHtml(it.severity)}</span><strong>${t(it.title)}</strong> — <code>${t(it.location)}</code>${it.fingerprint ? ` <span class="mut">${t(it.fingerprint)}</span>` : ''}</li>`).join('')}</ul>`);
      out.push(`<ol>${step.steps.map((s) => `<li>${md(s)}</li>`).join('')}</ol>`);
      if (step.verify?.length) out.push(`<p><strong>Verify the old credential is dead:</strong></p><ul>${step.verify.map((v) => `<li>${md(v)}</li>`).join('')}</ul>`);
      if (step.redeploy) out.push('<p><strong>Redeploy</strong> after updating: running processes keep the old value until restart.</p>');
      out.push(`<p class="mut">Docs: ${step.docs.map(([title, u]) => (safeUrl(u) ? `<a href="${safeUrl(u)}" rel="noreferrer">${t(title)}</a>` : t(title))).join(' · ')}</p>`, '</li>');
    });
    out.push('</ol>');
  }
  out.push('</section>');

  // 2. Every finding, for reference.
  if (result.findings?.length) {
    out.push('<section id="findings">', '<h2>All findings</h2>', '<table><thead><tr><th>Severity</th><th>Finding</th><th>Where</th></tr></thead><tbody>');
    for (const f of result.findings) {
      out.push(`<tr><td class="${escapeHtml(f.severity)}">${escapeHtml(String(f.severity).toUpperCase())}</td><td><strong>${t(f.title)}</strong><br>${t(f.detail)}${f.fix ? `<br><em>fix:</em> ${md(f.fix)}` : ''}</td><td><code>${t(f.location)}</code>${f.fingerprint ? `<br><span class="mut">${t(f.fingerprint)}</span>` : ''}${f.ageDays != null ? `<br><span class="mut">${Number(f.ageDays)}d old</span>` : ''}</td></tr>`);
    }
    out.push('</tbody></table>', '</section>');
  }
  out.push('</main>', '<footer class="mut">Generated offline by <a href="https://github.com/Krrishkumar125/secret-blast-radius" rel="noreferrer">secret-blast-radius</a>. This file loads nothing from the network.</footer>', '</body>', '</html>');
  return out.join('\n') + '\n';
}
