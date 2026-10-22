#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { writeFileSync, readFileSync } from 'node:fs';
import { scanAsync, failsAt, formatText, formatMarkdown, runbook, toSarif, INCIDENTS } from '../src/index.js';

const HELP = `Usage: secret-blast-radius [options] [project-dir...]

Lists every credential an npm install script (or any process you run) could read
on this machine or CI runner, ranks it, and writes an ordered rotation runbook.
Read-only. Never prints secret values.

Options:
  --incident <name>    Tailored checklist + only the relevant checks. Names:
                       php2shell, glassworm, railway, tensorlake, shai-hulud, subql, ghostaction, emudhra, sbi
  --list-incidents     Show incident names and status
  --json               Machine-readable output
  --sarif [file]       SARIF 2.1.0 for GitHub code scanning (stdout, or --sarif-file <f>)
  --ioc-file <f>       Extra IOC JSON (same shape as src/iocs.json); repeatable
  --no-exec            Never run helper commands (php -v, crontab -l, ps, git)
  --history            Exposure window: walk lockfile git history for known-bad versions (runs git)
  --since <date>       Limit --history to commits since a date (e.g. 2026-09-01)
  --osv                ONLINE, opt-in: send lockfile package names+versions (nothing else) to
                       api.osv.dev and report MAL- malicious-package advisories
  --runbook [file]     Print (or write to file) a Markdown rotation runbook
  --fail-on <level>    Exit 1 if any finding is at/above level: critical|high|medium|low|none (default: none)
  --only <list>        Comma list of scanners: persistence,npm,github,cloud,kubernetes,env,ai,ssh,dotenv,
                       hardening,malicious,repo,host-persistence,php,paas,certs,install-scripts,
                       ecosystems,extensions,npm-cache,history
  --skip <list>        Comma list of scanners to skip
  --no-env             Do not inspect environment variables
  --depth <n>          How deep to look for .env files in project dirs (default 4)
  --home <dir>         Home directory to inspect (default: your home)
  --no-color           Disable colours
  -v, --version        Print version
  -h, --help           Show this help
`;

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean' }, sarif: { type: 'boolean' }, 'sarif-file': { type: 'string' },
      incident: { type: 'string' }, 'list-incidents': { type: 'boolean' }, 'ioc-file': { type: 'string', multiple: true }, 'no-exec': { type: 'boolean' }, history: { type: 'boolean' }, since: { type: 'string' }, osv: { type: 'boolean' }, runbook: { type: 'boolean' }, 'runbook-file': { type: 'string' },
      'fail-on': { type: 'string', default: 'none' }, only: { type: 'string' }, skip: { type: 'string' },
      'no-env': { type: 'boolean' }, depth: { type: 'string' }, home: { type: 'string' },
      'no-color': { type: 'boolean' }, version: { type: 'boolean', short: 'v' }, help: { type: 'boolean', short: 'h' },
    },
  });
} catch (e) {
  console.error(e.message + '\n\n' + HELP);
  process.exit(2);
}
const { values: o, positionals } = args;
if (o.help) { process.stdout.write(HELP); process.exit(0); }
if (o.version) {
  console.log(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
  process.exit(0);
}
// `--runbook out.md`: parseArgs treats the file as positional; detect a .md positional right after.
let runbookFile = o['runbook-file'];
let projects = positionals;
if (o.runbook && !runbookFile && positionals.length && /\.md$/i.test(positionals[0])) { runbookFile = positionals[0]; projects = positionals.slice(1); }

if (o['list-incidents']) {
  for (const [k, v] of Object.entries(INCIDENTS)) console.log(`${k.padEnd(12)} ${v.title}\n${' '.repeat(13)}${v.status}`);
  process.exit(0);
}
const list = (s) => (s ? s.split(',').map((x) => x.trim()).filter(Boolean) : undefined);
const skip = list(o.skip) ?? [];
if (o['no-env']) skip.push('env');

let result;
try {
  if (o.since && !/^\d{4}-\d{2}-\d{2}/.test(o.since)) throw new Error('--since expects a date like 2026-09-01');
  result = await scanAsync({ osv: o.osv, history: o.history || o.since || list(o.only)?.includes('history') ? { since: o.since } : null, projects, home: o.home, only: list(o.only), skip, depth: o.depth ? Number(o.depth) : undefined, incident: o.incident, iocFiles: o['ioc-file'] ?? [], exec: o['no-exec'] ? false : undefined });
  failsAt(result, o['fail-on']);
} catch (e) {
  console.error(`secret-blast-radius: ${e.message}`);
  process.exit(2);
}

const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
if (o.sarif || o['sarif-file']) {
  const sarif = JSON.stringify(toSarif(result, version), null, 2) + '\n';
  if (o['sarif-file']) { writeFileSync(o['sarif-file'], sarif); if (!o.json) console.error(`SARIF written to ${o['sarif-file']}`); } else process.stdout.write(sarif);
}
if (o.sarif && !o['sarif-file']) {
  // stdout already used for SARIF
} else if (o.json) {
  process.stdout.write(JSON.stringify({ ...result, runbook: runbook(result).map(({ items, ...r }) => ({ ...r, findings: items.map((i) => i.id) })) }, null, 2) + '\n');
} else if (o.runbook) {
  const md = formatMarkdown(result);
  if (runbookFile) { writeFileSync(runbookFile, md); console.log(`Runbook written to ${runbookFile}`); } else process.stdout.write(md + '\n');
} else {
  const color = !o['no-color'] && process.stdout.isTTY && !process.env.NO_COLOR;
  console.log(formatText(result, { color }));
}
process.exit(failsAt(result, o['fail-on']) ? 1 : 0);
