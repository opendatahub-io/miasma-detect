#!/usr/bin/env node
'use strict';

const fs = require('fs');
const {
  scanText,
  scanFile,
  scanDir,
  scanGithubEvent,
  summarize,
  SEVERITY_ORDER,
} = require('./scanner');

const USAGE = `miasma-detect — scan for Miasma supply-chain IOCs, generic supply-chain
attack heuristics, and prompt-injection payloads.

Usage:
  miasma-detect [options] <path>...        Scan files and/or directories
  miasma-detect [options] --stdin          Scan text from stdin (PR body, diff, etc.)
  miasma-detect [options] --event <file>   Scan a GitHub event payload JSON
                                           (defaults to $GITHUB_EVENT_PATH if set)

Options:
  --min-severity <low|medium|high|critical>   Failure threshold (default: medium)
  --categories <list>    Comma-separated: miasma-ioc,supply-chain,prompt-injection,package
  --json                 Machine-readable JSON output
  --quiet                Only print on detection
  -h, --help             Show help

Exit codes:
  0  clean (no findings at/above threshold)
  1  detections at/above threshold — STOP PROCESSING
  2  usage/runtime error
`;

function parseArgs(argv) {
  const args = { paths: [], stdin: false, event: null, json: false, quiet: false, options: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        process.exit(0);
        break;
      case '--stdin':
        args.stdin = true;
        break;
      case '--event':
        args.event = argv[++i] || process.env.GITHUB_EVENT_PATH;
        if (!args.event) fail('--event requires a file path (or set GITHUB_EVENT_PATH)');
        break;
      case '--json':
        args.json = true;
        break;
      case '--quiet':
        args.quiet = true;
        break;
      case '--min-severity': {
        const v = argv[++i];
        if (!(v in SEVERITY_ORDER)) fail(`invalid --min-severity: ${v}`);
        args.options.minSeverity = v;
        break;
      }
      case '--categories':
        args.options.categories = (argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
        break;
      default:
        if (a.startsWith('-')) fail(`unknown option: ${a}`);
        args.paths.push(a);
    }
  }
  return args;
}

function fail(msg) {
  process.stderr.write(`miasma-detect: ${msg}\n\n${USAGE}`);
  process.exit(2);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

const COLORS = { critical: '\x1b[1;31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m' };
const RESET = '\x1b[0m';

function printHuman(summary, quiet) {
  const tty = process.stdout.isTTY;
  for (const f of summary.findings) {
    const c = tty ? COLORS[f.severity] || '' : '';
    const r = tty ? RESET : '';
    process.stdout.write(
      `${c}[${f.severity.toUpperCase()}]${r} ${f.ruleId} (${f.category})\n` +
        `  ${f.description}\n` +
        `  source: ${f.source}\n` +
        (f.match ? `  match:  ${f.match}\n` : '') +
        (f.excerpt ? `  context: …${f.excerpt}…\n` : '')
    );
  }
  if (!summary.ok) {
    process.stdout.write(
      `\n${tty ? COLORS.critical : ''}MIASMA-DETECT: BLOCKED — ${summary.blocking} finding(s) at or above threshold. ` +
        `Do not process this content further.${tty ? RESET : ''}\n`
    );
  } else if (!quiet) {
    process.stdout.write(
      summary.total > 0
        ? `miasma-detect: clean at threshold (${summary.total} sub-threshold finding(s) above)\n`
        : 'miasma-detect: clean\n'
    );
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const findings = [];

  if (!args.stdin && !args.event && args.paths.length === 0) {
    if (process.env.GITHUB_EVENT_PATH && fs.existsSync(process.env.GITHUB_EVENT_PATH)) {
      args.event = process.env.GITHUB_EVENT_PATH;
    } else {
      fail('nothing to scan: provide paths, --stdin, or --event');
    }
  }

  if (args.stdin) {
    findings.push(...scanText(await readStdin(), 'stdin', args.options));
  }

  if (args.event) {
    let payload;
    try {
      payload = JSON.parse(fs.readFileSync(args.event, 'utf8'));
    } catch (e) {
      fail(`cannot read event payload ${args.event}: ${e.message}`);
    }
    findings.push(...scanGithubEvent(payload, args.options));
  }

  for (const p of args.paths) {
    let stat;
    try {
      stat = fs.statSync(p);
    } catch {
      fail(`no such path: ${p}`);
    }
    findings.push(...(stat.isDirectory() ? scanDir(p, args.options) : scanFile(p, args.options)));
  }

  const summary = summarize(findings, args.options);

  if (args.json) {
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  } else {
    printHuman(summary, args.quiet);
  }
  process.exit(summary.ok ? 0 : 1);
}

main().catch((e) => {
  process.stderr.write(`miasma-detect: ${e.stack || e}\n`);
  process.exit(2);
});
