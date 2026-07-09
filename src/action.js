'use strict';

/**
 * GitHub Action entry point (runs: node20, zero dependencies).
 * Scans the triggering event payload and, optionally, files changed
 * in the PR/push. Fails the job on detection.
 */

const fs = require('fs');
const { execFileSync } = require('child_process');
const { scanGithubEvent, scanFile, summarize, loadPacks, compileExcludes, isExcluded } = require('./scanner');

function input(name, fallback) {
  const v = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
  return v === undefined || v === '' ? fallback : v;
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const delim = `ghadelim_${Date.now()}`;
  fs.appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`);
}

function annotate(f) {
  const level = f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning';
  const msg = `[${f.ruleId}] ${f.description} (source: ${f.source})`;
  process.stdout.write(`::${level}::${msg.replace(/\n/g, ' ')}\n`);
}

function changedFileStats() {
  // Returns [{file, lines}] where lines = added + deleted ('-' for binary → 0).
  const base =
    process.env.GITHUB_BASE_REF ||
    (process.env.GITHUB_EVENT_NAME === 'push' ? 'HEAD~1' : null);
  if (!base) return [];
  try {
    if (process.env.GITHUB_BASE_REF) {
      execFileSync('git', ['fetch', '--depth=1', 'origin', base], { stdio: 'ignore' });
    }
    const ref = process.env.GITHUB_BASE_REF ? `origin/${base}...HEAD` : `${base}..HEAD`;
    return execFileSync('git', ['diff', '--numstat', '--diff-filter=ACMR', ref], {
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const [a, d, ...rest] = l.split('\t');
        return { file: rest.join('\t'), lines: (parseInt(a, 10) || 0) + (parseInt(d, 10) || 0) };
      });
  } catch (e) {
    process.stdout.write(`::notice::miasma-detect: could not compute changed files (${e.message})\n`);
    return [];
  }
}

/** Flag diffs so large the platform UI collapses them (hidden from human review). */
function largeDiffFinding(f, threshold) {
  return {
    ruleId: 'SC-COLLAPSED-DIFF',
    severity: 'high',
    category: 'supply-chain',
    description:
      `Diff of ${f.file} changes ${f.lines} lines — large diffs are collapsed by the ` +
      `platform UI ("not rendered by default"), a known technique for hiding payloads ` +
      `from human review. A human must expand and review it (threshold: ${threshold}).`,
    source: 'changed-files',
    match: `${f.file} (${f.lines} lines)`,
  };
}

function main() {
  const options = { minSeverity: input('min-severity', 'medium') };
  const cats = input('categories', '');
  if (cats) options.categories = cats.split(',').map((s) => s.trim()).filter(Boolean);

  const packPaths = input('ioc-packs', '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
  if (packPaths.length) options.extraPacks = loadPacks(packPaths);

  const excludePatterns = input('exclude', '').split('\n').map((s) => s.trim()).filter(Boolean);
  if (excludePatterns.length) options.exclude = excludePatterns;
  const compiledExcludes = compileExcludes(excludePatterns);

  const findings = [];

  // 1. Event payload (PR body/title, issue, comments, commits…)
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    const payload = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    findings.push(...scanGithubEvent(payload, options));
  }

  // 2. Changed files
  if (input('scan-changed-files', 'true') === 'true') {
    const threshold = parseInt(input('large-diff-lines', '1000'), 10);
    for (const f of changedFileStats()) {
      if (isExcluded(f.file, false, compiledExcludes)) continue;
      if (threshold > 0 && f.lines >= threshold) findings.push(largeDiffFinding(f, threshold));
      if (fs.existsSync(f.file)) findings.push(...scanFile(f.file, options));
    }
  }

  // 3. Extra paths
  for (const p of input('paths', '').split('\n').map((s) => s.trim()).filter(Boolean)) {
    if (fs.existsSync(p)) {
      const stat = fs.statSync(p);
      const { scanDir } = require('./scanner');
      findings.push(...(stat.isDirectory() ? scanDir(p, options) : scanFile(p, options)));
    }
  }

  const summary = summarize(findings, options);
  summary.findings.forEach(annotate);
  setOutput('verdict', summary.ok ? 'clean' : 'blocked');
  setOutput('findings', JSON.stringify(summary.findings));

  if (!summary.ok) {
    process.stdout.write(
      `::error::MIASMA-DETECT BLOCKED: ${summary.blocking} finding(s) at/above ` +
        `"${options.minSeverity}". Halting so no agent or workflow processes this content.\n`
    );
    process.exit(1);
  }
  process.stdout.write(`miasma-detect: clean (${summary.total} sub-threshold finding(s))\n`);
}

try {
  main();
} catch (e) {
  process.stdout.write(`::error::miasma-detect crashed: ${e.stack || e}\n`);
  process.exit(1);
}
