#!/usr/bin/env node
'use strict';

/**
 * GitLab CI/CD entry point (zero dependencies). GitLab has no event-payload
 * file like GitHub's GITHUB_EVENT_PATH, so this reads the predefined CI_*
 * variables for MR/commit text surfaces and git-diffs the changed files.
 * Exits 1 on detection so the pipeline job fails and downstream jobs
 * (including agentic ones) never run.
 *
 * Use with a `needs:`/stage ordering so agent jobs depend on this one, and
 * make the job required via pipeline rules / merged-results settings.
 *
 * Configuration (all optional, via CI/CD variables):
 *   MIASMA_MIN_SEVERITY        low|medium|high|critical (default: medium)
 *   MIASMA_CATEGORIES          comma-separated category filter
 *   MIASMA_IOC_PACKS           comma/newline-separated extra pack JSON paths
 *   MIASMA_EXCLUDE             newline-separated gitignore-style patterns
 *   MIASMA_SCAN_CHANGED_FILES  "false" to skip file scanning (default: true)
 *
 * Requires GIT_DEPTH: "0" (or a sufficiently deep clone) for MR diffs.
 */

const fs = require('fs');
const { execFileSync } = require('child_process');
const {
  scanText,
  scanFile,
  summarize,
  loadPacks,
  compileExcludes,
  isExcluded,
  SUSPICIOUS_COMMIT_FILES,
} = require('./scanner');

const env = process.env;

// Text surfaces GitLab exposes as predefined variables.
const SURFACE_VARS = [
  'CI_MERGE_REQUEST_TITLE',
  'CI_MERGE_REQUEST_DESCRIPTION',
  'CI_MERGE_REQUEST_SOURCE_BRANCH_NAME',
  'CI_COMMIT_MESSAGE',
  'CI_COMMIT_TAG_MESSAGE',
  'CI_COMMIT_BRANCH',
];

function changedFiles() {
  // MR pipelines: diff against the MR diff base. Push pipelines: previous SHA.
  let range = null;
  if (env.CI_MERGE_REQUEST_DIFF_BASE_SHA) {
    range = `${env.CI_MERGE_REQUEST_DIFF_BASE_SHA}...HEAD`;
  } else if (env.CI_COMMIT_BEFORE_SHA && !/^0+$/.test(env.CI_COMMIT_BEFORE_SHA)) {
    range = `${env.CI_COMMIT_BEFORE_SHA}..${env.CI_COMMIT_SHA || 'HEAD'}`;
  }
  if (!range) return [];
  try {
    return execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMR', range], {
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean);
  } catch (e) {
    process.stdout.write(`miasma-detect: could not compute changed files (${e.message})\n`);
    return [];
  }
}

function main() {
  const options = { minSeverity: env.MIASMA_MIN_SEVERITY || 'medium' };
  if (env.MIASMA_CATEGORIES) {
    options.categories = env.MIASMA_CATEGORIES.split(',').map((s) => s.trim()).filter(Boolean);
  }
  const packPaths = (env.MIASMA_IOC_PACKS || '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
  if (packPaths.length) options.extraPacks = loadPacks(packPaths);
  const excludePatterns = (env.MIASMA_EXCLUDE || '').split('\n').map((s) => s.trim()).filter(Boolean);
  const compiledExcludes = compileExcludes(excludePatterns);

  const findings = [];

  // 1. Text surfaces from predefined variables.
  for (const v of SURFACE_VARS) {
    if (env[v]) findings.push(...scanText(env[v], v, options));
  }

  // 2. Changed files: name-based tampering/propagation checks + content scan.
  if ((env.MIASMA_SCAN_CHANGED_FILES || 'true') !== 'false') {
    for (const f of changedFiles()) {
      if (isExcluded(f, false, compiledExcludes)) continue;
      for (const sig of SUSPICIOUS_COMMIT_FILES) {
        if (sig.re.test(f)) {
          findings.push({
            ruleId: sig.id,
            severity: sig.sev || 'high',
            category: 'supply-chain',
            description: `Change adds/modifies ${sig.desc}`,
            source: 'changed-files',
            match: f,
          });
        }
      }
      if (fs.existsSync(f)) findings.push(...scanFile(f, options));
    }
  }

  const summary = summarize(findings, options);
  for (const f of summary.findings) {
    process.stdout.write(
      `[${f.severity.toUpperCase()}] ${f.ruleId} (${f.category})\n  ${f.description}\n` +
        `  source: ${f.source}\n` +
        (f.match ? `  match:  ${f.match}\n` : '')
    );
  }

  if (!summary.ok) {
    process.stdout.write(
      `\nMIASMA-DETECT BLOCKED: ${summary.blocking} finding(s) at/above ` +
        `"${options.minSeverity}". Failing the job so no downstream pipeline ` +
        `stage or agent processes this content.\n`
    );
    process.exit(1);
  }
  process.stdout.write(`miasma-detect: clean (${summary.total} sub-threshold finding(s))\n`);
}

try {
  main();
} catch (e) {
  process.stdout.write(`miasma-detect crashed (failing closed): ${e.stack || e}\n`);
  process.exit(1);
}
