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
 *   MIASMA_LARGE_DIFF_LINES    flag diffs >= this many lines as collapsed/
 *                              hidden from review (default: 1000; 0 disables)
 *   MIASMA_COMMENT_TOKEN       project access token (api scope, Reporter+) used
 *                              to post the report as an MR comment
 *   MIASMA_MR_COMMENT          "false" to disable MR comments (default: true)
 *   MIASMA_SIGNOFF_MAX_SEVERITY  highest severity a manual sign-off may waive
 *                              (default: high — critical is never waivable)
 *
 * Verdict export: writes miasma.env (dotenv) with MIASMA_VERDICT,
 * MIASMA_BLOCKING, and MIASMA_WAIVABLE so a downstream manual sign-off job
 * (see examples/gitlab-ci.yml) can gate on it and refuse unwaivable blocks.
 *
 * Requires GIT_DEPTH: "0" (or a sufficiently deep clone) for MR diffs.
 */

const fs = require('fs');
const { execFileSync } = require('child_process');
const {
  scanText,
  scanFile,
  scanChangedFilename,
  summarize,
  canWaive,
  loadPacks,
  compileExcludes,
  isExcluded,
  lineRange,
} = require('./scanner');
const { buildReport, buildResolved, MARKER } = require('./report');

const env = process.env;

/**
 * Upsert the report as an MR note (one note, updated in place).
 * Needs a token with `api` scope in MIASMA_COMMENT_TOKEN (project access
 * token, role Reporter+) — CI_JOB_TOKEN cannot post notes.
 */
async function upsertMrNote(summary) {
  if ((env.MIASMA_MR_COMMENT || 'true') === 'false') return;
  if (!env.CI_MERGE_REQUEST_IID || !env.CI_API_V4_URL) return; // not an MR pipeline
  const token = env.MIASMA_COMMENT_TOKEN;
  if (!token) {
    if (!summary.ok) {
      process.stdout.write(
        'miasma-detect: set MIASMA_COMMENT_TOKEN (project access token, api scope) ' +
          'to post this report as an MR comment. Report follows in the job log:\n\n'
      );
    }
    return;
  }
  const base = `${env.CI_API_V4_URL}/projects/${encodeURIComponent(env.CI_PROJECT_ID)}/merge_requests/${env.CI_MERGE_REQUEST_IID}/notes`;
  const headers = { 'PRIVATE-TOKEN': token, 'Content-Type': 'application/json' };
  const ctx = {
    platform: 'gitlab',
    runUrl: env.CI_JOB_URL || null,
    signoff:
      'If the manual sign-off gate is enabled: after reviewing the findings, a maintainer plays the `human-signoff` job on this pipeline to acknowledge them and authorize downstream stages. The job refuses when unwaivable (critical) findings are present, and new pushes reset the sign-off.',
  };

  const listRes = await fetch(`${base}?per_page=100`, { headers });
  if (!listRes.ok) throw new Error(`GET notes → ${listRes.status}`);
  const existing = (await listRes.json()).find((n) => n.body && n.body.includes(MARKER));

  if (!summary.ok) {
    const body = buildReport(summary, ctx);
    const res = existing
      ? await fetch(`${base}/${existing.id}`, { method: 'PUT', headers, body: JSON.stringify({ body }) })
      : await fetch(base, { method: 'POST', headers, body: JSON.stringify({ body }) });
    if (!res.ok) throw new Error(`write note → ${res.status}`);
  } else if (existing) {
    const res = await fetch(`${base}/${existing.id}`, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ body: buildResolved(ctx) }),
    });
    if (!res.ok) throw new Error(`update note → ${res.status}`);
  }
}

// Text surfaces GitLab exposes as predefined variables.
const SURFACE_VARS = [
  'CI_MERGE_REQUEST_TITLE',
  'CI_MERGE_REQUEST_DESCRIPTION',
  'CI_MERGE_REQUEST_SOURCE_BRANCH_NAME',
  'CI_COMMIT_MESSAGE',
  'CI_COMMIT_TAG_MESSAGE',
  'CI_COMMIT_BRANCH',
];

function changedFileStats() {
  // MR pipelines: diff against the MR diff base. Push pipelines: previous SHA.
  // Returns [{file, lines}] where lines = added + deleted ('-' for binary → 0).
  let range = null;
  if (env.CI_MERGE_REQUEST_DIFF_BASE_SHA) {
    range = `${env.CI_MERGE_REQUEST_DIFF_BASE_SHA}...HEAD`;
  } else if (env.CI_COMMIT_BEFORE_SHA && !/^0+$/.test(env.CI_COMMIT_BEFORE_SHA)) {
    range = `${env.CI_COMMIT_BEFORE_SHA}..${env.CI_COMMIT_SHA || 'HEAD'}`;
  }
  if (!range) return [];
  try {
    return execFileSync('git', ['diff', '--numstat', '--diff-filter=ACMR', range], {
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        const [a, d, ...rest] = l.split('\t');
        return { file: rest.join('\t'), lines: (parseInt(a, 10) || 0) + (parseInt(d, 10) || 0) };
      });
  } catch (e) {
    process.stdout.write(`miasma-detect: could not compute changed files (${e.message})\n`);
    return [];
  }
}

async function main() {
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

  // 2. Changed files: name-based tampering/propagation checks, collapsed-diff
  //    detection, and content scan.
  if ((env.MIASMA_SCAN_CHANGED_FILES || 'true') !== 'false') {
    const threshold = parseInt(env.MIASMA_LARGE_DIFF_LINES || '1000', 10);
    for (const stat of changedFileStats()) {
      const f = stat.file;
      if (isExcluded(f, false, compiledExcludes)) continue;
      if (threshold > 0 && stat.lines >= threshold) {
        findings.push({
          ruleId: 'SC-COLLAPSED-DIFF',
          severity: 'high',
          category: 'supply-chain',
          description:
            `Diff of ${f} changes ${stat.lines} lines — large diffs are collapsed by the ` +
            `platform UI, a known technique for hiding payloads from human review. ` +
            `A human must expand and review it (threshold: ${threshold}).`,
          source: 'changed-files',
          match: `${f} (${stat.lines} lines)`,
        });
      }
      findings.push(...scanChangedFilename(f));
      if (fs.existsSync(f)) findings.push(...scanFile(f, options));
    }
  }

  const summary = summarize(findings, options);
  for (const f of summary.findings) {
    process.stdout.write(
      `[${f.severity.toUpperCase()}] ${f.ruleId} (${f.category})\n  ${f.description}\n` +
        `  source: ${f.source}${lineRange(f) ? ':' + lineRange(f) : ''}\n` +
        (f.match ? `  match:  ${f.match}\n` : '')
    );
  }

  // Post/refresh the human-facing report as an MR note. A comment failure
  // must never mask the scan verdict.
  try {
    await upsertMrNote(summary);
  } catch (e) {
    process.stdout.write(`miasma-detect: could not post MR note (${e.message})\n`);
  }

  // Export the verdict for downstream jobs (dotenv artifact). The manual
  // human-signoff job gates on MIASMA_WAIVABLE so critical findings can
  // never be signed off.
  const waivable = summary.ok || canWaive(summary, env.MIASMA_SIGNOFF_MAX_SEVERITY || 'high');
  try {
    fs.writeFileSync(
      'miasma.env',
      `MIASMA_VERDICT=${summary.ok ? 'clean' : 'blocked'}\n` +
        `MIASMA_BLOCKING=${summary.blocking}\n` +
        `MIASMA_WAIVABLE=${waivable}\n`
    );
  } catch (e) {
    process.stdout.write(`miasma-detect: could not write miasma.env (${e.message})\n`);
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

main().catch((e) => {
  process.stdout.write(`miasma-detect crashed (failing closed): ${e.stack || e}\n`);
  process.exit(1);
});
