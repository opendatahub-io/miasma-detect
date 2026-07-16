'use strict';

/**
 * GitHub Action entry point (runs: node20, zero dependencies).
 * Scans the triggering event payload and, optionally, files changed
 * in the PR/push. Fails the job on detection.
 */

const fs = require('fs');
const { execFileSync } = require('child_process');
const { scanGithubEvent, scanFile, scanChangedFilename, summarize, canWaive, loadPacks, compileExcludes, isExcluded } = require('./scanner');
const { buildReport, buildResolved, MARKER } = require('./report');

const AUTHORIZED = ['OWNER', 'MEMBER', 'COLLABORATOR'];

function prNumberFrom(payload) {
  return (
    (payload.pull_request && payload.pull_request.number) ||
    (payload.issue && payload.issue.pull_request && payload.issue.number) ||
    null
  );
}

/**
 * Look for a fresh sign-off: the command, commented by a user with repo
 * write access, AFTER the PR's latest commit (stale approvals don't count).
 * Returns {approver, at} or null.
 */
async function findSignoff(token, base, prNumber, command) {
  const pr = await gh(token, 'GET', `${base}/pulls/${prNumber}`);
  const headSha = pr.head.sha;
  const commit = await gh(token, 'GET', `${base}/commits/${headSha}`);
  const commitDate = commit.commit.committer.date;
  const comments = await gh(token, 'GET', `${base}/issues/${prNumber}/comments?per_page=100`);
  const fresh = comments
    .filter(
      (c) =>
        c.body &&
        c.body.includes(command) &&
        AUTHORIZED.includes(c.author_association) &&
        c.created_at > commitDate
    )
    .pop();
  return fresh ? { approver: fresh.user && fresh.user.login, at: fresh.created_at, headSha } : null;
}

/**
 * When a sign-off arrives as a comment, the comment-triggered run can't turn
 * the PR's original check green — re-run the failed pull_request run so the
 * verdict lands on the PR. Needs `actions: write`; failure is non-fatal.
 */
async function rerunPrRun(token, base, headSha) {
  const runs = await gh(
    token,
    'GET',
    `${base}/actions/runs?event=pull_request&head_sha=${headSha}&per_page=20`
  );
  const failed = (runs.workflow_runs || []).find(
    (r) => r.name === process.env.GITHUB_WORKFLOW && r.conclusion === 'failure'
  );
  if (!failed) return false;
  await gh(token, 'POST', `${base}/actions/runs/${failed.id}/rerun-failed-jobs`);
  return true;
}

async function gh(token, method, url, body) {
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'miasma-detect',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${url} → ${res.status}`);
  return res.status === 204 ? null : res.json();
}

/**
 * Upsert the report comment on the PR or plain issue (one comment, updated
 * in place). For plain issues, a clean verdict only rewrites the report to
 * "resolved" on `issues` events (opened/edited — where the payload carries
 * the issue body); a clean comment-event run doesn't see earlier comments,
 * so it must not declare the issue resolved.
 */
async function upsertReportComment(payload, summary, options, waivedBy) {
  const token = input('github-token', process.env.GITHUB_TOKEN || '');
  const prNumber = prNumberFrom(payload);
  const issueNumber =
    payload.issue && !payload.issue.pull_request ? payload.issue.number : null;
  const targetNumber = prNumber || issueNumber;
  if (!targetNumber) return; // push/other events have nowhere to comment
  if (!token) {
    process.stdout.write(
      '::notice::miasma-detect: no github-token input — cannot post the PR report comment. ' +
        'Pass `github-token: ${{ github.token }}` and grant `pull-requests: write`.\n'
    );
    return;
  }
  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const base = `${api}/repos/${process.env.GITHUB_REPOSITORY}`;
  const runUrl = process.env.GITHUB_RUN_ID
    ? `${process.env.GITHUB_SERVER_URL || 'https://github.com'}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
    : null;
  const signoffCmd = input('signoff-command', '/miasma-approve');
  const ctx = {
    platform: 'github',
    runUrl,
    waivedBy,
    kind: prNumber ? 'pr' : 'issue',
    signoff:
      prNumber && signoffCmd
        ? `After reviewing the findings above, a maintainer (write/admin) comments \`${signoffCmd}\` to acknowledge them and unblock — the check re-runs and passes. Approvals from before the latest commit don't count, and critical findings can never be waived this way.`
        : null,
  };

  const comments = await gh(token, 'GET', `${base}/issues/${targetNumber}/comments?per_page=100`);
  const existing = comments.find((c) => c.body && c.body.includes(MARKER));

  if (!summary.ok || waivedBy) {
    const body = buildReport(summary, ctx);
    if (existing) await gh(token, 'PATCH', `${base}/issues/comments/${existing.id}`, { body });
    else await gh(token, 'POST', `${base}/issues/${targetNumber}/comments`, { body });
  } else if (existing) {
    // Clean: mark resolved — but a clean *comment-event* run on a plain
    // issue never saw earlier comments, so it isn't qualified to say so.
    const qualified = prNumber || process.env.GITHUB_EVENT_NAME === 'issues';
    if (qualified) {
      await gh(token, 'PATCH', `${base}/issues/comments/${existing.id}`, { body: buildResolved(ctx) });
    }
  }
}

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

async function main() {
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
  let payload = {};
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    payload = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    findings.push(...scanGithubEvent(payload, options));
  }

  // 2. Changed files
  if (input('scan-changed-files', 'true') === 'true') {
    const threshold = parseInt(input('large-diff-lines', '1000'), 10);
    for (const f of changedFileStats()) {
      if (isExcluded(f.file, false, compiledExcludes)) continue;
      if (threshold > 0 && f.lines >= threshold) findings.push(largeDiffFinding(f, threshold));
      // Name-based checks (.claude/, .vscode/, workflows, .miasmaignore, …)
      // — PR payloads carry no commits[] list, so this is where PRs get them.
      findings.push(...scanChangedFilename(f.file));
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

  // Trusted-bots: downgrade structural findings for verified bot PRs.
  // Campaign IOCs and critical findings keep their original severity.
  const TRUSTED_DOWNGRADE_RULES = new Set([
    'SC-WORKFLOW-ADDED', 'PI-UNICODE-TRICKERY', 'SC-COLLAPSED-DIFF',
  ]);
  const trustedBotEntries = input('trusted-bots', '').split('\n').map((s) => s.trim()).filter(Boolean);
  const trustedBotIds = new Set(trustedBotEntries.filter((e) => /^\d+$/.test(e)));
  const trustedBotLogins = new Set(trustedBotEntries.filter((e) => !/^\d+$/.test(e)).map((e) => e.toLowerCase()));
  const prUser = payload.pull_request && payload.pull_request.user;
  const prAuthor = prUser && prUser.login;
  const prAuthorId = prUser && String(prUser.id || '');
  const isTrusted = (prAuthorId && trustedBotIds.has(prAuthorId)) ||
    (prAuthor && trustedBotLogins.has(prAuthor.toLowerCase()));
  if (isTrusted) {
    let downgraded = 0;
    for (const f of findings) {
      if (f.severity !== 'critical' && f.category !== 'campaign-ioc' && TRUSTED_DOWNGRADE_RULES.has(f.ruleId)) {
        f.originalSeverity = f.severity;
        f.severity = 'low';
        downgraded++;
      }
    }
    if (downgraded) {
      process.stdout.write(
        `::notice::miasma-detect: PR author @${prAuthor} is a trusted bot — ` +
          `downgraded ${downgraded} structural finding(s) to low.\n`
      );
    }
  }

  const summary = summarize(findings, options);
  summary.findings.forEach(annotate);

  let waivedBy = null;
  const signoffCmd = input('signoff-command', '/miasma-approve');
  const token = input('github-token', process.env.GITHUB_TOKEN || '');
  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const base = `${api}/repos/${process.env.GITHUB_REPOSITORY}`;
  const prNumber = prNumberFrom(payload);
  const isCommentEvent = process.env.GITHUB_EVENT_NAME === 'issue_comment';

  // Comment events are a RELAY, not a judge: they don't check out the PR, so
  // they must never conclude anything about its content (or touch the report
  // comment). When the comment is a sign-off, validate it and re-run the
  // failed PR check — that run recomputes the verdict with full context.
  if (
    isCommentEvent &&
    prNumber &&
    signoffCmd &&
    token &&
    payload.comment &&
    payload.comment.body &&
    payload.comment.body.includes(signoffCmd)
  ) {
    try {
      const signoff = await findSignoff(token, base, prNumber, signoffCmd);
      if (signoff) {
        const kicked = await rerunPrRun(token, base, signoff.headSha);
        process.stdout.write(
          kicked
            ? `::notice::miasma-detect: sign-off by @${signoff.approver} validated — re-running the PR check to apply it.\n`
            : '::notice::miasma-detect: sign-off validated but no failed PR run found to re-run (it may already be green).\n'
        );
      } else {
        process.stdout.write(
          '::notice::miasma-detect: sign-off comment found but not valid — it must come from a user ' +
            'with write access and postdate the latest commit.\n'
        );
      }
    } catch (e) {
      process.stdout.write(
        `::notice::miasma-detect: sign-off relay failed (${e.message}) — re-run the failed PR check manually (needs actions: write).\n`
      );
    }
  }

  // Human sign-off waiver (PR-event runs): a maintainer's fresh approval
  // comment can waive blocking findings up to signoff-max-severity. Critical
  // findings (confirmed IOCs) can never be waived at the default setting.
  if (!summary.ok && !isCommentEvent && signoffCmd && token && prNumber) {
    if (canWaive(summary, input('signoff-max-severity', 'high'))) {
      try {
        const signoff = await findSignoff(token, base, prNumber, signoffCmd);
        if (signoff) {
          waivedBy = signoff;
          summary.ok = true;
          process.stdout.write(
            `::notice::miasma-detect: ${summary.blocking} finding(s) acknowledged and waived by ` +
              `@${signoff.approver} via ${signoffCmd} at ${signoff.at}.\n`
          );
        }
      } catch (e) {
        process.stdout.write(`::notice::miasma-detect: sign-off lookup failed (${e.message})\n`);
      }
    } else {
      process.stdout.write(
        '::error::miasma-detect: findings above signoff-max-severity are present — ' +
          'this block CANNOT be waived by sign-off. Treat as confirmed-hostile and report it.\n'
      );
    }
  }

  setOutput('verdict', waivedBy ? 'waived' : summary.ok ? 'clean' : 'blocked');
  setOutput('findings', JSON.stringify(summary.findings));

  // Post/refresh the human-facing report comment on the PR. A comment
  // failure must never mask the scan verdict.
  // PR comment-events never write the report comment: they're sign-off
  // relays that didn't scan the PR content. Plain-issue comment events DO
  // write when blocked — the payload carries the issue body + the new
  // comment, which is the content in question.
  if (input('pr-comment', 'true') === 'true' && !(isCommentEvent && prNumber)) {
    try {
      await upsertReportComment(payload, summary, options, waivedBy);
    } catch (e) {
      process.stdout.write(`::notice::miasma-detect: could not post report comment (${e.message})\n`);
    }
  }

  if (!summary.ok) {
    process.stdout.write(
      `::error::MIASMA-DETECT BLOCKED: ${summary.blocking} finding(s) at/above ` +
        `"${options.minSeverity}". Halting so no agent or workflow processes this content.\n`
    );
    process.exit(1);
  }
  process.stdout.write(`miasma-detect: clean (${summary.total} sub-threshold finding(s))\n`);
}

main().catch((e) => {
  process.stdout.write(`::error::miasma-detect crashed: ${e.stack || e}\n`);
  process.exit(1);
});
