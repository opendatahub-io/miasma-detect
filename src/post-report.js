#!/usr/bin/env node
'use strict';

/**
 * Fork-safe report poster. Runs in a `workflow_run` companion workflow (which
 * has a base-repo, write-capable GITHUB_TOKEN and does NOT execute fork code)
 * to post the report the scan job wrote as an artifact. This is how findings
 * get commented onto fork PRs, where the scan job's own token is read-only.
 *
 * Usage:  miasma-detect-post-report [artifact-dir]   (default: ./miasma-report)
 * Reads <dir>/meta.json ({ number, kind, state }) and <dir>/report.md, then
 * upserts a single report comment on the PR/issue.
 *
 * Env: GITHUB_TOKEN (write), GITHUB_REPOSITORY, optional GITHUB_API_URL.
 */

const fs = require('fs');
const path = require('path');
const { MARKER } = require('./report');

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

async function main() {
  const dir = process.argv[2] || process.env.MIASMA_REPORT_DIR || 'miasma-report';
  let meta;
  let body;
  try {
    meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    body = fs.readFileSync(path.join(dir, 'report.md'), 'utf8');
  } catch (e) {
    // No artifact (e.g. the scan didn't run, or nothing to comment on) — nothing to do.
    process.stdout.write(`miasma-detect post-report: no report artifact in ${dir} (${e.message})\n`);
    return;
  }

  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    process.stderr.write('miasma-detect post-report: GITHUB_TOKEN is required (with pull-requests/issues: write)\n');
    process.exit(1);
  }
  if (!meta.number) {
    process.stdout.write('miasma-detect post-report: artifact has no target number — nothing to comment on\n');
    return;
  }

  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const repoBase = `${api}/repos/${process.env.GITHUB_REPOSITORY}`;
  const comments = await gh(token, 'GET', `${repoBase}/issues/${meta.number}/comments?per_page=100`);
  const existing = comments.find((c) => c.body && c.body.includes(MARKER));

  if (meta.state === 'clean') {
    // Only rewrite an existing report to "resolved"; never create a fresh
    // comment just to say a clean PR is clean.
    if (existing) {
      await gh(token, 'PATCH', `${repoBase}/issues/comments/${existing.id}`, { body });
      process.stdout.write(`miasma-detect post-report: marked resolved on #${meta.number}\n`);
    } else {
      process.stdout.write('miasma-detect post-report: clean and no existing report — nothing to post\n');
    }
    return;
  }

  // blocked or waived — upsert the report.
  if (existing) {
    await gh(token, 'PATCH', `${repoBase}/issues/comments/${existing.id}`, { body });
  } else {
    await gh(token, 'POST', `${repoBase}/issues/${meta.number}/comments`, { body });
  }
  process.stdout.write(`miasma-detect post-report: posted ${meta.state} report on #${meta.number}\n`);
}

main().catch((e) => {
  process.stderr.write(`miasma-detect post-report: ${e.stack || e}\n`);
  process.exit(1);
});
