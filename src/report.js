'use strict';

/**
 * Builds the human-facing markdown report posted as a PR/MR comment when the
 * scan blocks. Explains what was found, what human intervention is needed,
 * and how to get past the gate.
 *
 * SAFETY: the report quotes findings, and comment bodies are themselves
 * scanned on later events — so every quoted match is defanged (dots/colons
 * bracketed) and the finished report is self-scanned; anything that still
 * matches a rule is redacted. The report can never re-trigger the scanner.
 */

const { scanText } = require('./scanner');

const MARKER = '<!-- miasma-detect-report -->';
const RESOLVED_MARKER = '<!-- miasma-detect-report:resolved -->';

function defang(s) {
  return String(s)
    .replace(/\./g, '[.]')
    .replace(/:/g, '[:]')
    // Strip invisible/bidi characters so a quoted match can't smuggle them.
    .replace(new RegExp('[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF]|\\uDB40[\\uDC00-\\uDC7F]', 'g'), '?')
    .slice(0, 120);
}

// What a human must do, keyed by rule ID (falls back to category guidance).
const RULE_GUIDANCE = {
  'SC-COLLAPSED-DIFF':
    'Expand the collapsed file(s) in the web UI ("Load diff" / "expand") and review every line. Platforms hide large diffs by default and attackers exploit that. If the file is a genuinely generated artifact (lockfile, bundle), add its path to the `exclude` patterns so future scans skip it.',
  'SC-GITATTRIBUTES-MODIFIED':
    'Review the `.gitattributes` change line by line — marking files "linguist-generated" collapses their diffs and hides them from review.',
  'SC-LINGUIST-GENERATED-TAMPER':
    'This change marks source/config files as generated, which hides their diffs from reviewers. Verify each marked path is truly generated output.',
  'SC-IGNOREFILE-MODIFIED':
    'A maintainer must review the new suppression patterns line by line — editing this file can hide payloads from future scans.',
  'SC-REVIEWGATE-MODIFIED':
    'A maintainer must verify the AI-review gate config still enforces label gating and pre-merge checks.',
  'SC-VSCODE-DIR-ADDED':
    'Security policy rejects changes introducing editor/agent config directories pending review. Verify every file in it; these can auto-execute when a project is opened.',
  'SC-AGENT-HOOK-ADDED':
    'Review the agent/editor auto-run hook contents. These execute when a project is opened and survive package uninstalls.',
  'SC-CI-CONFIG-MODIFIED':
    'Security policy requires reviewing every CI/CD pipeline change with extreme care before it runs.',
  'SC-WORKFLOW-ADDED':
    'Review the workflow file for command injection (event data echoed into run steps) and rogue runner registration.',
  'MIASMA-CLAUDE-SETUP-MJS':
    '⚠️ This matches a CONFIRMED malware signature. Per security advisory: stop interacting with this change entirely and report it to your security team immediately. Do not check out or open this branch in an editor or agent.',
};

const CATEGORY_GUIDANCE = {
  'campaign-ioc':
    'This matches a known-campaign indicator. Treat the change as hostile: do not check out, build, install, or open the branch in an editor/agent. Report it to your security team. If your repo legitimately documents these indicators (security tooling, IOC lists), have a maintainer add the path to the exclude patterns.',
  package:
    'A referenced package version is on the known-compromised list. Remove or change the pinned version; audit any machine that installed it and rotate exposed credentials.',
  'supply-chain':
    'A supply-chain attack technique was detected. A human must read the flagged content and confirm it is legitimate before anything installs, builds, or analyzes this change.',
  'prompt-injection':
    'The text tries to manipulate AI reviewers/agents. Humans should review the flagged text directly; keep AI tools away from this change until it is removed.',
};

function severityIcon(sev) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' }[sev] || '⚪';
}

/**
 * Build the blocked-report markdown.
 * ctx: { platform: 'github'|'gitlab', signoff: string|null, runUrl: string|null }
 */
function buildReport(summary, ctx = {}) {
  const lines = [];
  lines.push(MARKER);
  if (ctx.waivedBy) {
    lines.push('## ⚠️ miasma-detect: findings acknowledged by human sign-off');
    lines.push('');
    lines.push(
      `**@${ctx.waivedBy.approver}** reviewed and waived **${summary.blocking} finding(s)** ` +
        `(max severity: **${summary.maxSeverity}**) at ${ctx.waivedBy.at}. The check passes; ` +
        'the findings remain listed below for the audit trail. A new push re-locks the PR.'
    );
  } else {
    lines.push('## 🛑 miasma-detect blocked this change');
    lines.push('');
    lines.push(
      `The security scan found **${summary.blocking} finding(s)** at or above the failure threshold ` +
        `(max severity: **${summary.maxSeverity}**). AI/agent processing and downstream automation are ` +
        'halted until a human resolves this.'
    );
  }
  lines.push('');
  lines.push('### What was found');
  lines.push('');
  lines.push('| | Rule | Where | Detail |');
  lines.push('|---|---|---|---|');
  for (const f of summary.findings.slice(0, 25)) {
    const detail = defang(f.match || f.excerpt || '');
    lines.push(
      `| ${severityIcon(f.severity)} ${f.severity} | \`${f.ruleId}\` | \`${defang(f.source)}\` | ${f.description.split('\n')[0]}${detail ? ` — \`${detail}\`` : ''} |`
    );
  }
  if (summary.findings.length > 25) {
    lines.push(`| | … | | ${summary.findings.length - 25} more finding(s) in the job log |`);
  }
  lines.push('');
  lines.push('_Quoted matches are defanged (`[.]`, `[:]`) so this report cannot re-trigger scanners._');
  lines.push('');
  lines.push('### What a human needs to do');
  lines.push('');
  const seen = new Set();
  for (const f of summary.findings) {
    const g = RULE_GUIDANCE[f.ruleId] || CATEGORY_GUIDANCE[f.category];
    if (g && !seen.has(g)) {
      seen.add(g);
      lines.push(`- ${g}`);
    }
  }
  lines.push('');
  if (!ctx.waivedBy && ctx.kind === 'issue') {
    lines.push('### What to do next');
    lines.push('');
    lines.push('1. If you authored the flagged content, edit the issue or comment to remove it — the scan re-runs on edit and this report updates.');
    lines.push('2. If you did not author it, treat it as hostile: keep AI/agent tooling away from this issue, delete the offending comment or close the issue, and report it to your security contact.');
    lines.push('3. For false positives in legitimate security discussion, describe indicators rather than quoting exact marker strings, versions, or paths.');
  } else if (!ctx.waivedBy) {
    lines.push('### How to get past this gate');
    lines.push('');
    lines.push('1. Review every finding above; fix or remove the flagged content and push a new commit — the gate re-runs automatically.');
    lines.push(
      '2. For false positives, have a maintainer add an exclude pattern (workflow/job `exclude` input, or `.miasmaignore` for tree scans). Note that editing `.miasmaignore` is itself flagged — by design — so that change gets maintainer review too.'
    );
    if (ctx.signoff) {
      lines.push(`3. ${ctx.signoff}`);
    }
  }
  if (ctx.runUrl) {
    lines.push('');
    lines.push(`Full scan output: ${ctx.runUrl}`);
  }
  let md = lines.join('\n');

  // Self-check: the report must never match the scanner's own rules.
  // Redact by defanging in place (readable); if defanging doesn't change the
  // text (no dots/colons), break the pattern with a middle dot instead.
  for (let i = 0; i < 5; i++) {
    const hits = scanText(md, 'report').filter((f) => f.match);
    if (hits.length === 0) break;
    for (const f of hits) {
      let safe = defang(f.match);
      if (safe === f.match) safe = f.match.slice(0, 1) + '·' + f.match.slice(1);
      md = md.split(f.match).join(safe);
    }
  }
  return md;
}

/** Short body used to overwrite the report once the PR scans clean again. */
function buildResolved(ctx = {}) {
  return (
    `${MARKER}\n${RESOLVED_MARKER}\n## ✅ miasma-detect: resolved\n\n` +
    'The latest revision scans clean. Earlier findings on this thread were addressed or superseded.' +
    (ctx.signoff ? `\n\n${ctx.signoff}` : '')
  );
}

module.exports = { buildReport, buildResolved, defang, MARKER, RESOLVED_MARKER };
