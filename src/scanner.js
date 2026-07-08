'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { COMPROMISED_PACKAGES, MALICIOUS_SHA256, TEXT_RULES } = require('./rules');

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

const DEFAULT_OPTIONS = {
  minSeverity: 'medium',        // findings below this are reported but don't fail
  categories: null,             // null = all; or array of: miasma-ioc, supply-chain, prompt-injection, package
  maxFileSize: 10 * 1024 * 1024,
  ignoreDirs: new Set(['node_modules', '.git', 'dist', 'build', 'coverage']),
};

function makeFinding(rule, source, extra) {
  return Object.assign(
    {
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      description: rule.description,
      source,
    },
    extra || {}
  );
}

function excerpt(text, index, len) {
  const start = Math.max(0, index - 40);
  const end = Math.min(text.length, index + len + 40);
  return text.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 160);
}

/** Scan a blob of text (PR body, issue text, diff, file content). */
function scanText(text, source, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const findings = [];
  if (typeof text !== 'string' || text.length === 0) return findings;

  for (const rule of TEXT_RULES) {
    if (opts.categories && !opts.categories.includes(rule.category)) continue;
    const m = rule.pattern.exec(text);
    if (m) {
      findings.push(
        makeFinding(rule, source, {
          match: m[0].slice(0, 200),
          excerpt: excerpt(text, m.index, m[0].length),
        })
      );
    }
  }

  // Compromised package references anywhere in text (diffs, lockfiles, manifests)
  for (const [pkg, versions] of Object.entries(COMPROMISED_PACKAGES)) {
    if (!text.includes(pkg)) continue;
    for (const v of versions) {
      const re = new RegExp(
        escapeRegExp(pkg) + '["\'@\\s:]{0,4}[\\^~]?' + escapeRegExp(v) + '(?![\\d.])'
      );
      if (re.test(text)) {
        findings.push({
          ruleId: 'MIASMA-COMPROMISED-PKG',
          severity: 'critical',
          category: 'package',
          description: `Reference to compromised package ${pkg}@${v} (Miasma campaign)`,
          source,
          match: `${pkg}@${v}`,
        });
      }
    }
  }

  return findings;
}

/** Scan a parsed package.json object for compromised deps + hostile lifecycle scripts. */
function scanPackageJson(pkgJson, source, options) {
  const findings = [];
  const depFields = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
    'resolutions',
    'overrides',
  ];
  for (const field of depFields) {
    const deps = pkgJson[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, range] of Object.entries(deps)) {
      const versions = COMPROMISED_PACKAGES[name];
      if (!versions) continue;
      const cleaned = String(range).replace(/^[\^~>=<\s]+/, '');
      if (versions.includes(cleaned)) {
        findings.push({
          ruleId: 'MIASMA-COMPROMISED-PKG',
          severity: 'critical',
          category: 'package',
          description: `${field} pins compromised package ${name}@${range} (Miasma campaign)`,
          source,
          match: `${name}@${range}`,
        });
      } else {
        findings.push({
          ruleId: 'MIASMA-SCOPE-WATCH',
          severity: 'low',
          category: 'package',
          description: `Dependency on ${name} (@redhat-cloud-services scope was compromised in the Miasma campaign; version ${range} not in known-bad list — verify and pin)`,
          source,
          match: `${name}@${range}`,
        });
      }
    }
  }

  const scripts = pkgJson.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    const cmd = scripts[hook];
    if (!cmd) continue;
    if (/\b(node|sh|bash|curl|wget|bun|python)\b/.test(cmd)) {
      findings.push({
        ruleId: 'SC-LIFECYCLE-HOOK',
        severity: 'high',
        category: 'supply-chain',
        description: `npm ${hook} hook executes a script ("${cmd}") — primary Miasma delivery vector; verify before installing`,
        source,
        match: `"${hook}": "${cmd}"`,
      });
    }
  }
  return findings;
}

/** Scan a file: hash check + text rules + package.json awareness. */
function scanFile(filePath, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const findings = [];
  let buf;
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > opts.maxFileSize) return findings;
    buf = fs.readFileSync(filePath);
  } catch {
    return findings;
  }

  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  if (MALICIOUS_SHA256.includes(sha256)) {
    findings.push({
      ruleId: 'MIASMA-FILE-HASH',
      severity: 'critical',
      category: 'miasma-ioc',
      description: 'File SHA256 matches a known Miasma dropper',
      source: filePath,
      match: sha256,
    });
  }

  // Skip binary content for text rules
  if (buf.includes(0)) return findings;
  const text = buf.toString('utf8');

  const base = path.basename(filePath);
  if (base === 'package.json') {
    try {
      findings.push(...scanPackageJson(JSON.parse(text), filePath, opts));
    } catch {
      /* fall through to text scan */
    }
  }

  // Giant single-line JS heuristic (Miasma dropper was a 4.29 MB one-liner)
  if (/\.(js|cjs|mjs)$/.test(base)) {
    const lines = text.split('\n');
    const maxLine = Math.max(...lines.map((l) => l.length));
    if (maxLine > 500000) {
      findings.push({
        ruleId: 'SC-GIANT-ONELINER',
        severity: 'high',
        category: 'supply-chain',
        description: `Suspicious very large single-line JavaScript (${maxLine} chars) — matches Miasma dropper shape`,
        source: filePath,
        match: `${maxLine}-char line`,
      });
    }
  }

  findings.push(...scanText(text, filePath, opts));
  return findings;
}

/** Recursively scan a directory. */
function scanDir(dirPath, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const findings = [];
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return findings;
  }
  for (const e of entries) {
    const full = path.join(dirPath, e.name);
    if (e.isDirectory()) {
      if (!opts.ignoreDirs.has(e.name)) findings.push(...scanDir(full, opts));
    } else if (e.isFile()) {
      findings.push(...scanFile(full, opts));
    }
  }
  return findings;
}

/**
 * Scan a GitHub webhook/Actions event payload (pull_request, issues,
 * issue_comment, push, etc.). Extracts all human-authored text surfaces.
 */
function scanGithubEvent(event, options) {
  const findings = [];
  const surfaces = [];
  const push = (label, value) => {
    if (typeof value === 'string' && value) surfaces.push([label, value]);
  };

  push('pull_request.title', event.pull_request && event.pull_request.title);
  push('pull_request.body', event.pull_request && event.pull_request.body);
  push('pull_request.head.ref', event.pull_request && event.pull_request.head && event.pull_request.head.ref);
  push('issue.title', event.issue && event.issue.title);
  push('issue.body', event.issue && event.issue.body);
  push('comment.body', event.comment && event.comment.body);
  push('review.body', event.review && event.review.body);
  push('discussion.title', event.discussion && event.discussion.title);
  push('discussion.body', event.discussion && event.discussion.body);
  push('repository.description', event.repository && event.repository.description);
  if (Array.isArray(event.commits)) {
    event.commits.forEach((c, i) => {
      push(`commits[${i}].message`, c.message);
      (c.added || []).concat(c.modified || []).forEach((f) => {
        // Worm plants .github/setup.js via direct commits
        if (/\.github[\/\\]setup\.js$/i.test(f)) {
          findings.push({
            ruleId: 'MIASMA-SETUPJS-WORM',
            severity: 'critical',
            category: 'miasma-ioc',
            description: 'Commit adds/modifies .github/setup.js (Miasma worm propagation path)',
            source: `commits[${i}].files`,
            match: f,
          });
        }
      });
    });
  }

  for (const [label, value] of surfaces) {
    findings.push(...scanText(value, label, options));
  }
  return findings;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Summarize findings; verdict fails when any finding >= minSeverity. */
function summarize(findings, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const threshold = SEVERITY_ORDER[opts.minSeverity] ?? 1;
  const blocking = findings.filter((f) => SEVERITY_ORDER[f.severity] >= threshold);
  return {
    ok: blocking.length === 0,
    total: findings.length,
    blocking: blocking.length,
    maxSeverity: findings.reduce(
      (acc, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[acc] ? f.severity : acc),
      'low'
    ),
    findings,
  };
}

module.exports = {
  scanText,
  scanFile,
  scanDir,
  scanPackageJson,
  scanGithubEvent,
  summarize,
  SEVERITY_ORDER,
  DEFAULT_OPTIONS,
};
