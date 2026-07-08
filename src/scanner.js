'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rules = require('./rules');

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

const DEFAULT_OPTIONS = {
  minSeverity: 'medium',        // findings below this are reported but don't fail
  categories: null,             // null = all; or array of: campaign-ioc, supply-chain, prompt-injection, package
  maxFileSize: 10 * 1024 * 1024,
  giantLineThreshold: 500000,   // single-line JS length that looks like a packed dropper
  ignoreDirs: new Set([
    'node_modules', '.git', 'dist', 'build', 'coverage', // JS
    'target',                                            // Rust/Java build output
    '.venv', 'venv', '__pycache__', '.tox',              // Python
  ]),
  extraPacks: null,             // additional IOC packs (from --ioc-pack)
};

// Resolve the active ruleset. If a scan supplies extraPacks, rebuild; else
// use the cached default (generic rules + built-in campaign packs).
function getRuleset(opts) {
  if (opts && opts.extraPacks && opts.extraPacks.length) {
    return rules.buildRules(opts.extraPacks);
  }
  return rules; // module already exposes COMPROMISED_PACKAGES / MALICIOUS_SHA256 / TEXT_RULES
}

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

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Scan a blob of text (PR body, issue text, diff, file content). */
function scanText(text, source, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const rs = getRuleset(opts);
  const findings = [];
  if (typeof text !== 'string' || text.length === 0) return findings;

  for (const rule of rs.TEXT_RULES) {
    if (opts.categories && !opts.categories.includes(rule.category)) continue;
    const m = rule.pattern.exec(text);
    if (m) {
      findings.push(
        makeFinding(rule, source, {
          match: m[0].slice(0, 200),
          excerpt: excerpt(text, m.index, m[0].length),
          campaign: rule.campaign,
        })
      );
    }
  }

  // Known-compromised package references anywhere in text (diffs, lockfiles, manifests)
  if (!opts.categories || opts.categories.includes('package')) {
    for (const [pkg, versions] of Object.entries(rs.COMPROMISED_PACKAGES)) {
      if (!text.includes(pkg)) continue;
      for (const v of versions) {
        const re = new RegExp(
          escapeRegExp(pkg) + '["\'@\\s:]{0,4}[\\^~]?' + escapeRegExp(v) + '(?![\\d.])'
        );
        if (re.test(text)) {
          findings.push({
            ruleId: 'KNOWN-COMPROMISED-PKG',
            severity: 'critical',
            category: 'package',
            description: `Reference to known-compromised package ${pkg}@${v} (Shai-Hulud/Miasma family)`,
            source,
            match: `${pkg}@${v}`,
          });
        }
      }
    }
  }

  return findings;
}

/** Scan a parsed package.json object for compromised deps + hostile lifecycle scripts. */
function scanPackageJson(pkgJson, source, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const rs = getRuleset(opts);
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
      const raw = String(range);
      // Dependency pinned to a raw git commit / attacker fork (payload staging).
      // Covers URL forms (git+https, git@) and npm shorthands (github:, gitlab:,
      // bitbucket:, or bare owner/repo) that reference a commit SHA after '#'.
      if (/(?:(?:git\+)?(?:https?:\/\/|git@)|(?:github|gitlab|bitbucket):|^[\w.-]+\/[\w.-]+#)[^#\s]*#[0-9a-f]{7,40}\b/i.test(raw)) {
        findings.push({
          ruleId: 'SC-GIT-COMMIT-DEP',
          severity: 'medium',
          category: 'supply-chain',
          description: `${field} pins ${name} to a raw git commit (${raw}) — technique used to stage worm payloads; verify the source`,
          source,
          match: `${name}: ${raw}`,
        });
      }
      const versions = rs.COMPROMISED_PACKAGES[name];
      if (!versions) continue;
      const cleaned = raw.replace(/^[\^~>=<\s]+/, '');
      if (versions.includes(cleaned)) {
        findings.push({
          ruleId: 'KNOWN-COMPROMISED-PKG',
          severity: 'critical',
          category: 'package',
          description: `${field} pins known-compromised package ${name}@${range} (Shai-Hulud/Miasma family)`,
          source,
          match: `${name}@${range}`,
        });
      } else {
        findings.push({
          ruleId: 'COMPROMISED-SCOPE-WATCH',
          severity: 'low',
          category: 'package',
          description: `Dependency on ${name}, which had other versions compromised in the Shai-Hulud/Miasma family; version ${range} is not in the known-bad list — verify and pin`,
          source,
          match: `${name}@${range}`,
        });
      }
    }
  }

  const scripts = pkgJson.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish']) {
    const cmd = scripts[hook];
    if (!cmd) continue;
    if (/\b(node|sh|bash|curl|wget|bun|python3?|deno)\b/.test(cmd)) {
      findings.push({
        ruleId: 'SC-LIFECYCLE-HOOK',
        severity: 'high',
        category: 'supply-chain',
        description: `npm ${hook} hook executes a script ("${cmd}") — the family's classic install-time execution vector; verify before installing`,
        source,
        match: `"${hook}": "${cmd}"`,
      });
    }
  }

  // gypfile:true declares native build → node-gyp will run at install.
  // Not malicious by itself, but worth surfacing alongside a binding.gyp check.
  if (pkgJson.gypfile === true) {
    findings.push({
      ruleId: 'SC-GYPFILE-DECLARED',
      severity: 'low',
      category: 'supply-chain',
      description: 'package.json declares "gypfile": true — node-gyp runs at install; ensure the binding.gyp is legitimate (see "Phantom Gyp" technique)',
      source,
      match: '"gypfile": true',
    });
  }
  return findings;
}

/** Scan a file: hash check + filename technique checks + text rules + manifest awareness. */
function scanFile(filePath, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  const rs = getRuleset(opts);
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
  if (rs.MALICIOUS_SHA256.includes(sha256)) {
    findings.push({
      ruleId: 'KNOWN-MALICIOUS-HASH',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'File SHA256 matches a known dropper from the Shai-Hulud/Miasma family',
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

  // Giant single-line JS heuristic (family droppers are multi-MB one-liners).
  if (/\.(js|cjs|mjs)$/.test(base)) {
    let maxLine = 0;
    for (const l of text.split('\n')) if (l.length > maxLine) maxLine = l.length;
    if (maxLine > opts.giantLineThreshold) {
      findings.push({
        ruleId: 'SC-GIANT-ONELINER',
        severity: 'high',
        category: 'supply-chain',
        description: `Suspicious very large single-line JavaScript (${maxLine} chars) — matches the family's packed-dropper shape`,
        source: filePath,
        match: `${maxLine}-char line`,
      });
    }
  }

  findings.push(...scanText(text, filePath, opts));
  return findings;
}

// --- Exclusion patterns (--exclude / .miasmaignore) -------------------------
// Gitignore-flavored subset: `*` matches within a path segment, `**` across
// segments, `?` a single character. A pattern containing `/` is anchored to
// the scan root; one without matches any path segment (basename). A trailing
// `/` restricts the pattern to directories. Lines starting with # are comments.

function globToRegExp(glob) {
  let p = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  p = p.replace(/\*\*/g, '\x00').replace(/\*/g, '[^/]*').replace(/\x00/g, '.*').replace(/\?/g, '[^/]');
  return new RegExp('^' + p + '$');
}

function compileExcludes(patterns) {
  return (patterns || [])
    .map((raw) => {
      let pat = String(raw).trim();
      if (!pat || pat.startsWith('#')) return null;
      const dirOnly = pat.endsWith('/');
      if (dirOnly) pat = pat.slice(0, -1);
      const anchored = pat.includes('/');
      return { re: globToRegExp(pat), anchored, dirOnly, raw: String(raw).trim() };
    })
    .filter(Boolean);
}

function isExcluded(relPath, isDir, compiled) {
  if (!compiled || compiled.length === 0) return false;
  const p = relPath.split(path.sep).join('/');
  const base = p.slice(p.lastIndexOf('/') + 1);
  for (const c of compiled) {
    if (c.dirOnly && !isDir) continue;
    if (c.anchored ? c.re.test(p) : c.re.test(base) || c.re.test(p)) return true;
  }
  return false;
}

/**
 * Recursively scan a directory. Honors opts.exclude (array of gitignore-style
 * patterns) and, unless opts.useIgnoreFile === false, a .miasmaignore file at
 * the scan root (one pattern per line, # comments).
 */
function scanDir(dirPath, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options);
  let patterns = Array.isArray(opts.exclude) ? opts.exclude.slice() : [];
  if (opts.useIgnoreFile !== false) {
    try {
      patterns = patterns.concat(
        fs.readFileSync(path.join(dirPath, '.miasmaignore'), 'utf8').split('\n')
      );
    } catch {
      /* no ignore file */
    }
  }
  const compiled = compileExcludes(patterns);
  const findings = [];
  walkDir(dirPath, '', compiled, opts, findings);
  return findings;
}

function walkDir(dir, rel, compiled, opts, findings) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    const childRel = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) {
      if (opts.ignoreDirs.has(e.name)) continue;
      if (isExcluded(childRel, true, compiled)) continue;
      walkDir(full, childRel, compiled, opts, findings);
    } else if (e.isFile()) {
      if (isExcluded(childRel, false, compiled)) continue;
      findings.push(...scanFile(full, opts));
    }
  }
}

// Filenames that, when added/modified in a commit, indicate worm propagation
// or persistence regardless of campaign name.
const SUSPICIOUS_COMMIT_FILES = [
  { re: /\.github[\/\\]setup\.js$/i, id: 'SC-SETUP-JS-WORM', desc: '.github/setup.js (worm self-injection bootstrap)' },
  { re: /\.github[\/\\]workflows[\/\\].*\.ya?ml$/i, id: 'SC-WORKFLOW-ADDED', desc: 'a GitHub Actions workflow (verify it is not an injected backdoor)', sev: 'medium' },
  { re: /(?:^|[\/\\])(?:setup_bun|bun_environment|router_init)\.js$/i, id: 'SC-FAMILY-PAYLOAD-FILE', desc: 'a known family payload filename (setup_bun.js / bun_environment.js / router_init.js)' },
  { re: /(?:^|[\/\\])binding\.gyp$/i, id: 'SC-BINDING-GYP-ADDED', desc: 'binding.gyp (node-gyp build file — verify it contains no "<!(...)" command expansion)', sev: 'medium' },
  { re: /(?:^|[\/\\])extconf\.rb$/i, id: 'SC-EXTCONF-ADDED', desc: 'extconf.rb (RubyGems build hook — verify it does not fetch/run code)', sev: 'medium' },
  { re: /\.cursor[\/\\]rules[\/\\]|\.vscode[\/\\]tasks\.json$|\.claude[\/\\]/i, id: 'SC-AGENT-HOOK-ADDED', desc: 'an AI-agent/editor auto-run hook (persistence that survives npm uninstall)' },
];

/**
 * Scan a GitHub webhook/Actions event payload (pull_request, issues,
 * issue_comment, push, discussion, etc.). Extracts all human-authored text
 * surfaces and inspects commit file lists for propagation/persistence files.
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
      const files = (c.added || []).concat(c.modified || []);
      for (const f of files) {
        for (const sig of SUSPICIOUS_COMMIT_FILES) {
          if (sig.re.test(f)) {
            findings.push({
              ruleId: sig.id,
              severity: sig.sev || 'high',
              category: 'supply-chain',
              description: `Commit adds/modifies ${sig.desc}`,
              source: `commits[${i}].files`,
              match: f,
            });
          }
        }
      }
    });
  }

  for (const [label, value] of surfaces) {
    findings.push(...scanText(value, label, options));
  }
  return findings;
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

/** Load external IOC packs from JSON file paths (for --ioc-pack). */
function loadPacks(filePaths) {
  return (filePaths || []).map((p) => {
    const pack = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!pack.name) throw new Error(`IOC pack ${p} is missing a "name"`);
    return pack;
  });
}

module.exports = {
  scanText,
  scanFile,
  scanDir,
  scanPackageJson,
  scanGithubEvent,
  summarize,
  loadPacks,
  compileExcludes,
  isExcluded,
  SEVERITY_ORDER,
  DEFAULT_OPTIONS,
};
