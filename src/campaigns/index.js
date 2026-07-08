'use strict';

/**
 * Built-in campaign IOC packs. To cover a future campaign, add a pack file
 * here — or ship one at runtime as JSON via `--ioc-pack <file>` (CLI) or
 * `options.extraPacks` (library). No engine changes required.
 *
 * External JSON pack format:
 * {
 *   "name": "new-campaign",
 *   "packages": { "some-pkg": ["1.2.3"] },
 *   "hashes": ["<sha256>"],
 *   "rules": [
 *     { "id": "NEWCAMPAIGN-MARKER", "severity": "critical",
 *       "category": "campaign-ioc", "description": "…",
 *       "pattern": { "source": "the[- ]regex", "flags": "i" } }
 *   ]
 * }
 */

const BUILTIN_PACKS = [require('./miasma'), require('./shai-hulud')];

function reviveRule(rule, packName) {
  const pattern =
    rule.pattern instanceof RegExp
      ? rule.pattern
      : new RegExp(rule.pattern.source, rule.pattern.flags || '');
  return Object.assign({}, rule, { pattern, campaign: packName });
}

/** Merge built-in + extra packs into { packages, hashes, rules }. */
function mergePacks(extraPacks) {
  const packs = BUILTIN_PACKS.concat(extraPacks || []);
  const packages = {};
  const hashes = [];
  const rules = [];
  for (const pack of packs) {
    for (const [name, versions] of Object.entries(pack.packages || {})) {
      packages[name] = (packages[name] || []).concat(versions);
    }
    hashes.push(...(pack.hashes || []));
    for (const rule of pack.rules || []) rules.push(reviveRule(rule, pack.name));
  }
  return { packages, hashes, rules, packNames: packs.map((p) => p.name) };
}

module.exports = { BUILTIN_PACKS, mergePacks };
