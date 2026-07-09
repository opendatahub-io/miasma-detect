# How miasma-detect works

miasma-detect is layered pattern matching against every surface an attacker can control, with a severity threshold deciding when to throw. It is built to catch the whole **Shai-Hulud / Miasma family** of self-propagating npm/registry worms — not just the specific Red Hat compromise — so a future wave with a new name and new actors still trips it. This document explains the architecture, the rule tiers, and the verdict logic.

The perishable, campaign-specific indicators live in swappable packs under [`src/campaigns/`](../src/campaigns/); the durable, technique-level rules live in [`src/rules.js`](../src/rules.js); the engine lives in [`src/scanner.js`](../src/scanner.js).

## Design: generic techniques + pluggable campaign packs

The central idea is separating *what a specific campaign looked like* from *how this class of attack always works*.

A **campaign pack** is a small data file naming the exact compromised package versions, file hashes, and marker strings of one wave. `src/campaigns/miasma.js` covers the Red Hat compromise plus the June-2026 node-gyp ("Phantom Gyp") cluster; `src/campaigns/shai-hulud.js` covers the wider Shai-Hulud lineage (v1, "The Second Coming" 2.0, the TanStack/Mini waves). These are exact IOCs — they expire as npm removes packages, but they give zero-false-positive hits while the campaign is live.

The **generic rules** in `src/rules.js` describe the *techniques* the entire family reuses across waves. This is where the tool's ability to catch the next variant comes from: attackers keep changing package names, hashes, and marker strings, but they keep reusing install-time execution, a Bun-based off-Node stage, runner-memory scraping, GitHub-as-C2 exfiltration, and worm republishing. Those don't change between waves, so the rules that target them keep working.

When a new campaign is reported, you add a pack (a data drop) or pass `--ioc-pack pack.json` at runtime — you rarely touch the engine or the generic rules. `buildRules()` merges the built-in packs, any extra packs, and the generic rules into one active ruleset.

## The scanning pipeline

Everything funnels into `scanText()`, which runs the merged rule set (~40 rules) over whatever text it is given — a PR body, an issue comment, a diff, a file's contents — plus a lookup of every known-compromised `package@version` from the active packs. Each match produces a *finding* with the rule metadata, matched text, campaign tag, and surrounding context. Four specialized scanners sit on top and add checks regexes can't do well:

### `scanPackageJson()`

Parses the manifest and walks every dependency field (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, `resolutions`, `overrides`), comparing each against the merged compromised-version table. An exact match is **critical**; any *other* version of a package whose scope/name appeared in a campaign gets a **low** "watch" flag (verify, don't auto-block). It flags dependencies pinned to a raw **git commit or fork** (`github:owner/repo#<sha>`, `git+https…#<sha>`) — the technique used to stage the TanStack payload. It inspects `preinstall`/`install`/`postinstall`/`prepare`/`prepublish` scripts for interpreters/downloaders, and surfaces `"gypfile": true` (which makes node-gyp run at install).

### `scanFile()`

Computes the file's SHA256 and compares it against the merged hash list, catching the actual malware regardless of name or location. It then applies a shape heuristic: family droppers are multi-MB *single-line* JS files, so any `.js`/`.cjs`/`.mjs` file with a line over 500,000 characters is flagged even if its content is novel obfuscation no signature covers. Binary files are hash-checked but skipped for text rules; `package.json` is routed through `scanPackageJson()`; everything textual then goes through `scanText()`.

### `scanGithubEvent()`

Knows the GitHub webhook/Actions payload structure. It extracts every human-authored surface — PR/issue title and body, comment and review bodies, discussion text, commit messages, repository description, branch names — and scans each. It also inspects commit **file lists** for propagation/persistence filenames regardless of campaign: `.github/setup.js`, injected workflows, `setup_bun.js`/`bun_environment.js`/`router_init.js`, `binding.gyp`, `extconf.rb`, and AI-agent/editor hooks (`.claude/`, `.cursor/rules/`, `.vscode/tasks.json`).

## Rule tiers, decreasing confidence

**Tier 1 — exact IOCs (from packs; critical/high).** Campaign markers ("Miasma: The Spreading Blight", "Sha1-Hulud: The Second Coming"), destructive honeytoken strings, dropper hashes, the compromised `package@version` table, the worm commit signature, and known payload/workflow filenames. These essentially cannot false-positive, so they block immediately — but they're the part that expires.

**Tier 2 — family techniques (generic; critical to low).** The durable core. Install/build-time execution: lifecycle-script hooks, `binding.gyp` `<!(...)` command expansion ("Phantom Gyp"), RubyGems `extconf.rb` hooks. Off-Node evasion: Bun runtime downloads, `curl|bash`, `eval`+char-code and inline AES-GCM self-decryption. Privilege/evasion: `NOPASSWD:ALL`, `docker run --privileged -v /:/host` breakout, `isSecret":true` runner-memory scraping, `/etc/hosts` tampering. Credential access: IMDS metadata endpoints, credential-file sweeps, trufflehog abuse, npm token and maintainer enumeration. Propagation/persistence: workflow command-injection, self-hosted runner registration, AI-agent/editor persistence hooks, `.github/setup.js` self-injection, forged Sigstore/SLSA provenance, `results/…json` dead-drops, `python-requests` UA spoofing, and `rm -rf ~/`.

**Tier 3 — prompt injection (generic; high to medium).** Text aimed at the *agent* rather than the machine: instruction overrides, directives addressed to an AI agent, commands hidden in HTML comments (invisible when rendered, visible to an agent reading raw markdown), concealment instructions, invisible/bidirectional Unicode, and system-prompt probes.

## The verdict

`summarize()` compares each finding's severity against the configured threshold (default `medium`, ordering `low < medium < high < critical`). Any finding at or above the threshold makes the verdict **blocked**:

| Entry point | On detection |
| --- | --- |
| CLI (`src/cli.js`) | exit code `1`, prints findings + block banner |
| GitHub Action (`src/action.js`) | fails the job, emits `::error::`/`::warning::` annotations, sets `verdict`/`findings` outputs |
| GitLab CI job (`src/gitlab-ci.js`) | exit code `1` — fails the pipeline job so downstream stages/agents never run; fails closed on internal errors |
| Claude Code hook (`hooks/claude-code-hook.js`) | exit code `2` — Claude Code withholds the content and warns the model to stop and report to the user |
| Library (`summarize().ok`) | returns `false`; caller decides |

The hook **fails closed**: if the scanner itself crashes, it blocks rather than allows. Sub-threshold findings are still reported so a human can review them without failing automation.

## Limitations

This is signature and heuristic matching, not semantic understanding. A determined attacker can phrase an injection the regexes don't cover, and novel obfuscation may evade the shape heuristics. The generic rules raise the bar — an attacker has to avoid *every* reused technique, not just change a name — but they are not a guarantee. Keep the baseline defenses: `npm install --ignore-scripts` in CI, exact-pinned dependencies with lockfile integrity, a registry cooldown on freshly published versions, least-privilege CI/CD tokens, and branch protection.

Note that `src/`, `README.md`, and this file contain IOC strings themselves — exclude the scanner's own install directory when scanning file trees, or you'll detect the detector.

## Adding a new campaign

Preferred (no code): write a JSON pack and pass `--ioc-pack pack.json` (CLI), `ioc-packs:` (Action), or `options.extraPacks` (library):

```json
{
  "name": "next-campaign",
  "packages": { "some-pkg": ["1.2.3"] },
  "hashes": ["<sha256>"],
  "rules": [
    { "id": "NEXT-MARKER", "severity": "critical", "category": "campaign-ioc",
      "description": "…", "pattern": { "source": "the[- ]marker", "flags": "i" } }
  ]
}
```

In-tree: add a file under `src/campaigns/` and list it in `src/campaigns/index.js`. If you spot a genuinely new *technique*, add a generic rule to `GENERIC_RULES` in `src/rules.js`. Either way, add a test in `test/test.js` — including a benign control — and run `npm test`.
