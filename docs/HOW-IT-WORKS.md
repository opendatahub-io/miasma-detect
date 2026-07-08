# How miasma-detect works

miasma-detect is layered pattern matching against every surface an attacker can control, with a severity threshold deciding when to throw. This document explains the pipeline, the rule tiers, and the verdict logic. Rule definitions live in [`src/rules.js`](../src/rules.js); the engine lives in [`src/scanner.js`](../src/scanner.js).

## The scanning pipeline

Everything funnels into `scanText()`, which runs ~24 regex rules over whatever text it is given — a PR body, an issue comment, a diff, a file's contents. Each rule has an ID, a severity, and a category. When a rule matches, it produces a *finding* containing the rule metadata, the matched text, and surrounding context for triage.

Three specialized scanners sit on top of `scanText()` and add checks that regexes cannot do well:

### `scanPackageJson()`

Parses the manifest and walks every dependency field (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, `resolutions`, `overrides`), comparing names and versions against the hardcoded table of 32 compromised `@redhat-cloud-services` package versions from the Microsoft advisory. An exact version match is **critical**. Any *other* version inside that scope gets a **low**-severity "watch" flag, because the entire namespace was compromised and unknown versions deserve verification, not an automatic block.

It also inspects the `preinstall`, `install`, and `postinstall` lifecycle scripts — Miasma's delivery vector — and flags any that invoke an interpreter or downloader (`node`, `sh`, `bash`, `curl`, `wget`, `bun`, `python`).

### `scanFile()`

Computes the file's SHA256 and compares it against the six known Miasma dropper hashes. This catches the actual malware file regardless of what it is named or where it sits.

It then applies a shape heuristic: the Miasma dropper was a 4.29 MB *single-line* JavaScript file, so any `.js`/`.cjs`/`.mjs` file containing a line longer than 500,000 characters is flagged even if its content is novel obfuscation no signature covers. Binary files are hash-checked but skipped for text rules; files named `package.json` are routed through `scanPackageJson()` first; everything textual then goes through `scanText()`.

### `scanGithubEvent()`

Knows the GitHub webhook/Actions payload structure. It extracts every human-authored surface — PR title and body, issue title and body, comment bodies, review bodies, discussion text, commit messages, repository description, branch names — and runs each through `scanText()` with the surface name attached as the finding source.

It also checks commit file lists directly for `.github/setup.js`, the path Miasma's worm uses to inject itself into victim repositories via the Git Data API.

## Three rule tiers, decreasing confidence

**Tier 1 — exact IOCs (critical/high).** The campaign marker ("Miasma: The Spreading Blight"), the destructive honeytoken string, the six dropper hashes, the 32 compromised package versions, the worm commit signature (`chore: update dependencies [skip ci]`), exfiltration drop paths (`results/<timestamp>-<counter>.json`), and `bun run .claude/` second-stage execution. These essentially cannot false-positive, so they block immediately.

**Tier 2 — behavioral heuristics (critical to low).** These describe *how* this class of attack works rather than this specific sample, so they catch Miasma variants that change their strings but keep their technique: Bun runtime downloads from release infrastructure, `eval()` combined with character-code array reconstruction, `NOPASSWD:ALL` sudoers injection, the `isSecret":true` runner-memory-scrape pattern, cloud metadata endpoint access (IMDS), credential-file sweeps, npm token enumeration endpoints, `/etc/hosts` tampering, nested base64 encoding, and `rm -rf ~/`.

**Tier 3 — prompt injection (high to medium).** Text aimed at manipulating the *agent* rather than the machine: instruction overrides ("ignore previous instructions"), directives addressed to an AI agent ("AI assistant: run …"), commands hidden inside HTML comments (invisible when rendered on GitHub, but visible to an agent reading raw markdown), concealment instructions ("do not tell the user"), invisible or bidirectional Unicode characters used to hide text, and system-prompt probes.

## The verdict

`summarize()` compares each finding's severity against the configured threshold (default `medium`, ordering `low < medium < high < critical`). Any finding at or above the threshold makes the verdict **blocked**:

| Entry point | On detection |
| --- | --- |
| CLI (`src/cli.js`) | exit code `1`, prints findings + block banner |
| GitHub Action (`src/action.js`) | fails the job, emits `::error::`/`::warning::` annotations, sets `verdict`/`findings` outputs |
| Claude Code hook (`hooks/claude-code-hook.js`) | exit code `2` — Claude Code withholds the content and shows the model a warning telling it to stop and report to the user |
| Library (`summarize().ok`) | returns `false`; caller decides |

The hook **fails closed**: if the scanner itself crashes, it blocks rather than allows. Sub-threshold findings are still reported so a human can review them without failing automation.

## Limitations

This is signature and heuristic matching, not semantic understanding. A determined attacker can phrase an injection the regexes do not cover, and novel obfuscation may evade the heuristics. The design leans on exact IOCs and behavioral patterns together so the common cases are reliable, while accepting that novel cases need other layers: `npm install --ignore-scripts`, pinned dependencies, least-privilege tokens, and branch protection remain essential.

Note that `src/rules.js`, `README.md`, and this file contain the IOC strings themselves — exclude the scanner's own install directory when scanning file trees, or you will detect the detector.

## Updating the rules

As the campaign evolves, edit `src/rules.js`: add package versions to `COMPROMISED_PACKAGES`, hashes to `MALICIOUS_SHA256`, and new patterns to `TEXT_RULES` (each entry needs `id`, `severity`, `category`, `description`, `pattern`). Add a matching test in `test/test.js` — including a benign control — and run `npm test`.
