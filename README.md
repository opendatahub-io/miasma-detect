# miasma-detect

Fail-fast scanner for the **Miasma** npm supply-chain campaign ([Microsoft Security Blog, June 2, 2026](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)), plus generic supply-chain attack heuristics and prompt-injection patterns.

Point it at a GitHub PR/issue/comment, a diff, a file tree, or any text blob. If it matches an indicator, it exits non-zero immediately — so CI fails and coding agents stop before processing malicious content.

Zero dependencies. Node ≥ 18. One codebase, four entry points: CLI, library, GitHub Action, Claude Code hook. For the detection architecture, see [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## What it detects

**Confirmed Miasma IOCs (critical/high)** — all 32 compromised `@redhat-cloud-services` package versions (in package.json, lockfiles, or diff text), the six known dropper SHA256 hashes (by file hash and by mention), the "Miasma: The Spreading Blight" campaign marker, the destructive honeytoken string, `.github/setup.js` worm commits, the `chore: update dependencies [skip ci]` worm commit signature, exfil drop paths (`results/<timestamp>-<n>.json`), and `bun run .claude/` second-stage execution.

**Generic supply-chain heuristics** — lifecycle hooks (`preinstall`/`install`/`postinstall`) that execute scripts, Bun runtime downloads, `eval` + char-code obfuscation, very large single-line JS files (the dropper was a 4.29 MB one-liner), `NOPASSWD:ALL` sudoers injection, runner memory scraping (`isSecret":true`), cloud metadata endpoint access, credential-file sweeps, npm token enumeration, `/etc/hosts` tampering, and `rm -rf ~/`.

**Prompt injection** — instruction overrides ("ignore previous instructions"), directives addressed to AI agents, hidden HTML-comment commands, concealment instructions ("don't tell the user"), invisible/bidi Unicode, and system-prompt probes.

Severity levels: `critical`, `high`, `medium`, `low`. The failure threshold defaults to `medium`; anything below is reported but doesn't fail.

## CLI

```bash
npm install -g miasma-detect        # or npx miasma-detect

# Scan files/directories
miasma-detect path/to/repo package.json

# Scan text (PR body, diff, anything) from stdin
gh pr view 123 --json title,body -q '.title + "\n" + .body' | miasma-detect --stdin
git diff origin/main...HEAD | miasma-detect --stdin

# Scan a GitHub event payload (auto-uses $GITHUB_EVENT_PATH in Actions)
miasma-detect --event event.json

# Options
miasma-detect --min-severity high --categories miasma-ioc,package --json --quiet <path>
```

Exit codes: `0` clean, `1` **blocked — stop processing**, `2` usage error.

## Library

```js
const { scanText, scanFile, scanDir, scanGithubEvent, summarize } = require('miasma-detect');

const findings = scanText(prBody, 'pr.body');
const { ok, findings: all } = summarize(findings, { minSeverity: 'medium' });
if (!ok) throw new Error('Miasma indicators detected — halting');
```

## GitHub Action

Publish this repo (or vendor it) and add `.github/workflows/miasma-detect.yml` (full example in `examples/workflow.yml`):

```yaml
on:
  pull_request: { types: [opened, edited, reopened, synchronize] }
  issues: { types: [opened, edited] }
  issue_comment: { types: [created, edited] }

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: your-org/miasma-detect@v1
        with:
          min-severity: medium
          scan-changed-files: 'true'
```

The action scans the event payload (PR/issue/comment text, commit messages, changed-file names) and, on PRs/pushes, the content of changed files. It emits `::error::` annotations and fails the job on detection. Outputs: `verdict` (`clean`/`blocked`) and `findings` (JSON). Make it a required status check to hard-gate merges and downstream agent workflows.

## Claude Code hook

Blocks the agent the moment fetched content matches — before it can act on it. Copy `hooks/settings.example.json` wiring into `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "node ./node_modules/miasma-detect/hooks/claude-code-hook.js" }] }
    ],
    "PostToolUse": [
      { "matcher": "WebFetch|WebSearch|Bash|Read|mcp__github__.*",
        "hooks": [{ "type": "command", "command": "node ./node_modules/miasma-detect/hooks/claude-code-hook.js" }] }
    ]
  }
}
```

The hook reads the event JSON from stdin, scans prompt/tool input/tool output, and exits `2` on detection — Claude Code blocks the content and shows the model a warning telling it to stop and report to the user. Threshold via `MIASMA_MIN_SEVERITY` env var. The hook fails **closed**: internal errors block rather than allow.

## Jenkins / anywhere else

```groovy
sh 'git diff origin/main...HEAD | npx miasma-detect --stdin'   // non-zero exit fails the stage
```

## Caveats

This is one defense-in-depth layer, not a guarantee. Regex/IOC scanning can't catch novel obfuscation, and the prompt-injection rules will have both false negatives and occasional false positives on security-related discussion (this README and `src/rules.js` themselves trigger detections — exclude the scanner's own install directory from scans). Keep the baseline mitigations from the Microsoft advisory: `npm install --ignore-scripts`, pinned dependencies, rotated credentials, and audit for repos described "Miasma: The Spreading Blight".

To update IOCs as the campaign evolves, edit `src/rules.js` (`COMPROMISED_PACKAGES`, `MALICIOUS_SHA256`, `TEXT_RULES`).

## Test

```bash
npm test   # 27 tests: IOCs, heuristics, injections, benign controls, CLI/hook exit codes
```
