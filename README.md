# miasma-detect

Fail-fast scanner for the **Shai-Hulud / Miasma family** of self-propagating npm supply-chain worms — the lineage behind the [Shai-Hulud](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/) waves (Sept 2025 →), [Sha1-Hulud 2.0 "The Second Coming"](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack) (Nov 2025), and the [Miasma](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/) / [node-gyp "Phantom Gyp"](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/) waves (June 2026) — plus generic supply-chain attack heuristics and prompt-injection patterns.

Point it at a GitHub PR/issue/comment, a diff, a file tree, or any text blob. If it matches an indicator, it exits non-zero immediately — so CI fails and coding agents stop before processing malicious content.

**Built to catch the next wave, not just the last one.** Exact indicators (compromised versions, hashes, marker strings) live in swappable [campaign packs](src/campaigns/); the bulk of the rules target the *techniques* the whole family reuses across waves, so a future campaign with a different name and different actors still trips them. Add a new campaign as a data drop (`--ioc-pack`), not a code change.

Zero dependencies. Node ≥ 18. One codebase, five entry points: CLI, library, GitHub Action, GitLab CI/CD job, Claude Code hook. For the detection architecture, see [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## What it detects

**Confirmed campaign IOCs (critical/high), from the built-in packs** — known-compromised package versions across the `@redhat-cloud-services`, `@vapi-ai/server-sdk`, `autotel`, `ai-sdk-ollama` and other affected names (in package.json, lockfiles, or diff text); known dropper SHA256 hashes; campaign markers ("Miasma: The Spreading Blight", "Sha1-Hulud: The Second Coming"); the destructive honeytoken; worm commit signatures; and known payload/workflow filenames (`setup_bun.js`, `bun_environment.js`, `router_init.js`, `shai-hulud-workflow.yml`).

**Family techniques (generic — the part that catches future variants)** — install/build-time execution via lifecycle hooks, `binding.gyp` `<!(...)` command expansion ("Phantom Gyp"), and RubyGems `extconf.rb`; Bun runtime downloads and `curl|bash`; `eval`+char-code and inline AES-GCM obfuscation; multi-MB single-line JS droppers; `NOPASSWD:ALL` and `docker --privileged -v /:/host` breakout; runner memory scraping (`isSecret":true`); IMDS metadata access, credential-file sweeps, trufflehog abuse, npm token and maintainer enumeration; workflow command-injection, rogue self-hosted runner registration, AI-agent/editor persistence hooks (`.claude/`, `.cursor/rules/`, `.vscode/tasks.json`), `.github/setup.js` self-injection, forged Sigstore/SLSA provenance, `results/…json` dead-drops, git-commit-pinned deps, and `rm -rf ~/`.

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
miasma-detect --min-severity high --categories campaign-ioc,supply-chain,package --json --quiet <path>

# Add a new campaign at runtime — no code change
miasma-detect --ioc-pack ./packs/new-wave.json --stdin

# Audit whole repos: exclude paths, or use `--` for dash-prefixed paths.
# A .miasmaignore file (gitignore-style patterns) at the scan root is
# honored automatically. For tree audits, --categories package,campaign-ioc
# keeps the technique heuristics (curl|bash in READMEs, sudoers templates
# in infra code…) from drowning the signal.
miasma-detect --exclude 'vendor/' --exclude '**/testdata/' ~/git/myrepo
miasma-detect --categories package,campaign-ioc -- -weird-dir-name
```

Exit codes: `0` clean, `1` **blocked — stop processing**, `2` usage error.

## Covering a new campaign

Perishable indicators live in [`src/campaigns/`](src/campaigns/); the generic technique rules in `src/rules.js` are what catch unnamed future variants. To add a wave without touching code, write a JSON pack and pass it via `--ioc-pack` (CLI), `ioc-packs:` (Action input), or `options.extraPacks` (library):

```json
{
  "name": "next-wave",
  "packages": { "some-pkg": ["1.2.3"] },
  "hashes": ["<sha256>"],
  "rules": [
    { "id": "NEXTWAVE-MARKER", "severity": "critical", "category": "campaign-ioc",
      "description": "new marker string", "pattern": { "source": "the[- ]marker", "flags": "i" } }
  ]
}
```

Built-in packs stay active alongside yours. See [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) for the full format and the technique-rule catalog.

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
  push:
    branches: [main]   # direct-push safety net only — PR branches are covered
                       # by pull_request:synchronize; scanning branch pushes too
                       # creates a second, unwaivable red check on the commit

permissions:
  contents: read
  pull-requests: write   # report comments on PRs
  issues: write          # report comments on plain issues
  actions: write         # lets /miasma-approve re-run the failed PR check

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5
        if: github.event_name == 'pull_request' || github.event_name == 'push'
        with: { fetch-depth: 0 }
      - uses: opendatahub-io/miasma-detect@<full-commit-SHA>   # pin per your Actions policy
        with:
          min-severity: medium
          scan-changed-files: ${{ github.event_name == 'pull_request' || github.event_name == 'push' }}
```

The action scans the event payload (PR/issue/comment text, commit messages, changed-file names) and, on PRs/pushes, the names and content of changed files (including collapsed-diff detection). It emits `::error::` annotations and fails the job on detection. Outputs: `verdict` (`clean` / `blocked` / `waived`) and `findings` (JSON). Make it a required status check to hard-gate merges and downstream agent workflows.

Inputs (all optional): `min-severity` (default `medium`), `categories`, `ioc-packs`, `exclude` (gitignore-style patterns), `large-diff-lines` (default `1000`, `0` disables), `scan-changed-files`, `paths`, `pr-comment` (default `true`), `github-token` (defaults to the workflow token), `signoff-command` (default `/miasma-approve`, empty disables waivers), `signoff-max-severity` (default `high`; critical is never waivable), `report-artifact-dir` (fork-safe pattern, below).

If your Actions policy requires full-length SHA pins (recommended), remember the pin freezes the scanner version — bump it when the scanner updates, or let Dependabot open the bump PRs. To scan the scanner's own repo without pin churn, use the two-checkout pattern in this repo's own `.github/workflows/miasma-detect.yml`: check out main's copy into a subdirectory and `uses: ./<subdir>` — always current, and a malicious PR can't run its own modified scanner on itself.

**Report comments on PRs and issues.** On detection the action posts one comment (updated in place on re-runs; marked resolved when the content comes clean) explaining each finding, the human intervention required, and how to unblock. PRs get fix-and-push / exclude / sign-off steps; issues get edit-or-close guidance. Comment-triggered runs never overwrite the report for PRs (they're sign-off relays that don't scan PR content), and a clean comment-event run on an issue won't declare it resolved (it can't see earlier comments). Disable with `pr-comment: 'false'`. Quoted matches are defanged (`[.]`/`[:]`) and the report body is self-scanned before posting, so the comment can never re-trigger this or any other scanner reading comment text. On GitLab, the same report is posted as an MR note when `MIASMA_COMMENT_TOKEN` (project access token, `api` scope) is set; otherwise it appears in the job log.

**Commenting on fork PRs (the `workflow_run` pattern).** A scan triggered by a PR from a fork gets a **read-only** `GITHUB_TOKEN` and no secrets (GitHub's fork-PR security boundary), so it can't post a comment — the action skips it with a clear notice, and findings still appear as inline annotations and a failed check. To get comments on fork PRs anyway (like a GitHub App would), use the two-workflow fork-safe pattern in [`examples/fork-safe-scan.yml`](examples/fork-safe-scan.yml) + [`examples/fork-safe-comment.yml`](examples/fork-safe-comment.yml). The scan keeps `pr-comment: 'true'` (so issues and **same-repo** PRs still get a direct comment) and adds `report-artifact-dir:` to also write the rendered report as an artifact. A companion workflow on `workflow_run` then runs with a write-capable base-repo token, downloads that artifact, and posts it via `miasma-detect-post-report` — **without checking out or executing any fork code**. The companion is gated to fork PRs only (`workflow_run.head_repository != workflow_run.repository`), so same-repo PRs — already commented directly — never get a second comment. Do *not* use `pull_request_target` for this — running base-repo code with base secrets against fork content is the secret-exfiltration vector the scanner itself flags. (Inline annotations still work on fork PRs regardless; this pattern is only needed if you also want the summary *comment*.)

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

The hook reads the event JSON from stdin, scans prompt/tool input/tool output, and exits `2` on detection — Claude Code blocks the content and shows the model a warning telling it to stop and report to the user. Threshold via `MIASMA_MIN_SEVERITY`; extra campaign packs via `MIASMA_IOC_PACKS` (comma/newline-separated JSON paths, same format as `--ioc-pack`). The hook fails **closed**: internal errors block rather than allow.

## CodeRabbit

Two complementary layers keep CodeRabbit from agentically processing malicious PR content. Example configs: [`examples/coderabbit.yaml`](examples/coderabbit.yaml) and [`examples/coderabbit-gate-workflow.yml`](examples/coderabbit-gate-workflow.yml).

**Layer 1 — label gate (prevention).** CodeRabbit is a webhook-driven SaaS, so a repo can't intercept its input directly — but it can withhold the review trigger. In `.coderabbit.yaml`, disable auto-review and opt in via a positive label match:

```yaml
reviews:
  auto_review:
    enabled: false
    labels: ["miasma-clean"]
```

Then install the gate workflow (`examples/coderabbit-gate-workflow.yml` → `.github/workflows/miasma-gate.yml`). On every PR open/edit/push it removes the `miasma-clean` label, runs this scanner, and re-applies the label only on a clean verdict. CodeRabbit starts its review only when the label appears; blocked PRs fail the check and are never processed. Make `miasma-gate` a required status check so they can't merge either.

**Layer 2 — pre-merge checks (defense in depth).** `examples/coderabbit.yaml` also defines two `custom_checks` in `error` mode (with `request_changes_workflow: true` so failures block the merge): one instructing CodeRabbit to fail the PR on supply-chain indicators, one on agent-manipulation attempts. This covers what slips past layer 1 — including the race window below.

Caveats: there is a small race on pushes — if a PR already carries the label from a previous clean scan, CodeRabbit's incremental review may start in the seconds before the gate workflow revokes it. The label gates *reviews* only; `@coderabbitai` comment interactions aren't controlled by it. And when writing check instructions, *describe* indicators rather than quoting exact IOC strings, or your `.coderabbit.yaml` will itself trip the changed-files scan (the example config is written this way and scans clean).

**Control-tampering defense:** a PR could try to disable these defenses instead of evading them — editing `.miasmaignore` to hide a payload from tree scans, or `.coderabbit.yaml` to remove the gate. The event scanner therefore flags any commit touching either file (`SC-IGNOREFILE-MODIFIED` / `SC-REVIEWGATE-MODIFIED`, high — blocks at the default threshold). Note the Action's changed-files scan never honors the PR branch's `.miasmaignore`; only the workflow-level `exclude:` input (protected by branch rules) applies there.

## Organization-wide deployment

To enforce the scan (and the CodeRabbit gate) across many repos without copying logic into each, use the reusable workflow. All logic lives in [`.github/workflows/reusable-scan.yml`](.github/workflows/reusable-scan.yml); each repo gets a ~15-line stub ([`examples/org-stub-workflow.yml`](examples/org-stub-workflow.yml) → `.github/workflows/miasma-detect.yml`) that calls it:

```yaml
permissions:
  contents: read
  pull-requests: write
  issues: write
  actions: write
jobs:
  miasma-detect:
    uses: opendatahub-io/miasma-detect/.github/workflows/reusable-scan.yml@<full-sha>
    with:
      min-severity: medium
```

Update behavior org-wide by editing the reusable workflow once, then bumping the pinned SHA in the stubs (Dependabot opens those PRs automatically). The CodeRabbit gate config itself belongs in your org's `.github/.coderabbit.yaml` (the org-default all repos inherit); protect it with a push ruleset, since a repo-level `.coderabbit.yaml` overrides org settings.

Why a stub-and-reusable-workflow rather than GitHub's native "required workflows"? Required workflows only trigger on `pull_request` events, which would drop issue scanning, the direct-push audit trail, and the `issue_comment`-based `/miasma-approve` waiver. The stub subscribes to all of those and the caller's event context flows into the reusable workflow, preserving the full feature set. (Because the reusable workflow references the published action by SHA, keep that pin in sync with the SHA the stubs use — both live in this repo and move together per release.)

## GitLab CI/CD

Add the gate job from [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) to your `.gitlab-ci.yml`:

```yaml
miasma-detect:
  stage: gate
  image: registry.access.redhat.com/ubi9/nodejs-22:latest
  variables: { GIT_DEPTH: "0" }
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "push"
  script:
    - npm install -g miasma-detect
    - miasma-detect-gitlab-ci
```

GitLab exposes no event-payload file, so `miasma-detect-gitlab-ci` reads the predefined variables (MR title/description, branch name, commit message) and git-diffs the changed files — including the name-based control-tampering checks (`.miasmaignore`, workflows, agent hooks). It fails the job on detection; put it in a first `gate` stage (or use `needs:`) so build/test/agent jobs never run on blocked content. Configure via CI/CD variables: `MIASMA_MIN_SEVERITY`, `MIASMA_CATEGORIES`, `MIASMA_EXCLUDE`, `MIASMA_IOC_PACKS`, `MIASMA_SCAN_CHANGED_FILES`, `MIASMA_LARGE_DIFF_LINES` (collapsed-diff threshold, default `1000`, `0` disables), `MIASMA_COMMENT_TOKEN` (project access token for MR report notes), and `MIASMA_MR_COMMENT` (`false` disables notes). It fails **closed** on internal errors.

For GitLab **webhooks** (e.g. a bot or service consuming merge_request/note/push events), the library's `scanGitlabEvent(payload)` handles GitLab's payload shape, and `scanEvent(payload)` auto-detects GitHub vs GitLab (GitLab sets `object_kind`). The CLI's `--event` flag does the same auto-detection. The same direct-push caveat applies as on GitHub: gate protected branches with merge requests and make this job required.

## Jenkins / anywhere else

```groovy
sh 'git diff origin/main...HEAD | npx miasma-detect --stdin'   // non-zero exit fails the stage
```

## Automating InfoSec PR-review rules

The gate automates the standard InfoSec mandates for PR review, so humans only get pulled in when something needs judgment:

**"Don't run suspicious branches through AI tools."** The label gate + Claude Code hook mean no AI processing happens until the scan passes — and, with sign-off enabled, until a human explicitly approves (see below).

**"Expand and review every collapsed diff."** Changed files whose diff meets the `large-diff-lines` threshold (default 1000; `MIASMA_LARGE_DIFF_LINES` on GitLab) raise `SC-COLLAPSED-DIFF` (**high**) — platforms don't render large diffs by default, which attackers exploit to hide payloads from review. The scan stays red until a human expands, reviews, and signs off (or excludes a legitimately generated path). Relatedly, `SC-LINGUIST-GENERATED-TAMPER` (high) catches `.gitattributes` changes that mark source files `linguist-generated` — the other way to make GitHub collapse a diff — and `SC-GITATTRIBUTES-MODIFIED` (medium) flags any `.gitattributes` change in a PR.

**"Reject PRs containing `.claude/` or `.vscode/`."** `SC-AGENT-HOOK-ADDED` and `SC-VSCODE-DIR-ADDED` (both high) block them pending review, and the confirmed malware signature — an agent hook running `node .claude/setup.mjs` — is `MIASMA-CLAUDE-SETUP-MJS` (**critical**). Per the advisory: don't interact further, report immediately.

**"Scrutinize all CI/CD configuration changes."** `SC-WORKFLOW-ADDED` (GitHub workflows) and `SC-CI-CONFIG-MODIFIED` (`.gitlab-ci.yml`, `Jenkinsfile`, CircleCI/Azure/Drone/Travis configs) flag every pipeline change for human eyes.

**Acknowledge-and-proceed waivers (`/miasma-approve`).** Some findings' remediation *is* human review — a modified workflow, a `.claude/` change, a collapsed diff. For those, the Action supports waivers natively: after a maintainer (write/admin) reviews the findings and comments `/miasma-approve` on the PR, the check passes with verdict `waived`, and the report comment is rewritten as an audit trail crediting the approver. Guardrails: the approval must postdate the latest commit (a new push re-locks the PR), the commenter must have write access, and findings above `signoff-max-severity` (default `high`) can **never** be waived — confirmed-IOC criticals always stay blocked. Because comment-triggered runs can't update a PR's existing check, the action re-runs the failed PR check automatically when it sees a valid sign-off (needs `actions: write`; otherwise re-run it manually). Set `signoff-command: ''` to disable waivers entirely.

**Human sign-off before AI processing.** Two mechanisms, per platform. On GitHub (`examples/coderabbit-gate-workflow.yml`, `REQUIRE_SIGNOFF: 'true'`): the gate label is only applied after a user with write/admin permission comments `/miasma-approve` — and only if that comment postdates the latest commit, so a push after approval automatically re-locks the PR. On GitLab (`examples/gitlab-ci.yml`): a `when: manual` + `allow_failure: false` job that a maintainer must click — GitLab's permission model controls who can play it, and each new push creates a fresh pipeline with the job un-played, so approvals can't go stale. The manual job is more robust than comment parsing; if you prefer the comment convention on GitLab too, the same pattern can be built with a notes-API poll and a project access token.

## Caveats

This is one defense-in-depth layer, not a guarantee. Regex/IOC scanning can't catch novel obfuscation, and the prompt-injection rules will have both false negatives and occasional false positives on security-related discussion (this README and `src/` themselves trigger detections — exclude the scanner's own install directory from scans). Keep the baseline mitigations from the Microsoft advisory: `npm install --ignore-scripts`, pinned dependencies, rotated credentials, and audit for repos described "Miasma: The Spreading Blight".

**Direct pushes bypass PR scanning.** Everything in the PR gate (label gating, changed-file scans, control-tampering flags) only fires on pull requests — someone with push access to a branch skips all of it. Close this by (1) enabling branch protection so protected branches only change via PR with `miasma-gate`/`scan` as required status checks, and (2) subscribing the scan workflow to `push:` as well, as `examples/workflow.yml` does — a direct push then still gets its commits, changed files, and any `.miasmaignore`/`.coderabbit.yaml` tampering scanned after the fact and surfaced as a failed check. Note this is a *workflow trigger*, not an action input: an action can't choose its own events, so make sure `on: push` is present in your workflow file rather than assuming the action covers it.

To cover a new campaign, add a pack under `src/campaigns/` or ship one at runtime via `--ioc-pack` (see "Covering a new campaign" above); new *technique* rules go in `GENERIC_RULES` in `src/rules.js`.

## Test

```bash
npm test   # 69 tests: IOCs, techniques, injections, packs, excludes, GitHub/GitLab events, policy rules, waivers, report safety, benign controls, exit codes
```
