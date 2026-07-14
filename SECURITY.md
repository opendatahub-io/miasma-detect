# Security Policy

## Reporting a vulnerability in miasma-detect

If you find a security issue in the scanner itself — a way to bypass detection,
a false-negative class, a crash or resource-exhaustion in the parser, or a way
to make the tool execute or leak something — please report it privately.

**Do not open a public issue for security reports.** Use GitHub's private
vulnerability reporting: on this repository, go to the **Security** tab →
**Report a vulnerability** (GitHub Private Vulnerability Reporting). If that is
unavailable, email the maintainer listed in `package.json`.

Please include:

- What the issue is and where (file, rule, or entry point)
- Steps or a minimal input that reproduces it
- The impact you believe it has (bypass, false result, DoS, etc.)

You can expect an acknowledgement within a few business days. This is a
volunteer-maintained project, so please allow reasonable time for a fix before
any public disclosure — coordinated disclosure is appreciated.

## Scope

In scope: the scanner code (`src/`, `hooks/`, the GitHub Action, the GitLab
CI entry, the reusable workflow) and its detection logic.

Out of scope: findings that the tool *reports* on other people's code — those
are the whole point and should go through the normal issue tracker or the
affected project. Also out of scope: the third-party campaigns and CVEs the
rules describe; report those to the relevant vendors.

## A note on detection coverage

miasma-detect is one defense-in-depth layer, not a guarantee. It combines exact
indicators of the Shai-Hulud / Miasma worm family with generic technique
heuristics and prompt-injection patterns. By design it will have both false
positives and false negatives:

- **Exact IOCs expire.** Compromised package versions, hashes, and marker
  strings are removed from registries over time and new waves appear. The
  campaign packs under `src/campaigns/` are updated on a best-effort basis;
  they are not a substitute for a maintained commercial feed.
- **Heuristics can be evaded.** A determined attacker can phrase an injection
  or obfuscate a payload in a way the current rules do not match.

Keep the baseline mitigations regardless of this tool: `npm install
--ignore-scripts` in CI, exact-pinned dependencies with lockfile integrity,
least-privilege CI/CD tokens, SHA-pinned GitHub Actions, and branch protection.

## Supported versions

Security fixes are applied to the latest release on `main`. There is no
long-term support branch. Pin to a full-length commit SHA and update
deliberately (Dependabot understands SHA-pinned actions and will open bump
PRs).
