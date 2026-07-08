'use strict';

/**
 * Detection rules for self-propagating package-registry supply-chain worms
 * of the Shai-Hulud / Miasma family, and prompt-injection payloads.
 *
 * DESIGN: The specific, perishable indicators (compromised package versions,
 * file hashes, campaign marker strings) live in per-campaign packs under
 * src/campaigns/. The rules in THIS file are deliberately generic — they
 * describe the *techniques* the whole family reuses, so a new campaign with
 * a different name and different actors still trips them. When a new wave is
 * reported, add a pack (or pass --ioc-pack); you should rarely need to touch
 * this file.
 *
 * Severities:
 *   critical - confirmed IOC or unambiguous attack behavior; block now
 *   high     - strong supply-chain / injection indicator
 *   medium   - suspicious; worth blocking for unattended agents
 *   low      - informational heuristic
 */

const { mergePacks } = require('./campaigns');

// ---------------------------------------------------------------------------
// Generic, campaign-independent technique rules. These are the heart of the
// tool's ability to catch *future* variants.
// ---------------------------------------------------------------------------
const GENERIC_RULES = [
  // --- Automatic install/build-time execution (the family's entry point) -----
  {
    id: 'SC-LIFECYCLE-HOOK-TEXT',
    severity: 'high',
    category: 'supply-chain',
    description: 'npm lifecycle hook (pre/post/install) executing an interpreter or downloader — classic install-time execution vector',
    pattern: /"(?:pre|post)?install"\s*:\s*"[^"]*\b(?:node|sh|bash|curl|wget|bun|python3?|deno)\b[^"]*"/i,
  },
  {
    id: 'SC-BINDING-GYP-EXEC',
    severity: 'critical',
    category: 'supply-chain',
    description: 'node-gyp command-expansion abuse in binding.gyp ("<!(...)" runs a shell command at install time — "Phantom Gyp" technique)',
    pattern: /<!\(\s*(?:node|sh|bash|curl|wget|bun|python3?|\.\/)/i,
  },
  {
    id: 'SC-EXTCONF-EXEC',
    severity: 'high',
    category: 'supply-chain',
    description: 'RubyGems native-extension build hook (extconf.rb) spawning a downloader/interpreter — cross-ecosystem install-time execution',
    pattern: /extconf\.rb[\s\S]{0,200}(?:system|`|exec|spawn)\s*[("'`][^)]*\b(?:curl|wget|bun|node|sh)\b/i,
  },
  {
    id: 'SC-GYPFILE-NO-SOURCE',
    severity: 'medium',
    category: 'supply-chain',
    description: 'gyp target with "type":"none" and a command-expansion source — build produces nothing; the side effect is the payload',
    pattern: /"type"\s*:\s*"none"[\s\S]{0,120}<!\(/i,
  },

  // --- Runtime download / off-Node execution (evasion) -----------------------
  {
    id: 'SC-BUN-DOWNLOAD',
    severity: 'high',
    category: 'supply-chain',
    description: 'Download of the Bun runtime from release infrastructure (family reuses Bun to run the real payload off the Node process)',
    pattern: /(?:github\.com\/oven-sh\/bun\/releases|release-assets\.githubusercontent\.com[^\s"']*bun-(?:linux|darwin|windows)|bun-(?:linux|darwin|windows)-(?:x64|aarch64|arm64)\.zip)/i,
  },
  {
    id: 'SC-DOWNLOAD-PIPE-SHELL',
    severity: 'high',
    category: 'supply-chain',
    description: 'Remote script piped straight into a shell (curl|wget … | sh/bash)',
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|node|bun|python3?)\b/i,
  },
  {
    id: 'SC-EVAL-CHARCODE',
    severity: 'high',
    category: 'supply-chain',
    description: 'eval() over a character-code array / Caesar-rotation wrapper (family\'s outer obfuscation layer)',
    pattern: /eval\s*\([^)]{0,200}(?:String\.fromCharCode|fromCharCode|charCodeAt)|eval\s*\(\s*function\s*\([a-z],\s*[a-z]\)\s*\{\s*return[\s\S]{0,80}replace\([\s\S]{0,80}[a-zA-Z]\)/i,
  },
  {
    id: 'SC-INLINE-AES-DECRYPT',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Inline self-decrypting layer: createDecipheriv with hardcoded aes-128/256-gcm key material (family\'s second stage)',
    pattern: /createDecipheriv\s*\(\s*["']aes-(?:128|256)-gcm["']/i,
  },

  // --- Privilege escalation / defense evasion --------------------------------
  {
    id: 'SC-SUDOERS-NOPASSWD',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Passwordless-sudo rule injection (privilege escalation)',
    pattern: /NOPASSWD\s*:\s*ALL/i,
  },
  {
    id: 'SC-DOCKER-BREAKOUT',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Privileged-container host filesystem mount for breakout (docker run --privileged -v /:/host …)',
    pattern: /docker\s+run[^\n]*--privileged[^\n]*-v\s*\/:\/host|-v\s*\/:\/host[^\n]*--privileged/i,
  },
  {
    id: 'SC-RUNNER-MEMORY-SCRAPE',
    severity: 'critical',
    category: 'supply-chain',
    description: 'CI runner process-memory scraping to unmask secrets ("isSecret":true grep / Runner.Worker)',
    pattern: /isSecret\\?"\s*:\s*true|Runner\.Worker/,
  },
  {
    id: 'SC-ETC-HOSTS-BLOCK',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Security-product neutralization via /etc/hosts redirection',
    pattern: /echo\s+['"]?127\.0\.0\.1[^'"\n]*['"]?\s*>>\s*\/etc\/hosts/i,
  },

  // --- Credential access -----------------------------------------------------
  {
    id: 'SC-METADATA-ENDPOINT',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Cloud instance-metadata endpoint access (IMDS credential harvesting across AWS/Azure/GCP)',
    pattern: /169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal/i,
  },
  {
    id: 'SC-CRED-FILE-SWEEP',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Sweep of local credential files (.ssh, .aws, .npmrc, .pypirc, .netrc, wallet, kube/docker configs, password-manager stores)',
    pattern: /(?:\.ssh\/id_|\.aws\/credentials|\.npmrc|\.pypirc|\.netrc|\.claude\.json|wallet\.dat|\.kube\/config|\.docker\/config\.json|\.config\/gopass|\.password-store).{0,140}(?:\.ssh\/id_|\.aws\/credentials|\.npmrc|\.pypirc|\.netrc|\.claude\.json|wallet\.dat|\.kube\/config|\.docker\/config\.json|\.config\/gopass|\.password-store)/is,
  },
  {
    id: 'SC-TRUFFLEHOG',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Invocation or installation of a secret-scanner (trufflehog) to find credentials to steal — recurring family TTP. Matches execution/installation, not mere mentions.',
    pattern: /\btrufflehog\b\s+(?:filesystem|git\b|github|gitlab|s3|gcs|docker|jenkins|--)|(?:npx|pip3?\s+install|brew\s+install|go\s+install|curl[^\n]*|wget[^\n]*)\s+[^\n]*trufflehog/i,
  },
  {
    id: 'SC-NPM-TOKEN-ENUM',
    severity: 'medium',
    category: 'supply-chain',
    description: 'npm token/identity enumeration endpoints (/-/whoami, /-/npm/v1/tokens)',
    pattern: /registry\.npmjs\.org\/-\/(?:whoami|npm\/v1\/tokens)/i,
  },
  {
    id: 'SC-MAINTAINER-ENUM',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Enumeration of a maintainer\'s packages for worm targeting (registry search text=maintainer:)',
    pattern: /registry\.npmjs\.org\/-\/v1\/search\?[^"'\s]*text=maintainer:/i,
  },

  // --- Worm propagation & persistence ----------------------------------------
  {
    id: 'SC-WORKFLOW-INJECTION',
    severity: 'high',
    category: 'supply-chain',
    description: 'Injected GitHub Actions workflow that echoes attacker-controllable event data into a run step (command injection / C2)',
    pattern: /run:\s*echo\s*\$\{\{\s*github\.event\.(?:discussion|issue|comment|pull_request)\.[a-z_.]*body[^}]*\}\}/i,
  },
  {
    id: 'SC-SELF-HOSTED-RUNNER-REG',
    severity: 'high',
    category: 'supply-chain',
    description: 'Registration of a rogue self-hosted GitHub Actions runner (persistence / C2)',
    pattern: /config\.(?:sh|cmd)\s+--url[\s\S]{0,120}--token|RUNNER_TRACKING_ID\s*[:=]\s*0/i,
  },
  {
    id: 'SC-AGENT-PERSISTENCE-HOOK',
    severity: 'high',
    category: 'supply-chain',
    description: 'Payload written into AI-agent / editor auto-run hooks that re-execute on project open (.claude/, .cursor/rules/, .vscode/tasks.json runOn folderOpen) — survives npm uninstall',
    pattern: /\.cursor[\/\\]rules[\/\\]|\.vscode[\/\\]tasks\.json|"runOn"\s*:\s*"folderOpen"|\.claude[\/\\](?:settings\.json|hooks|setup)/i,
  },
  {
    id: 'SC-SETUP-JS-WORM',
    severity: 'high',
    category: 'supply-chain',
    description: 'Worm self-injection into a repo bootstrap file (.github/setup.js and similar) via the Git Data API',
    pattern: /\.github[\/\\]setup\.js/i,
  },
  {
    id: 'SC-SLSA-FORGERY',
    severity: 'high',
    category: 'supply-chain',
    description: 'Forged provenance: programmatic Sigstore/Fulcio/Rekor attestation to make republished packages look legitimately signed',
    pattern: /(?:fulcio|rekor)\.sigstore\.dev|sigstore[\s\S]{0,60}(?:attest|provenance)/i,
  },
  {
    id: 'SC-EXFIL-RESULTS-JSON',
    severity: 'high',
    category: 'supply-chain',
    description: 'Exfiltration dead-drop artifact path (results/results-<timestamp>.json or results/<timestamp>-<n>.json) committed to an attacker repo',
    pattern: /results\/(?:results-)?\d{9,14}(?:-\d+)?\.json/i,
  },
  {
    id: 'SC-UA-SPOOF',
    severity: 'low',
    category: 'supply-chain',
    description: 'python-requests User-Agent spoofing from a non-Python process (family exfil signature)',
    pattern: /python-requests\/\d/i,
  },
  {
    id: 'SC-HOME-WIPE',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Destructive home-directory wipe (rm -rf ~/) — family fail-safe / wiper',
    pattern: /rm\s+-rf\s+~\/?(?:\s|$|["'&;])|rm\s+-rf\s+(?:"?\$HOME"?|\/root)\b/,
  },
  {
    id: 'SC-GIT-COMMIT-DEP',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Dependency pinned to a raw git commit / attacker fork (used to stage payload — e.g. optionalDependencies to a fork commit)',
    pattern: /["'][^"']+["']\s*:\s*["'](?:git\+)?(?:https?:\/\/|git@)github\.com[^"']+#[0-9a-f]{7,40}["']/i,
  },

  // --- Prompt-injection patterns (agent manipulation via PR/issue text) ------
  {
    id: 'PI-IGNORE-INSTRUCTIONS',
    severity: 'high',
    category: 'prompt-injection',
    description: 'Instruction-override attempt ("ignore previous/above/all instructions")',
    pattern: /(?:ignore|disregard|forget)\s+(?:all\s+|your\s+|any\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions|prompts?|rules|guidelines|context)/i,
  },
  {
    id: 'PI-AGENT-DIRECTIVE',
    severity: 'high',
    category: 'prompt-injection',
    description: 'Direct instruction addressed to an AI/coding agent embedded in content',
    pattern: /(?:^|\n|<!--)\s*(?:(?:hey|dear|attention|note\s+to)\s+)?(?:(?:ai|llm|claude|copilot|cursor|codex)(?:\s+a(?:ssistant|gent))?|(?:coding\s+)?a(?:ssistant|gent))\s*[:,].{0,200}?(?:run|execute|install|download|curl|fetch|ignore|disregard|do\s+not\s+tell)/is,
  },
  {
    id: 'PI-HIDDEN-COMMENT-CMD',
    severity: 'medium',
    category: 'prompt-injection',
    description: 'HTML comment containing execution/download instructions (hidden from rendered view)',
    pattern: /<!--(?:(?!-->)[\s\S]){0,400}?(?:curl|wget|npm\s+install|npx\s|bash\s|sh\s+-c|eval|execute|run\s+the\s+following)(?:(?!-->)[\s\S])*?-->/i,
  },
  {
    id: 'PI-CONCEALMENT',
    severity: 'high',
    category: 'prompt-injection',
    description: 'Instruction to conceal actions from the user ("do not tell/inform the user", "without mentioning")',
    pattern: /(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|mention\s+(?:this\s+)?to|alert|show|reveal\s+(?:this\s+)?to)\s+(?:the\s+)?(?:user|human|owner|developer)/i,
  },
  {
    id: 'PI-UNICODE-TRICKERY',
    severity: 'medium',
    category: 'prompt-injection',
    description: 'Invisible/bidirectional Unicode characters (content hiding or trojan-source style spoofing)',
    // U+202A-202E bidi overrides, U+2066-2069 isolates, U+200B-200F zero-width,
    // U+FEFF BOM, U+E0000-E007F tag characters
    pattern: new RegExp('[\\u202A-\\u202E\\u2066-\\u2069\\u200B-\\u200F\\uFEFF]|\\uDB40[\\uDC00-\\uDC7F]', 'u'),
  },
  {
    id: 'PI-SYSTEM-PROMPT-PROBE',
    severity: 'medium',
    category: 'prompt-injection',
    description: 'Attempt to extract or override the system prompt',
    pattern: /(?:reveal|print|repeat|output|show)\s+(?:your\s+)?system\s+prompt|new\s+system\s+prompt\s*:/i,
  },
];

/**
 * Build the active ruleset by merging generic rules with campaign packs.
 * @param {Array} extraPacks - additional IOC packs (e.g. from --ioc-pack).
 * @returns {{COMPROMISED_PACKAGES, MALICIOUS_SHA256, TEXT_RULES, campaigns}}
 */
function buildRules(extraPacks) {
  const merged = mergePacks(extraPacks);
  return {
    COMPROMISED_PACKAGES: merged.packages,
    MALICIOUS_SHA256: merged.hashes,
    // Campaign-specific rules first (more specific), then generic techniques.
    TEXT_RULES: merged.rules.concat(GENERIC_RULES),
    campaigns: merged.packNames,
  };
}

// Default export: generic rules + built-in packs, no extras.
const _default = buildRules();

module.exports = {
  GENERIC_RULES,
  buildRules,
  COMPROMISED_PACKAGES: _default.COMPROMISED_PACKAGES,
  MALICIOUS_SHA256: _default.MALICIOUS_SHA256,
  TEXT_RULES: _default.TEXT_RULES,
  campaigns: _default.campaigns,
};
