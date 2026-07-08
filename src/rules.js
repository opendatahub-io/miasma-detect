'use strict';

/**
 * Detection rules for the Miasma npm supply-chain campaign
 * (Microsoft Security Blog, 2026-06-02: "Preinstall to persistence:
 * Inside the Red Hat npm Miasma credential-stealing campaign")
 * plus generic supply-chain heuristics and prompt-injection patterns.
 *
 * Severities:
 *   critical - confirmed Miasma IOC; block immediately
 *   high     - strong supply-chain attack indicator
 *   medium   - suspicious; likely worth blocking for unattended agents
 *   low      - informational heuristic
 */

// ---------------------------------------------------------------------------
// Confirmed-malicious package versions under @redhat-cloud-services
// ---------------------------------------------------------------------------
const COMPROMISED_PACKAGES = {
  '@redhat-cloud-services/types': ['3.6.1', '3.6.2', '3.6.4'],
  '@redhat-cloud-services/frontend-components-utilities': ['7.4.1', '7.4.2', '7.4.4'],
  '@redhat-cloud-services/frontend-components': ['7.7.2', '7.7.3', '7.7.5'],
  '@redhat-cloud-services/rbac-client': ['9.0.3', '9.0.4', '9.0.6'],
  '@redhat-cloud-services/javascript-clients-shared': ['2.0.8', '2.0.9', '2.0.11'],
  '@redhat-cloud-services/frontend-components-config-utilities': ['4.11.2', '4.11.3', '4.11.5'],
  '@redhat-cloud-services/frontend-components-notifications': ['6.9.2', '6.9.3', '6.9.5'],
  '@redhat-cloud-services/tsc-transform-imports': ['1.2.2', '1.2.4', '1.2.6'],
  '@redhat-cloud-services/frontend-components-config': ['6.11.3', '6.11.4', '6.11.6'],
  '@redhat-cloud-services/eslint-config-redhat-cloud-services': ['3.2.1', '3.2.2', '3.2.4'],
  '@redhat-cloud-services/host-inventory-client': ['5.0.3', '5.0.4', '5.0.6'],
  '@redhat-cloud-services/rule-components': ['4.7.2', '4.7.3', '4.7.5'],
  '@redhat-cloud-services/frontend-components-remediations': ['4.9.2', '4.9.3', '4.9.5'],
  '@redhat-cloud-services/frontend-components-translations': ['4.4.1', '4.4.2', '4.4.4'],
  '@redhat-cloud-services/vulnerabilities-client': ['2.1.9', '2.1.11'],
  '@redhat-cloud-services/frontend-components-advisor-components': ['3.8.2', '3.8.4', '3.8.6'],
  '@redhat-cloud-services/entitlements-client': ['4.0.11', '4.0.12', '4.0.14'],
  '@redhat-cloud-services/chrome': ['2.3.1', '2.3.2', '2.3.4'],
  '@redhat-cloud-services/notifications-client': ['6.1.4', '6.1.5', '6.1.7'],
  '@redhat-cloud-services/compliance-client': ['4.0.3', '4.0.4', '4.0.6'],
  '@redhat-cloud-services/sources-client': ['3.0.10', '3.0.11', '3.0.13'],
  '@redhat-cloud-services/integrations-client': ['6.0.4', '6.0.5', '6.0.7'],
  '@redhat-cloud-services/frontend-components-testing': ['1.2.1', '1.2.2', '1.2.4'],
  '@redhat-cloud-services/remediations-client': ['4.0.4', '4.0.5', '4.0.7'],
  '@redhat-cloud-services/insights-client': ['4.0.4', '4.0.5', '4.0.7'],
  '@redhat-cloud-services/topological-inventory-client': ['3.0.10', '3.0.11', '3.0.13'],
  '@redhat-cloud-services/config-manager-client': ['5.0.4', '5.0.5', '5.0.7'],
  '@redhat-cloud-services/hcc-pf-mcp': ['0.6.1', '0.6.2', '0.6.4'],
  '@redhat-cloud-services/quickstarts-client': ['4.0.11', '4.0.12', '4.0.14'],
  '@redhat-cloud-services/patch-client': ['4.0.4', '4.0.5', '4.0.7'],
  '@redhat-cloud-services/hcc-feo-mcp': ['0.3.1', '0.3.2', '0.3.4'],
  '@redhat-cloud-services/hcc-kessel-mcp': ['0.3.1', '0.3.2', '0.3.4'],
};

// ---------------------------------------------------------------------------
// Known-malicious file hashes (index.js droppers)
// ---------------------------------------------------------------------------
const MALICIOUS_SHA256 = [
  '396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4',
  'd8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223',
  'f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c',
  'd5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b',
  'f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f',
  '25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b',
];

// ---------------------------------------------------------------------------
// Text/pattern rules. Each: { id, severity, category, description, pattern }
// Patterns are applied per-input with the `gi` flags unless noted.
// ---------------------------------------------------------------------------
const TEXT_RULES = [
  // --- Confirmed Miasma IOCs -------------------------------------------------
  {
    id: 'MIASMA-MARKER',
    severity: 'critical',
    category: 'miasma-ioc',
    description: 'Miasma campaign marker string ("Miasma: The Spreading Blight")',
    pattern: /miasma[:\s_-]{1,3}the\s+spreading\s+blight/i,
  },
  {
    id: 'MIASMA-HONEYTOKEN',
    severity: 'critical',
    category: 'miasma-ioc',
    description: 'Miasma destructive-tripwire honeytoken string',
    pattern: /IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner/i,
  },
  {
    id: 'MIASMA-HASH',
    severity: 'critical',
    category: 'miasma-ioc',
    description: 'Known-malicious Miasma dropper SHA256 hash',
    pattern: new RegExp(MALICIOUS_SHA256.join('|'), 'i'),
  },
  {
    id: 'MIASMA-SETUPJS-WORM',
    severity: 'critical',
    category: 'miasma-ioc',
    description: 'Worm self-injection path (.github/setup.js) used by Miasma Channel B propagation',
    pattern: /\.github[\/\\]setup\.js/i,
  },
  {
    id: 'MIASMA-WORM-COMMIT',
    severity: 'high',
    category: 'miasma-ioc',
    description: 'Miasma worm commit signature: "chore: update dependencies [skip ci]" (spoofed github-actions author)',
    pattern: /chore:\s*update\s+dependencies\s*\[skip\s*ci\]/i,
  },
  {
    id: 'MIASMA-EXFIL-RESULTS',
    severity: 'high',
    category: 'miasma-ioc',
    description: 'Miasma exfiltration artifact path (results/<timestamp>-<counter>.json in drop repo)',
    pattern: /results\/\d{9,14}-\d+\.json/i,
  },
  {
    id: 'MIASMA-CLAUDE-STAGE',
    severity: 'high',
    category: 'miasma-ioc',
    description: 'Second-stage execution via "bun run .claude/" (Miasma persistence)',
    pattern: /bun\s+run\s+\.claude[\/\\]/i,
  },

  // --- Generic supply-chain heuristics --------------------------------------
  {
    id: 'SC-PREINSTALL-NODE',
    severity: 'high',
    category: 'supply-chain',
    description: 'npm lifecycle hook (pre/post/install) executing a script — primary Miasma delivery vector',
    pattern: /"(?:pre|post)?install"\s*:\s*"(?:[^"]*\b(?:node|sh|bash|curl|wget|bun)\b[^"]*)"/i,
  },
  {
    id: 'SC-BUN-DOWNLOAD',
    severity: 'high',
    category: 'supply-chain',
    description: 'Download of the Bun runtime from release infrastructure (used to evade Node-focused monitoring)',
    pattern: /(?:github\.com\/oven-sh\/bun\/releases|release-assets\.githubusercontent\.com[^\s"']*bun-(?:linux|darwin|windows)|bun-(?:linux|darwin|windows)-(?:x64|aarch64|arm64)\.zip)/i,
  },
  {
    id: 'SC-EVAL-CHARCODE',
    severity: 'high',
    category: 'supply-chain',
    description: 'eval() combined with character-code array reconstruction (ROT/Caesar obfuscation wrapper)',
    pattern: /eval\s*\([^)]{0,200}(?:String\.fromCharCode|fromCharCode|charCodeAt)/i,
  },
  {
    id: 'SC-SUDOERS-NOPASSWD',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Passwordless-sudo rule injection (privilege escalation)',
    pattern: /NOPASSWD\s*:\s*ALL/i,
  },
  {
    id: 'SC-RUNNER-MEMORY-SCRAPE',
    severity: 'critical',
    category: 'supply-chain',
    description: 'GitHub Actions runner memory scraping for secrets (isSecret":true grep pattern)',
    pattern: /isSecret\\?":\s*true|Runner\.Worker/,
  },
  {
    id: 'SC-METADATA-ENDPOINT',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Cloud instance-metadata endpoint access (IMDS credential harvesting)',
    pattern: /169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal/i,
  },
  {
    id: 'SC-HOME-WIPE',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Destructive home-directory wipe command (rm -rf ~/)',
    pattern: /rm\s+-rf\s+~\/?(?:\s|$|["'&;])/,
  },
  {
    id: 'SC-DOUBLE-BASE64',
    severity: 'low',
    category: 'supply-chain',
    description: 'Nested/double base64 encoding call (exfiltration obfuscation)',
    pattern: /btoa\s*\(\s*btoa\s*\(|base64\s*\|\s*base64|toString\(['"]base64['"]\)\s*\)\s*,?\s*['"]base64['"]/i,
  },
  {
    id: 'SC-CRED-FILE-SWEEP',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Sweep of local credential files (.ssh, .aws, .npmrc, .claude.json, wallet files, kube/docker configs)',
    pattern: /(?:\.ssh\/id_|\.aws\/credentials|\.npmrc|\.pypirc|\.claude\.json|wallet\.dat|\.kube\/config|\.docker\/config\.json).{0,120}(?:\.ssh\/id_|\.aws\/credentials|\.npmrc|\.pypirc|\.claude\.json|wallet\.dat|\.kube\/config|\.docker\/config\.json)/is,
  },
  {
    id: 'SC-NPM-TOKEN-ENUM',
    severity: 'medium',
    category: 'supply-chain',
    description: 'npm token enumeration endpoints (/-/whoami, /-/npm/v1/tokens)',
    pattern: /registry\.npmjs\.org\/-\/(?:whoami|npm\/v1\/tokens)/i,
  },
  {
    id: 'SC-ETC-HOSTS-BLOCK',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Security-product neutralization via /etc/hosts redirection',
    pattern: /echo\s+['"]?127\.0\.0\.1[^'"\n]*['"]?\s*>>\s*\/etc\/hosts/i,
  },

  // --- Prompt-injection patterns (agent manipulation via PR/issue text) -----
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

module.exports = { COMPROMISED_PACKAGES, MALICIOUS_SHA256, TEXT_RULES };
