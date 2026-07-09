'use strict';

/**
 * Campaign pack: Miasma (June 2026)
 * Source: Microsoft Security Blog 2026-06-02, Snyk "Node-gyp Supply Chain
 * Compromise" 2026-06-04. Part of the Shai-Hulud worm lineage.
 *
 * Pack format (also accepted as external JSON via --ioc-pack):
 *   name       - campaign label
 *   packages   - { "pkg-name": ["bad-version", ...] }
 *   hashes     - [sha256, ...] of known-malicious files
 *   rules      - text rules; `pattern` may be a RegExp or {source, flags}
 */

module.exports = {
  name: 'miasma',

  packages: {
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
    // June 2026 node-gyp ("Phantom Gyp") wave — same campaign, second cluster.
    // Highest-traffic victims per Snyk; full list at
    // https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026
    '@vapi-ai/server-sdk': ['0.11.1', '0.11.2', '1.2.1', '1.2.2'],
    'ai-sdk-ollama': ['0.13.1', '1.1.1', '2.2.1', '3.8.5'],
    'autotel': ['2.26.4', '3.4.3'],
    'awaitly': ['1.33.3'],
  },

  hashes: [
    '396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4',
    'd8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223',
    'f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c',
    'd5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b',
    'f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f',
    '25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b',
  ],

  rules: [
    {
      id: 'MIASMA-MARKER',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'Miasma campaign marker string ("Miasma: The Spreading Blight")',
      pattern: /miasma[:\s_-]{1,3}the\s+spreading\s+blight/i,
    },
    {
      id: 'MIASMA-HONEYTOKEN',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'Miasma destructive-tripwire honeytoken string',
      pattern: /IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner/i,
    },
    {
      id: 'MIASMA-CLAUDE-SETUP-MJS',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'Confirmed malware signature: agent-hook command running node .claude/setup.mjs (per InfoSec advisory — do not interact further; report immediately)',
      pattern: /node\s+\.claude[\/\\]setup\.mjs/i,
    },
    {
      id: 'MIASMA-WORM-COMMIT',
      severity: 'high',
      category: 'campaign-ioc',
      description: 'Miasma worm commit signature: "chore: update dependencies [skip ci]" (spoofed github-actions author)',
      pattern: /chore:\s*update\s+dependencies\s*\[skip\s*ci\]/i,
    },
  ],
};
