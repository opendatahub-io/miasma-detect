'use strict';

/**
 * Campaign pack: Shai-Hulud worm family (Sept 2025 – present)
 * Covers Shai-Hulud v1 (Sept 2025), Sha1-Hulud 2.0 "The Second Coming"
 * (Nov 2025), and the Mini Shai-Hulud / TanStack wave (2026). Miasma is
 * the June 2026 descendant (see miasma.js).
 *
 * Sources: Unit 42, Wiz, Microsoft, StepSecurity, Snyk public analyses.
 *
 * The compromised-package lists for these waves run to hundreds of entries
 * and are maintained by registries/vendors; this pack carries the durable
 * markers, filenames, and hashes. Add package pins via a custom --ioc-pack
 * if you need them.
 */

module.exports = {
  name: 'shai-hulud',

  packages: {},

  hashes: [
    // router_init.js — identical across all compromised @tanstack packages
    'ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c',
  ],

  rules: [
    {
      id: 'SHAIHULUD-MARKER',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'Shai-Hulud family campaign marker ("Shai-Hulud", "Sha1-Hulud: The Second Coming", migration repos)',
      pattern: /sha[i1][-\s]?hulud/i,
    },
    {
      id: 'SHAIHULUD-WORKFLOW',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'Shai-Hulud injected workflow filename (shai-hulud-workflow.yml)',
      pattern: /shai-hulud(?:-workflow)?\.ya?ml/i,
    },
    {
      id: 'SHAIHULUD-PAYLOAD-FILES',
      severity: 'high',
      category: 'campaign-ioc',
      description: 'Sha1-Hulud 2.0 payload filenames (setup_bun.js, bun_environment.js) or TanStack-wave payload (router_init.js)',
      pattern: /setup_bun\.js|bun_environment\.js|router_init\.js/i,
    },
    {
      id: 'SHAIHULUD-EXFIL-FILES',
      severity: 'high',
      category: 'campaign-ioc',
      description: 'Sha1-Hulud 2.0 exfiltration artifact filenames (truffleSecrets.json, actionsSecrets.json)',
      pattern: /truffleSecrets\.json|actionsSecrets\.json/i,
    },
    {
      id: 'SHAIHULUD-DISCUSSION-BACKDOOR',
      severity: 'critical',
      category: 'campaign-ioc',
      description: 'Sha1-Hulud 2.0 discussion.yaml backdoor: self-hosted workflow echoing discussion body (command injection C2)',
      pattern: /runs-on:\s*self-hosted[\s\S]{0,300}\$\{\{\s*github\.event\.discussion\.body\s*\}\}/i,
    },
  ],
};
