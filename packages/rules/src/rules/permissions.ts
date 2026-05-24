import type { Rule, Finding } from '../index';

const HIGH_RISK_TOOLS = new Set([
  'bash', 'shell', 'exec', 'subprocess',
  'fetch', 'http', 'requests',
  'filesystem', 'fs', 'write_file', 'delete_file',
  'browser', 'puppeteer', 'playwright',
  'email', 'sms', 'send_message',
]);

export const permissionsRules: Rule[] = [
  {
    id: 'perm-broad-tool-list',
    category: 'permissions',
    defaultSeverity: 'low',
    description: 'Flags skills declaring an unusually large or high-risk toolset.',
    detect: (ctx) => {
      const skill = ctx.skill;
      if (!skill?.tools || skill.tools.length === 0) return [];
      const findings: Finding[] = [];
      if (skill.tools.length > 8) {
        findings.push({
          ruleId: 'perm-broad-tool-list',
          category: 'permissions',
          severity: 'medium',
          explanation: `Skill declares ${skill.tools.length} tools. A large permission surface increases blast radius if the skill is compromised.`,
          evidence: { count: skill.tools.length, tools: skill.tools },
        });
      }
      const risky = skill.tools.filter((t) => HIGH_RISK_TOOLS.has(t.toLowerCase()));
      if (risky.length >= 3) {
        findings.push({
          ruleId: 'perm-high-risk-combo',
          category: 'permissions',
          severity: 'high',
          explanation: `Skill combines multiple high-risk tools (${risky.join(', ')}). Combinations like shell + fetch + filesystem enable RCE-with-exfil.`,
          evidence: { risky },
        });
      }
      return findings;
    },
  },
  {
    id: 'perm-broad-fs-glob',
    category: 'permissions',
    defaultSeverity: 'medium',
    description: 'Detects broad filesystem globs in SKILL.md or scripts.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      const broad = /(^|[\s"'`])(\/|~\/|\$HOME\/?|\.\.\/?)?\*\*\/\*/;
      for (const f of ctx.files) {
        const m = f.text.match(broad);
        if (m && typeof m.index === 'number') {
          findings.push({
            ruleId: 'perm-broad-fs-glob',
            category: 'permissions',
            severity: 'medium',
            explanation: 'Broad filesystem glob (e.g. **/*) detected. Limit to the smallest necessary scope.',
            filePath: f.path,
            snippet: m[0].slice(0, 80),
          });
        }
      }
      return findings;
    },
  },
];
