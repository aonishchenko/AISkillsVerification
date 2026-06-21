import type { Rule, Finding, Severity } from '../index';
import { lineOf } from '../index';

const SECRET_ACCESS_PATTERNS: Array<{ id: string; regex: RegExp; severity: Severity; reason: string; requiresAccessIntent?: boolean }> = [
  {
    id: 'sec-env-aws',
    regex: /\b(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/,
    severity: 'high',
    reason: 'References AWS credential environment variable. Skill should not be reading cloud credentials.',
  },
  {
    id: 'sec-env-gcp',
    regex: /\b(GOOGLE_APPLICATION_CREDENTIALS|GCP_SERVICE_ACCOUNT_KEY)\b/,
    severity: 'high',
    reason: 'References GCP credential environment variable.',
  },
  {
    id: 'sec-keyring',
    regex: /\b(keyring\.get_password|security\s+find-generic-password|secretstorage)\b/i,
    severity: 'high',
    reason: 'Reads from the OS keyring / Keychain — typical credential-harvest pattern.',
  },
  {
    id: 'sec-dotfile-read',
    regex: /(\.aws\/credentials|\.ssh\/id_(rsa|ed25519|dsa)|\.netrc|\.npmrc|\.docker\/config\.json|\.kube\/config)/,
    severity: 'critical',
    reason: 'Accesses a known credential file path. Highly suspicious.',
    requiresAccessIntent: true,
  },
  {
    id: 'sec-browser-cookies',
    regex: /(Cookies|Login Data|key3\.db|logins\.json|key4\.db)/,
    severity: 'critical',
    reason: 'Reads browser cookie/credential stores.',
  },
  {
    id: 'sec-gh-token',
    regex: /\b(GITHUB_TOKEN|GH_TOKEN|gh\s+auth\s+token)\b/,
    severity: 'medium',
    reason: 'References GitHub token. Verify scope/intent.',
  },
  {
    id: 'sec-process-env-broad',
    regex: /(process\.env|os\.environ)\s*(\.|$|\[\s*["']?$)/,
    severity: 'info',
    reason: 'Reads from process environment. Common but worth a glance; flag higher if combined with outbound calls.',
  },
];

export const secretsRules: Rule[] = [
  {
    id: 'secrets-patterns',
    category: 'secrets',
    defaultSeverity: 'medium',
    description: 'Detects access to common credential storage locations and env vars.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      for (const f of ctx.files) {
        for (const p of SECRET_ACCESS_PATTERNS) {
          const re = new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g');
          let m: RegExpExecArray | null;
          while ((m = re.exec(f.text))) {
            if (p.requiresAccessIntent && !hasAccessIntent(f.text, m.index, m[0].length)) continue;
            findings.push({
              ruleId: p.id,
              category: 'secrets',
              severity: p.severity,
              explanation: p.reason,
              filePath: f.path,
              lineStart: lineOf(f.text, m.index),
              snippet: m[0].slice(0, 160),
            });
            if (re.lastIndex === m.index) re.lastIndex++;
          }
        }
      }
      return findings;
    },
  },
];

function hasAccessIntent(text: string, index: number, length: number): boolean {
  const lineStart = text.lastIndexOf('\n', index) + 1;
  const nextLine = text.indexOf('\n', index + length);
  const line = text.slice(lineStart, nextLine === -1 ? text.length : nextLine);
  return /\b(read|load|open|copy|collect|extract|upload|send|forward|steal|exfiltrate|cat|type|get-content)\b|\b(?:readFile|readFileSync|read_text|getText|openSync)\s*\(/i.test(line);
}
