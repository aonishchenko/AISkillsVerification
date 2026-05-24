import type { Rule, Finding } from '../index';
import { lineOf } from '../index';

const PATTERNS: Array<{ id: string; regex: RegExp; severity: 'low' | 'medium' | 'high' | 'critical'; reason: string; exts?: string[] }> = [
  {
    id: 'mal-curl-pipe-sh',
    regex: /curl\s+[^\n|]*\|\s*(sh|bash|zsh|python|node)/,
    severity: 'critical',
    reason: 'Pipes remote content directly to a shell or interpreter. Anyone controlling that URL can run arbitrary code.',
  },
  {
    id: 'mal-wget-pipe-sh',
    regex: /wget\s+[^\n|]*-O\s*-\s*\|\s*(sh|bash|zsh|python|node)/,
    severity: 'critical',
    reason: 'Pipes remote content directly to a shell.',
  },
  {
    id: 'mal-eval-network',
    regex: /eval\s*\(\s*(await\s+)?(fetch|urlopen|requests\.get|requests\.post)/i,
    severity: 'critical',
    reason: 'Evaluates code fetched from the network at runtime.',
  },
  {
    id: 'mal-exec-decode',
    regex: /(exec|eval)\s*\(\s*(base64\.b64decode|atob|Buffer\.from\([^)]*['"]base64)/,
    severity: 'high',
    reason: 'Executes base64-decoded content. Common obfuscation pattern.',
  },
  {
    id: 'mal-os-system',
    regex: /os\.system\s*\(/,
    severity: 'medium',
    reason: 'Uses os.system. Higher-level subprocess APIs with shell=False are safer.',
    exts: ['.py'],
  },
  {
    id: 'mal-subprocess-shell-true',
    regex: /subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/,
    severity: 'high',
    reason: 'subprocess with shell=True allows command injection if any argument is user-controlled.',
    exts: ['.py'],
  },
  {
    id: 'mal-child-process-shell',
    regex: /child_process\.(exec|execSync)\s*\(/,
    severity: 'medium',
    reason: 'Node `exec`/`execSync` invokes a shell. Prefer `execFile` with separate arguments.',
    exts: ['.js', '.ts', '.mjs', '.cjs'],
  },
  {
    id: 'mal-rm-rf-root',
    regex: /\brm\s+-rf\s+(\/(?:\s|$)|~\b|\$HOME\b)/,
    severity: 'critical',
    reason: 'Destructive recursive delete near the filesystem root or home directory.',
  },
  {
    id: 'mal-fork-bomb',
    regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}/,
    severity: 'critical',
    reason: 'Classic shell fork-bomb signature.',
  },
];

function extOf(p: string): string {
  const i = p.lastIndexOf('.');
  return i < 0 ? '' : p.slice(i).toLowerCase();
}

export const maliciousRules: Rule[] = [
  {
    id: 'malicious-code-patterns',
    category: 'malicious',
    defaultSeverity: 'high',
    description: 'Heuristics for dangerous code patterns in helper scripts.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      for (const f of ctx.files) {
        const ext = extOf(f.path);
        for (const p of PATTERNS) {
          if (p.exts && !p.exts.includes(ext)) continue;
          const re = new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g');
          let m: RegExpExecArray | null;
          while ((m = re.exec(f.text))) {
            findings.push({
              ruleId: p.id,
              category: 'malicious',
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
