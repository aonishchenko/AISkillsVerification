import type { Rule, Finding } from '../index';
import { lineOf } from '../index';

const INJECTION_PATTERNS: Array<{ id: string; regex: RegExp; severity: 'low' | 'medium' | 'high' | 'critical'; reason: string }> = [
  {
    id: 'inj-ignore-previous',
    regex: /ignore\s+(?:(?:all|any)\s+)?(?:(?:previous|prior|above|system|developer|user|assistant|safety)\s+(?:or\s+)?)*(instructions?|prompts?|directives?|rules?)/i,
    severity: 'high',
    reason: 'Classic prompt-override phrasing; instructs the model to disregard system or earlier instructions.',
  },
  {
    id: 'inj-hidden-output',
    regex: /(do\s+not|don't)\s+(mention|tell|disclose|reveal|show)[^\n]{0,80}\b(user|operator|reviewer)\b/i,
    severity: 'high',
    reason: 'Instruction attempts to hide behavior from the user or reviewer.',
  },
  {
    id: 'inj-system-impersonation',
    regex: /(^|\n)\s*(system|assistant)\s*:/i,
    severity: 'medium',
    reason: 'Skill body contains lines that mimic system/assistant role headers, which can confuse role-aware models.',
  },
  {
    id: 'inj-real-task-override',
    regex: /your\s+(real|actual|true)\s+(task|job|goal|instruction)/i,
    severity: 'high',
    reason: 'Override phrasing used to redirect the model away from its assigned task.',
  },
  {
    id: 'inj-output-only',
    regex: /(only|just)\s+(output|reply|respond|return)\s+(with|the\s+text|exactly)/i,
    severity: 'low',
    reason: 'Output-coercion pattern; can be benign but is commonly used in injections.',
  },
  {
    id: 'inj-tag-smuggling',
    // Unicode tag characters (U+E0000–U+E007F) are invisible and can carry hidden directives.
    regex: /[\u{E0000}-\u{E007F}]/u,
    severity: 'critical',
    reason: 'Invisible Unicode tag characters detected. These can smuggle hidden instructions invisible to humans.',
  },
  {
    id: 'inj-base64-directive',
    regex: /base64[^a-zA-Z0-9]{0,10}[A-Za-z0-9+/=]{40,}/i,
    severity: 'medium',
    reason: 'Base64-encoded payload near the word "base64". Often used to hide instructions from review.',
  },
  {
    id: 'inj-hidden-html',
    regex: /<(span|div|p)\s+[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*(white|#fff))/i,
    severity: 'high',
    reason: 'HTML element styled to be invisible. Common technique for hiding adversarial instructions in rendered content.',
  },
  {
    id: 'inj-jailbreak-personas',
    regex: /\b(DAN|do anything now|developer mode|godmode|jailbroken)\b/i,
    severity: 'medium',
    reason: 'References a well-known jailbreak persona/keyword.',
  },
];

function scanText(file: { path: string; text: string }): Finding[] {
  const findings: Finding[] = [];
  for (const p of INJECTION_PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.text))) {
      const idx = m.index;
      findings.push({
        ruleId: p.id,
        category: 'injection',
        severity: p.severity,
        explanation: p.reason,
        filePath: file.path,
        lineStart: lineOf(file.text, idx),
        snippet: m[0].slice(0, 160),
      });
      if (re.lastIndex === idx) re.lastIndex++; // avoid zero-width infinite loop
    }
  }
  return findings;
}

export const injectionRules: Rule[] = [
  {
    id: 'injection-patterns',
    category: 'injection',
    defaultSeverity: 'medium',
    description: 'Pattern-based prompt-injection detector across all source files in the bundle.',
    detect: (ctx) => ctx.files.flatMap(scanText),
  },
];
