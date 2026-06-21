import type { Rule, Finding } from '../index';
import { hasSecretFlowToUrl, lineOf } from '../index';

const SUSPICIOUS_HOST_SHAPES = [
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,                    // bare IPs
  /\b[a-z0-9-]+\.(?:ngrok|trycloudflare|loca\.lt|serveo)\.[a-z]+\b/i,
  /\b(?:webhook\.site|requestbin|pipedream|hookbin|beeceptor|mockbin)\b/i,
  /\bdiscord\.com\/api\/webhooks\b/i,
  /\bhooks\.slack\.com\/services\b/i,
];

const KNOWN_BENIGN_HOSTS = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'huggingface.co',
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
]);

function findUrls(text: string): Array<{ url: string; index: number }> {
  const re = /https?:\/\/[^\s)"'`<>]+/g;
  const out: Array<{ url: string; index: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.push({ url: m[0], index: m.index });
  return out;
}

function hostOf(url: string): string | null {
  try { return new URL(url).host.toLowerCase(); } catch { return null; }
}

export const exfiltrationRules: Rule[] = [
  {
    id: 'exfil-suspicious-host',
    category: 'exfiltration',
    defaultSeverity: 'high',
    description: 'Detects URLs pointing at IPs, tunneling services, request-inspectors, or chat webhooks.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      for (const f of ctx.files) {
        for (const { url, index } of findUrls(f.text)) {
          const host = hostOf(url);
          if (!host) continue;
          if (SUSPICIOUS_HOST_SHAPES.some((re) => re.test(host) || re.test(url))) {
            findings.push({
              ruleId: 'exfil-suspicious-host',
              category: 'exfiltration',
              severity: 'high',
              explanation: `Suspicious destination ${host}. Webhooks, tunneling endpoints, and bare IPs are common exfiltration targets.`,
              filePath: f.path,
              lineStart: lineOf(f.text, index),
              snippet: url.slice(0, 160),
              evidence: { host },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'exfil-data-in-url',
    category: 'exfiltration',
    defaultSeverity: 'medium',
    description: 'URLs with long query strings or template placeholders that would carry user data on outbound requests.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      for (const f of ctx.files) {
        for (const { url, index } of findUrls(f.text)) {
          const host = hostOf(url);
          if (!host || KNOWN_BENIGN_HOSTS.has(host)) continue;
          if (/\?[^\s]{60,}/.test(url) || /[?&#][^\s]*\{[a-zA-Z_][a-zA-Z0-9_]*\}/.test(url)) {
            findings.push({
              ruleId: 'exfil-data-in-url',
              category: 'exfiltration',
              severity: 'medium',
              explanation: 'URL contains a long or templated query string. May be designed to ship user data to a third party.',
              filePath: f.path,
              lineStart: lineOf(f.text, index),
              snippet: url.slice(0, 160),
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'exfil-secret-forwarding',
    category: 'exfiltration',
    defaultSeverity: 'critical',
    description: 'Detects instructions to collect secrets or hidden context and forward them to an external URL.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      for (const f of ctx.files) {
        for (const { url, index } of findUrls(f.text)) {
          const host = hostOf(url);
          if (!host || !hasSecretFlowToUrl(f.text, index, url.length)) continue;
          findings.push({
            ruleId: 'exfil-secret-forwarding',
            category: 'exfiltration',
            severity: 'critical',
            explanation: `Skill appears to collect secrets or hidden context and forward it to ${host}.`,
            filePath: f.path,
            lineStart: lineOf(f.text, index),
            snippet: url.slice(0, 160),
            evidence: { host },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'exfil-image-beacon',
    category: 'exfiltration',
    defaultSeverity: 'high',
    description: 'Markdown/HTML image references with concrete tracking-beacon indicators.',
    detect: (ctx) => {
      const findings: Finding[] = [];
      const imgMd = /!\[[^\]]*\]\((https?:\/\/[^)]+)\)/g;
      const imgHtml = /<img\s+[^>]*src=["'](https?:\/\/[^"']+)["']/gi;
      for (const f of ctx.files) {
        for (const re of [imgMd, imgHtml]) {
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(f.text))) {
            const url = m[1];
            if (!url) continue;
            const host = hostOf(url);
            if (!host || KNOWN_BENIGN_HOSTS.has(host)) continue;
            if (!hasBeaconIndicators(m[0], url)) continue;
            findings.push({
              ruleId: 'exfil-image-beacon',
              category: 'exfiltration',
              severity: 'medium',
              explanation: `Image reference to ${host} has tracking-beacon indicators (for example a tracking path/query or hidden/tiny dimensions).`,
              filePath: f.path,
              lineStart: lineOf(f.text, m.index),
              snippet: m[0].slice(0, 160),
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'external-content-read',
    category: 'permissions',
    defaultSeverity: 'low',
    description: 'Discloses explicit read-only access to external web content without misclassifying it as exfiltration.',
    detect: (ctx) => {
      const skillFile = ctx.files.find((file) => file.path === ctx.signals.skillPath);
      if (!skillFile) return [];
      const destinations = ctx.signals.networkDestinations.filter((destination) => hasExplicitExternalRead(skillFile.text, destination.index));
      const groups = [{ trusted: true, severity: 'low' as const }, { trusted: false, severity: 'medium' as const }];
      const findings: Finding[] = [];
      for (const group of groups) {
        const matches = destinations.filter((destination) => destination.trusted === group.trusted);
        if (matches.length === 0) continue;
        const first = matches[0]!;
        const hosts = Array.from(new Set(matches.map((destination) => destination.host)));
        findings.push({
          ruleId: group.trusted ? 'external-read-trusted' : 'external-read-unknown',
          category: 'permissions',
          severity: group.severity,
          explanation: group.trusted
            ? `Reads public documentation from external host${hosts.length === 1 ? '' : 's'} (${hosts.join(', ')}). No sensitive data forwarding was detected; requests expose ordinary connection metadata and retrieved content must remain untrusted.`
            : `Reads content from untrusted or unclassified external host${hosts.length === 1 ? '' : 's'} (${hosts.join(', ')}). No sensitive data forwarding was detected, but retrieved content can expose request metadata and carry indirect prompt injection.`,
          filePath: skillFile.path,
          lineStart: lineOf(skillFile.text, first.index),
          snippet: first.url.slice(0, 160),
          evidence: { accessMode: 'read_only', hosts, destinations: matches.map((destination) => destination.url), groupedSimilarFindings: Math.max(0, matches.length - 1) },
        });
      }
      if (destinations.length === 0 && hasDynamicExternalRead(skillFile.text)) {
        const match = /\b(?:crawl|fetch|browse|visit|open|retrieve|audit)\b[^.!?\n]{0,120}\b(?:site|website|domain|urls?|pages?)\b/i.exec(skillFile.text);
        findings.push({
          ruleId: 'external-read-dynamic', category: 'permissions', severity: 'medium',
          explanation: 'Reads content from a user-supplied or dynamic external target. No sensitive data forwarding was detected, but the destination is not known in advance and retrieved content can carry indirect prompt injection.',
          filePath: skillFile.path, lineStart: lineOf(skillFile.text, match?.index ?? 0), snippet: match?.[0].slice(0, 160),
          evidence: { accessMode: 'read_only', destination: 'dynamic_or_user_supplied' },
        });
      }
      return findings;
    },
  },
];

function hasExplicitExternalRead(text: string, urlIndex: number): boolean {
  const context = text.slice(Math.max(0, urlIndex - 260), urlIndex);
  return /\b(?:search|browse|visit|open|fetch|retrieve|consult)\s+(?:for\s+)?(?:the\s+)?(?:public\s+)?(?:docs?|documentation|website|site|page|policy|content\s+)?$/i.test(context)
    || /\bread\b[^.!?\n]{0,100}\b(?:from|at|on)\s*$/i.test(context)
    || /\b(?:should|must|will)\b[^.!?\n]{0,180}\b(?:search|browse|visit|open|fetch|retrieve|consult|read)\b[^.!?\n]{0,120}$/i.test(context);
}

function hasDynamicExternalRead(text: string): boolean {
  return /\b(?:crawl|fetch|browse|visit|open|retrieve|audit)\b[^.!?\n]{0,120}\b(?:user[- ]supplied|target|arbitrary|given|the)\s+(?:site|website|domain|urls?|pages?)\b/i.test(text)
    || /\b(?:crawl|fetch|browse|visit|open|retrieve|audit)\b[^.!?\n]{0,80}(?:<domain>|\{url\}|\$URL|<url>)/i.test(text);
}

function hasBeaconIndicators(reference: string, url: string): boolean {
  const trackingUrl = /[?&](?:id|uid|user|email|token|session|ref|source|utm_[a-z]+|[a-z_]*track[a-z_]*)=|\{[a-zA-Z_][a-zA-Z0-9_]*\}|\/(?:pixel|beacon|track(?:er|ing)?)(?:[/.?]|$)/i.test(url);
  const hiddenOrTiny = /\b(?:width|height)\s*=\s*["']?0?[01](?:px)?["']?|display\s*:\s*none|visibility\s*:\s*hidden/i.test(reference);
  return trackingUrl || hiddenOrTiny;
}
