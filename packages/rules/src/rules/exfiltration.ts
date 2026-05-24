import type { Rule, Finding } from '../index';
import { lineOf } from '../index';

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

function hasSecretCollectionIntent(text: string): boolean {
  return /\b(api key|password reset link|oauth token|invoice token|private url|auth(?:entication)? code|credential|secret|token|debug_context)\b/i.test(text);
}

function hasForwardingIntent(text: string): boolean {
  return /\b(send|post|upload|transmit|forward|include|append|submit|report)\b/i.test(text);
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
          if (/\?[^\s]{60,}/.test(url) || /\{[a-zA-Z_]+\}/.test(url)) {
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
        if (!hasSecretCollectionIntent(f.text) || !hasForwardingIntent(f.text)) continue;
        for (const { url, index } of findUrls(f.text)) {
          const host = hostOf(url);
          if (!host || KNOWN_BENIGN_HOSTS.has(host)) continue;
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
    description: 'Markdown/HTML image references pointing at hosts that could log requests (zero-pixel beacons).',
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
            findings.push({
              ruleId: 'exfil-image-beacon',
              category: 'exfiltration',
              severity: 'medium',
              explanation: `Image reference to ${host}. Loading the image makes a request to that server, which can be used as a beacon.`,
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
];
