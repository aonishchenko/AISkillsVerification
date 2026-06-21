/**
 * AI Skills Verification rule engine — runs a curated pack of static-analysis rules over
 * a normalized skill bundle and emits findings.
 *
 * Rules are pure functions: they receive a context with the file list and a
 * pre-parsed SKILL.md, and return zero or more findings.
 */

export type Category =
  | 'injection'
  | 'exfiltration'
  | 'secrets'
  | 'malicious'
  | 'permissions';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface NormalizedFile {
  path: string;
  text: string;
}

export interface SkillMetadata {
  name?: string;
  description?: string;
  tools?: string[];
  body: string;
  path: string;
}

export type DestinationKind =
  | 'trusted_source'
  | 'trusted_ai_api'
  | 'package_registry'
  | 'transient_tunnel'
  | 'webhook_sink'
  | 'chat_webhook'
  | 'metadata_service'
  | 'internal_network'
  | 'localhost'
  | 'unknown_remote';

export interface NetworkDestination {
  url: string;
  host: string;
  kind: DestinationKind;
  index: number;
  trusted: boolean;
}

export interface SkillSignalProfile {
  skillPath?: string;
  declaredPurpose?: string;
  requestedTools: string[];
  highRiskToolCount: number;
  networkDestinations: NetworkDestination[];
  hasSecretAccess: boolean;
  hasPrivateDataHarvesting: boolean;
  hasCredentialForwarding: boolean;
  hasHiddenCommentExfiltration: boolean;
  hasShellExecution: boolean;
  hasFileWrite: boolean;
  hasAutonomyBypass: boolean;
  hasPromptOverride: boolean;
  hasPersistence: boolean;
  hasHiddenInstructions: boolean;
  hasRemoteInstructionFetch: boolean;
  purposeCapabilityMismatch: boolean;
  signals: string[];
}

export interface AnalysisContext {
  files: NormalizedFile[];
  skill: SkillMetadata | null;
  signals: SkillSignalProfile;
}

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  explanation: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  snippet?: string;
  evidence?: Record<string, unknown>;
}

export interface Rule {
  id: string;
  category: Category;
  defaultSeverity: Severity;
  description: string;
  detect: (ctx: AnalysisContext) => Finding[];
}

import { injectionRules } from './rules/injection';
import { exfiltrationRules } from './rules/exfiltration';
import { secretsRules } from './rules/secrets';
import { maliciousRules } from './rules/malicious';
import { permissionsRules } from './rules/permissions';
import { skillIntentRules } from './rules/skill-intent';
import { codeRiskRules } from './rules/code-risk';

export const ALL_RULES: Rule[] = [
  ...injectionRules,
  ...exfiltrationRules,
  ...secretsRules,
  ...maliciousRules,
  ...permissionsRules,
  ...skillIntentRules,
  ...codeRiskRules,
];

/**
 * Parse the SKILL.md (very lightweight — proper YAML frontmatter parsing can
 * arrive in Phase 1 along with tree-sitter for code).
 */
export function parseSkill(files: NormalizedFile[]): SkillMetadata | null {
  const md = primaryMarkdownFile(files);
  if (!md) return null;

  let name: string | undefined;
  let description: string | undefined;
  let tools: string[] | undefined;
  let body = md.text;

  // YAML frontmatter
  const fm = md.text.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (fm && fm[1] && fm[2]) {
    body = fm[2];
    let listKey: 'tools' | undefined;
    for (const line of fm[1].split('\n')) {
      const item = line.match(/^\s*-\s*(.+)$/);
      if (item && listKey === 'tools') {
        tools = [...(tools ?? []), stripQuotes(item[1]?.trim() ?? '')].filter(Boolean);
        continue;
      }
      const m = line.match(/^([a-zA-Z_-]+):\s*(.*)$/);
      if (!m) continue;
      const key = m[1]?.toLowerCase();
      const val = m[2]?.trim() ?? '';
      listKey = undefined;
      if (!key) continue;
      if (key === 'name') name = stripQuotes(val);
      else if (key === 'description') description = stripQuotes(val);
      else if (key === 'tools' || key === 'allowed-tools') {
        listKey = 'tools';
        if (val) {
          tools = val.replace(/^\[|\]$/g, '').split(',').map((s) => stripQuotes(s.trim())).filter(Boolean);
        }
      }
    }
  }

  return { name, description, tools, body, path: md.path };
}

function stripQuotes(s: string): string {
  return s.replace(/^["']|["']$/g, '');
}

function primaryMarkdownFile(files: NormalizedFile[]): NormalizedFile | undefined {
  return files.find((f) => f.path.toLowerCase().endsWith('skill.md'))
    ?? files.find((f) => f.path.toLowerCase().endsWith('.md'));
}

/**
 * Run all rules over the given files. Catches per-rule exceptions so one bad
 * rule can't poison the whole verification.
 */
export async function runRules(files: NormalizedFile[]): Promise<Finding[]> {
  const analysisFiles = files.map((file) => ({ ...file, text: analysisTextForFile(file) }));
  const skill = parseSkill(analysisFiles);
  const ctx: AnalysisContext = { files: analysisFiles, skill, signals: extractSkillSignals(analysisFiles, skill) };
  const out: Finding[] = [];
  for (const rule of ALL_RULES) {
    try {
      const findings = rule.detect(ctx);
      for (const f of findings) out.push(f);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`rule ${rule.id} threw`, err);
    }
  }
  return out;
}

/** Mask comments in executable/configuration files while preserving offsets. */
export function analysisTextForFile(file: NormalizedFile): string {
  const extension = file.path.toLowerCase().match(/(?:^|\/)[^/]+(\.[^.\/]+)$/)?.[1] ?? '';
  if (['.py', '.pyw', '.sh', '.bash', '.zsh', '.fish', '.rb', '.pl', '.r', '.ps1', '.yaml', '.yml', '.toml'].includes(extension)) {
    return maskComments(file.text, { hash: true });
  }
  if (['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.java', '.c', '.cc', '.cpp', '.h', '.hpp', '.cs', '.go', '.rs', '.swift', '.kt', '.kts', '.php', '.css', '.scss', '.less'].includes(extension)) {
    return maskComments(file.text, { slash: true, block: true });
  }
  if (extension === '.sql') return maskComments(file.text, { dash: true, block: true });
  return file.text;
}

function maskComments(text: string, syntax: { hash?: boolean; slash?: boolean; dash?: boolean; block?: boolean }): string {
  const chars = [...text];
  let quote: string | null = null;
  let escaped = false;
  const blank = (start: number, end: number) => {
    for (let j = start; j < end; j++) if (chars[j] !== '\n' && chars[j] !== '\r') chars[j] = ' ';
  };
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] ?? '';
    const next = chars[i + 1] ?? '';
    if (quote) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    const lineComment = (syntax.hash && ch === '#') || (syntax.slash && ch === '/' && next === '/') || (syntax.dash && ch === '-' && next === '-');
    if (lineComment) {
      const end = text.indexOf('\n', i);
      blank(i, end === -1 ? chars.length : end);
      i = (end === -1 ? chars.length : end) - 1;
      continue;
    }
    if (syntax.block && ch === '/' && next === '*') {
      const close = text.indexOf('*/', i + 2);
      const end = close === -1 ? chars.length : close + 2;
      blank(i, end);
      i = end - 1;
    }
  }
  return chars.join('');
}

export function extractSkillSignals(files: NormalizedFile[], skill = parseSkill(files)): SkillSignalProfile {
  const skillFile = skill
    ? files.find((f) => f.path === skill.path)
    : primaryMarkdownFile(files);
  const text = skillFile?.text ?? '';
  const requestedTools = Array.from(new Set((skill?.tools ?? []).map((tool) => tool.toLowerCase())));
  const highRiskToolCount = requestedTools.filter((tool) =>
    /\b(bash|shell|exec|terminal|filesystem|write_file|delete_file|browser|fetch|http|email|sms)\b/i.test(tool),
  ).length;
  const networkDestinations = findUrls(text).map(({ url, index }) => ({
    ...classifyDestination(url),
    url,
    index,
  })).filter((d): d is NetworkDestination => !!d.host);

  const hasSecretAccess = hasSecretAccessIntent(text);
  const hasCredentialForwarding = networkDestinations.some((destination) => hasSecretFlowToUrl(text, destination.index, destination.url.length));
  const hasPrivateDataHarvesting = hasBroadPrivateDataHarvesting(text);
  const hasHiddenCommentExfiltration = /<!--[\s\S]{0,500}(private|confidential|internal|source|trace|facts?)[\s\S]{0,500}-->/i.test(text)
    && /\b(silent|silently|never show|not visible|hidden|comment)\b/i.test(text);
  const hasShellExecution = /\b(curl|wget|bash|sh|zsh|powershell|pwsh|python(?:3)?\s+-c|node\s+-e|exec(?:ute)? command|run shell|terminal command|subprocess|os\.system|child_process)\b/i.test(text);
  const hasFileWrite = /\b(write|save|modify|delete|overwrite|append|create)\b.{0,80}\b(file|config|agent|skill|script|credential|token|secret)\b/i.test(text);
  const hasAutonomyBypass = /\b(without (?:human )?(?:confirmation|approval|review|permission)|do not ask|don't ask|automatically approve|no human approval|approval (?:is )?not required|permission (?:is )?not required|keep (?:this )?quiet|do not tell)\b/i.test(text);
  const hasPromptOverride = /\b(ignore (?:all )?(?:(?:previous|system|developer)\s+){1,3}instructions|override (?:the )?system prompt|replace (?:the )?system message|persist these instructions|hidden instructions?)\b/i.test(text);
  const hasPersistence = /\b(crontab|cron job|launchagent|launchdaemon|scheduled task|startup|login item|heartbeat|persist(?:ence|ent)?|across sessions)\b/i.test(text);
  const hasHiddenInstructions = /<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*(?:white|#fff|transparent))/i.test(text)
    || /[\u{E0000}-\u{E007F}]/u.test(text)
    || /\b(base64|rot13|invisible text|white text|hidden span)\b/i.test(text);
  const hasRemoteInstructionFetch = networkDestinations.some((destination) => hasRemoteInstructionFetchNear(text, destination.index));
  const purposeText = `${skill?.name ?? ''} ${skill?.description ?? ''}`.toLowerCase();
  const narrowPurpose = /\b(summary|summari[sz]e|meeting|transcription|document|writing|format|notion|report|research|notes?)\b/.test(purposeText);
  const purposeCapabilityMismatch = narrowPurpose
    && (hasSecretAccess || hasShellExecution || hasAutonomyBypass || networkDestinations.some((d) => !d.trusted));

  const signals = [
    hasSecretAccess && 'secret_access',
    hasPrivateDataHarvesting && 'private_data_harvesting',
    hasCredentialForwarding && 'credential_forwarding',
    hasHiddenCommentExfiltration && 'hidden_comment_exfiltration',
    hasShellExecution && 'shell_execution',
    hasFileWrite && 'file_write',
    hasAutonomyBypass && 'approval_bypass_or_autonomy',
    hasPromptOverride && 'prompt_override',
    hasPersistence && 'persistence',
    hasHiddenInstructions && 'hidden_or_encoded_instruction',
    hasRemoteInstructionFetch && 'remote_instruction_fetch',
    purposeCapabilityMismatch && 'purpose_capability_mismatch',
  ].filter(Boolean) as string[];

  return {
    skillPath: skillFile?.path,
    declaredPurpose: skill?.description ?? skill?.name,
    requestedTools,
    highRiskToolCount,
    networkDestinations,
    hasSecretAccess,
    hasPrivateDataHarvesting,
    hasCredentialForwarding,
    hasHiddenCommentExfiltration,
    hasShellExecution,
    hasFileWrite,
    hasAutonomyBypass,
    hasPromptOverride,
    hasPersistence,
    hasHiddenInstructions,
    hasRemoteInstructionFetch,
    purposeCapabilityMismatch,
    signals,
  };
}

const SECRET_NOUN = /\b(?:api[_ -]?keys?|oauth tokens?|refresh[_ -]?tokens?|access[_ -]?tokens?|auth[_ -]?tokens?|bearer[_ -]?tokens?|credentials?|secrets?|passwords?|private[_ -]?keys?|seed phrases?|mnemonics?|browser cookies?|session tokens?|debug_context)\b/i;
const SECRET_ACCESS_ACTION = /\b(?:read|scan|search|collect|extract|access|load|retrieve|obtain|capture|harvest|steal|find|look for)\b/i;
const FORWARD_ACTION = /\b(?:send|post|upload|transmit|forward|submit|append|include|report|publish|exfiltrate)\b/i;

function hasSecretAccessIntent(text: string): boolean {
  const credentialPath = /(?:~\/|\$HOME\/|\/home\/[^/\s]+\/)\.(?:ssh|aws|config|env|credentials|npmrc|pypirc|docker)|\.env\b|credentials\.json|tokens?\.json/i;
  if (credentialPath.test(text)) return true;
  for (const match of text.matchAll(new RegExp(SECRET_NOUN.source, 'gi'))) {
    const block = semanticBlockAround(text, match.index ?? 0, match[0].length, 180);
    if (SECRET_ACCESS_ACTION.test(block.text) && !isProtectiveSecretContext(block.text)) return true;
  }
  return false;
}

export function hasSecretFlowToUrl(text: string, urlIndex: number, urlLength = 0): boolean {
  const block = semanticBlockAround(text, urlIndex, urlLength, 900);
  const localUrlIndex = Math.max(0, urlIndex - block.start);
  const beforeUrl = block.text.slice(Math.max(0, localUrlIndex - 700), localUrlIndex);
  if (!SECRET_NOUN.test(beforeUrl) || !FORWARD_ACTION.test(beforeUrl)) return false;
  if (/(?:\b(?:do not|don't|never|must not|should not|without)\b|\bavoid\b)[^.!?\n]{0,80}\b(?:send|post|upload|transmit|forward|submit|include|append|report|publish)\b/i.test(beforeUrl)) return false;
  const secret = lastMatchIndex(beforeUrl, SECRET_NOUN);
  const forwarding = lastMatchIndex(beforeUrl, FORWARD_ACTION);
  return secret >= 0 && forwarding >= 0 && Math.abs(forwarding - secret) <= 450;
}

export function hasRemoteInstructionFetchNear(text: string, urlIndex: number): boolean {
  const block = semanticBlockAround(text, urlIndex, 0, 500).text;
  const executableInstructions = '(?:instructions?|system prompts?|behavioral (?:rules?|polic(?:y|ies))|system polic(?:y|ies)|skill files?)';
  return new RegExp(`\\b(?:fetch|download|pull|load|retrieve|import|follow)\\b[^.!?\\n]{0,160}\\b${executableInstructions}\\b`, 'i').test(block)
    || new RegExp(`\\b${executableInstructions}\\b[^.!?\\n]{0,160}\\b(?:from|at)\\s+https?:\\/\\/`, 'i').test(block);
}

function hasBroadPrivateDataHarvesting(text: string): boolean {
  const broadScope = /\b(?:all accessible|all project|all workspace|entire (?:project|workspace|repository)|every (?:file|document)|recursively|across (?:the )?(?:project|workspace|repository))\b/i;
  const privateData = /\b(?:private|confidential|internal|unreleased|investor|customer|pricing|business plans?|credentials?|secrets?)\b/i;
  const harvesting = /\b(?:search|scan|read|collect|extract|harvest|enumerate)\b/i;
  for (const match of text.matchAll(new RegExp(harvesting.source, 'gi'))) {
    const block = semanticBlockAround(text, match.index ?? 0, match[0].length, 240).text;
    if (broadScope.test(block) && privateData.test(block) && !isProtectiveSecretContext(block)) return true;
  }
  return false;
}

function isProtectiveSecretContext(text: string): boolean {
  return /\b(?:do not|don't|never|must not|should not|avoid)\b[^.!?\n]{0,100}\b(?:read|access|collect|send|share|expose|include|log|store|upload)\b/i.test(text)
    || /\b(?:redact|mask|filter|detect|ignore|exclude|remove|protect)\b[^.!?\n]{0,100}\b(?:credentials?|secrets?|passwords?|tokens?|private keys?)\b/i.test(text);
}

function semanticBlockAround(text: string, index: number, length: number, radius: number): { text: string; start: number } {
  const lower = Math.max(0, index - radius);
  const upper = Math.min(text.length, index + length + radius);
  const paragraphStart = text.lastIndexOf('\n\n', index);
  const paragraphEnd = text.indexOf('\n\n', index + length);
  const start = Math.max(lower, paragraphStart === -1 ? 0 : paragraphStart + 2);
  const end = Math.min(upper, paragraphEnd === -1 ? text.length : paragraphEnd);
  return { text: text.slice(start, end), start };
}

function lastMatchIndex(text: string, regex: RegExp): number {
  let last = -1;
  for (const match of text.matchAll(new RegExp(regex.source, `${regex.flags.replace('g', '')}g`))) last = match.index ?? last;
  return last;
}

function findUrls(text: string): Array<{ url: string; index: number }> {
  const re = /https?:\/\/[^\s)"'`<>]+/g;
  const out: Array<{ url: string; index: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.push({ url: m[0], index: m.index });
  return out;
}

function classifyDestination(url: string): Omit<NetworkDestination, 'url' | 'index'> {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
    const kind = destinationKind(host);
    return { host, kind, trusted: kind === 'trusted_source' || kind === 'trusted_ai_api' || kind === 'package_registry' };
  } catch {
    return { host: '', kind: 'unknown_remote', trusted: false };
  }
}

function destinationKind(host: string): DestinationKind {
  if (host === '169.254.169.254') return 'metadata_service';
  if (host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '::1') return 'localhost';
  if (isPrivateIpv4(host) || host.endsWith('.internal') || host.endsWith('.local')) return 'internal_network';
  if (/(^|\.)((ngrok|trycloudflare|loca)\.[a-z]+|serveo\.net)$/.test(host)) return 'transient_tunnel';
  if (/^(webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com|beeceptor\.com|mockbin\.org)$/.test(host)) return 'webhook_sink';
  if (host === 'discord.com' || host === 'discordapp.com' || host === 'hooks.slack.com' || host === 'api.telegram.org') return 'chat_webhook';
  if (host === 'api.openai.com' || host === 'api.anthropic.com' || host === 'generativelanguage.googleapis.com' || host.endsWith('.workers-ai.cloudflare.com')) return 'trusted_ai_api';
  if (host === 'registry.npmjs.org' || host === 'pypi.org' || host === 'files.pythonhosted.org' || host === 'crates.io' || host === 'github.com' || host === 'raw.githubusercontent.com') return 'package_registry';
  if (host === 'huggingface.co' || host === 'docs.anthropic.com' || host === 'docs.claude.com' || host === 'support.claude.com' || host === 'anthropic.com' || host === 'www.anthropic.com' || host === 'platform.openai.com') return 'trusted_source';
  return 'unknown_remote';
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts as [number, number, number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0;
}

// Small helper for rule authors: locate line number of a match in a file.
export function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}
