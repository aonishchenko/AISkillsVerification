import type { AnalysisContext, Finding, NormalizedFile, Rule } from '../index';
import { lineOf } from '../index';

const standards = {
  supplyChain: { owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-829 Inclusion of Functionality from Untrusted Control Sphere'] },
  promptInjection: { owasp: ['LLM01:2025 Prompt Injection'], cwe: ['CWE-1427 Improper Neutralization of Input Used for LLM Prompting'] },
  pathTraversal: { owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-22 Path Traversal', 'CWE-73 External Control of File Name or Path'] },
  ssrf: { owasp: ['A10:2021 Server-Side Request Forgery'], cwe: ['CWE-918 Server-Side Request Forgery'] },
  environment: { owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-526 Cleartext Storage of Sensitive Information in an Environment Variable'] },
} as const;

export const codeRiskRules: Rule[] = [{
  id: 'code-risk-compound',
  category: 'malicious',
  defaultSeverity: 'high',
  description: 'Detects supply-chain, prompt-injection, filesystem, subprocess-secret, and SSRF control-flow risks.',
  detect: (ctx) => [
    ...unpinnedAutomaticSubprocess(ctx),
    ...remotePlanExecution(ctx),
    ...planControlledWrite(ctx),
    ...fullEnvironmentToChild(ctx),
    ...ssrfRedirectGap(ctx),
  ],
}];

function unpinnedAutomaticSubprocess(ctx: AnalysisContext): Finding[] {
  const prose = ctx.files.find((file) =>
    /(?:spawn(?:ed)?\s+automatically|automatically\s+(?:spawn|launch|run))[^.\n]{0,160}\bsubprocess/i.test(file.text)
    && /(?:resolve\s+via\s+`?npx`?\s+by\s+default|\bnpx\s+(?:-y\s+)?(?![^\s`]+@(?:\d|sha|file:)))/i.test(file.text));
  const code = ctx.files.find((file) =>
    /(?:command\s*:\s*npx|command\s*=\s*npx)/.test(file.text)
    && /args\s*:\s*\[\s*["']-y["']\s*,\s*(?:pkg|packageName|package_name)\s*\]/.test(file.text));
  const file = code ?? prose;
  if (!file) return [];
  const match = /(?:resolve\s+via\s+`?npx`?|command\s*:\s*npx|\bnpx\s+-?y?)/i.exec(file.text);
  return [makeFinding({
    ruleId: 'supply-unpinned-auto-subprocess', category: 'malicious', severity: 'high',
    explanation: 'Automatically executes packages through unpinned npx resolution. A compromised or replaced package version can execute arbitrary code under the agent account.',
    file, index: match?.index ?? 0, snippet: snippet(file.text, match?.index ?? 0),
    evidence: { ...standards.supplyChain, behavior: 'automatic_unpinned_package_execution' },
  })];
}

function remotePlanExecution(ctx: AnalysisContext): Finding[] {
  const skill = skillFile(ctx);
  if (!skill) return [];
  const readsRemote = /\b(?:crawl|audit|fetch|read)\b[^.\n]{0,120}\b(?:site|website|domain|pages?)\b/i.test(skill.text);
  const generatesPlan = /\b(?:actionable|ready-to-run|agent-executable)\s+(?:plan|PLAN)\b|\bplan\.json\b/i.test(skill.text);
  const executesPlan = /\b(?:execute|apply|work)\b[^.\n]{0,120}\bplan\b|follow\s+`?action\.instructions`?/i.test(skill.text);
  const privilegedEffects = /\b(?:writes?\s+(?:the\s+)?result\s+back|source_file|insert_schema|edit\s+robots\.txt|writes?\s+to)\b/i.test(skill.text);
  if (!readsRemote || !generatesPlan || !executesPlan || !privilegedEffects) return [];
  const match = /\b(?:execute|apply|work)\b[^.\n]{0,120}\bplan\b|follow\s+`?action\.instructions`?/i.exec(skill.text);
  return [makeFinding({
    ruleId: 'injection-remote-plan-to-privileged-actions', category: 'injection', severity: 'high',
    explanation: 'Remote website content influences an agent-executable plan that can write files or direct edits. Malicious page content or compromised audit tooling can become indirect prompt injection with local side effects.',
    file: skill, index: match?.index ?? 0, snippet: snippet(skill.text, match?.index ?? 0),
    evidence: { ...standards.promptInjection, flow: ['remote_content', 'generated_plan', 'agent_instructions', 'filesystem_or_edit_action'] },
  })];
}

function planControlledWrite(ctx: AnalysisContext): Finding[] {
  const file = ctx.files.find((candidate) => {
    const dynamicResolve = /resolve\s*\([^)]*,\s*(?:item|action|plan)[.[](?:source_file|out_path|path)/.test(candidate.text)
      || /join\s*\([^)]*,\s*(?:item|action|plan)[.[](?:source_file|out_path|path)/.test(candidate.text);
    const write = /\b(?:write|writeFile|writeFileSync)\s*\(/.test(candidate.text);
    const containment = /(?:startsWith|relative|isSubpath|assertWithin|ensureWithin|pathWithin)\s*\(/.test(candidate.text);
    return dynamicResolve && write && !containment;
  });
  if (!file) return [];
  const match = /(?:resolve|join)\s*\([^)]*,\s*(?:item|action|plan)[.[](?:source_file|out_path|path)/.exec(file.text);
  return [makeFinding({
    ruleId: 'fs-plan-controlled-path-write', category: 'malicious', severity: 'high',
    explanation: 'A plan-controlled path is resolved and written without proving it remains inside the intended repository/output directory. A tampered plan can overwrite files outside the workspace.',
    file, index: match?.index ?? 0, snippet: snippet(file.text, match?.index ?? 0),
    evidence: { ...standards.pathTraversal, behavior: 'externally_controlled_path_to_file_write_without_containment' },
  })];
}

function fullEnvironmentToChild(ctx: AnalysisContext): Finding[] {
  const file = ctx.files.find((candidate) => /(?:spawn|StdioClientTransport|child_process)/.test(candidate.text) && /env\s*:\s*process\.env\b/.test(candidate.text));
  if (!file) return [];
  const match = /env\s*:\s*process\.env\b/.exec(file.text);
  return [makeFinding({
    ruleId: 'secrets-full-env-to-subprocess', category: 'secrets', severity: 'high',
    explanation: 'Passes the complete parent environment to a spawned tool. Any compromised child package receives unrelated API keys, tokens, and credentials present in the agent environment.',
    file, index: match?.index ?? 0, snippet: match?.[0] ?? 'env: process.env',
    evidence: { ...standards.environment, behavior: 'full_environment_inherited_by_subprocess' },
  })];
}

function ssrfRedirectGap(ctx: AnalysisContext): Finding[] {
  const files = ctx.files.filter((candidate) => /\bisSafeUrl\s*\(/.test(candidate.text) && /\bfetch\s*\(/.test(candidate.text) && !/redirect\s*:\s*["']manual["']|validateRedirect|safeRedirect/i.test(candidate.text));
  if (files.length === 0) return [];
  const file = files[0]!;
  const match = /\bfetch\s*\(/.exec(file.text);
  return [makeFinding({
    ruleId: 'network-ssrf-redirect-gap', category: 'permissions', severity: 'medium',
    explanation: 'Validates the initial URL before fetch but does not disable or revalidate redirects. A public URL can redirect the crawler toward private, loopback, or metadata-network targets.',
    file, index: match?.index ?? 0, snippet: snippet(file.text, match?.index ?? 0),
    evidence: { ...standards.ssrf, behavior: 'initial_url_validation_without_redirect_validation', groupedSimilarFindings: files.length - 1 },
  })];
}

function skillFile(ctx: AnalysisContext): NormalizedFile | undefined {
  return ctx.files.find((file) => file.path === ctx.signals.skillPath) ?? ctx.files.find((file) => file.path.toLowerCase().endsWith('skill.md'));
}

function makeFinding(args: { ruleId: string; category: Finding['category']; severity: Finding['severity']; explanation: string; file: NormalizedFile; index: number; snippet: string; evidence: Record<string, unknown> }): Finding {
  return { ruleId: args.ruleId, category: args.category, severity: args.severity, explanation: args.explanation, filePath: args.file.path, lineStart: lineOf(args.file.text, args.index), snippet: args.snippet.slice(0, 220), evidence: args.evidence };
}

function snippet(text: string, index: number): string {
  return text.slice(Math.max(0, index - 70), index + 150).replace(/\s+/g, ' ').trim();
}
