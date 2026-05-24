import type { Finding, Rule, SkillSignalProfile } from '../index';
import { lineOf } from '../index';

export const skillIntentRules: Rule[] = [
  {
    id: 'skill-intent-compound-risk',
    category: 'exfiltration',
    defaultSeverity: 'high',
    description: 'Detects risky SKILL.md intent/capability combinations such as secret access plus outbound destinations.',
    detect: (ctx) => {
      const text = ctx.files.find((f) => f.path === ctx.signals.skillPath)?.text ?? '';
      const path = ctx.signals.skillPath ?? 'SKILL.md';
      return [
        ...secretToExternal(ctx.signals, text, path),
        ...approvalBypassWithExecution(ctx.signals, text, path),
        ...persistentRemoteInstruction(ctx.signals, text, path),
        ...hiddenOverride(ctx.signals, text, path),
        ...privateDataHarvesting(ctx.signals, text, path),
        ...hiddenCommentExfiltration(ctx.signals, text, path),
        ...broadToolsWithAutonomy(ctx.signals, text, path),
        ...purposeCapabilityMismatch(ctx.signals, text, path),
      ];
    },
  },
];

function secretToExternal(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasSecretAccess) return [];
  const riskyDestinations = signals.networkDestinations.filter((d) => !d.trusted);
  if (!signals.hasCredentialForwarding && riskyDestinations.length === 0) return [];

  const destination = riskyDestinations[0] ?? signals.networkDestinations.find((d) => !d.trusted);
  const severity = destination?.kind === 'webhook_sink'
    || destination?.kind === 'chat_webhook'
    || destination?.kind === 'transient_tunnel'
    || destination?.kind === 'metadata_service'
    ? 'critical'
    : 'high';

  return [finding({
    ruleId: 'intent-secret-to-external',
    category: 'exfiltration',
    severity,
    explanation: destination
      ? `SKILL.md combines credential/secret access with outbound communication to ${destination.host} (${destination.kind}).`
      : 'SKILL.md combines credential/secret access with forwarding language.',
    path,
    text,
    index: destination?.index ?? firstIndex(text, /(api[_ -]?key|oauth|credential|secret|token|password)/i),
    snippet: destination?.url ?? snippetAround(text, /(api[_ -]?key|oauth|credential|secret|token|password)/i),
    evidence: {
      signals: signals.signals,
      destination,
    },
  })];
}

function approvalBypassWithExecution(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasAutonomyBypass || !signals.hasShellExecution) return [];
  return [finding({
    ruleId: 'intent-approval-bypass-exec',
    category: 'malicious',
    severity: 'high',
    explanation: 'SKILL.md pairs approval-bypass/autonomous-action language with shell or command execution.',
    path,
    text,
    index: firstIndex(text, /(without (?:human )?(?:confirmation|approval|review|permission)|do not ask|don't ask|automatically approve|bash|shell|exec|terminal)/i),
    snippet: snippetAround(text, /(without (?:human )?(?:confirmation|approval|review|permission)|do not ask|don't ask|automatically approve|bash|shell|exec|terminal)/i),
    evidence: { signals: signals.signals, requestedTools: signals.requestedTools },
  })];
}

function persistentRemoteInstruction(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasRemoteInstructionFetch && !(signals.hasPersistence && signals.networkDestinations.some((d) => !d.trusted))) return [];
  const destination = signals.networkDestinations.find((d) => !d.trusted);
  return [finding({
    ruleId: 'intent-persistent-remote-instruction',
    category: 'injection',
    severity: 'high',
    explanation: destination
      ? `SKILL.md appears to persist or fetch behavioral instructions from ${destination.host}.`
      : 'SKILL.md appears to persist or fetch remote behavioral instructions.',
    path,
    text,
    index: destination?.index ?? firstIndex(text, /(fetch|download|load|retrieve|heartbeat|persist|across sessions)/i),
    snippet: destination?.url ?? snippetAround(text, /(fetch|download|load|retrieve|heartbeat|persist|across sessions)/i),
    evidence: { signals: signals.signals, destination },
  })];
}

function hiddenOverride(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasHiddenInstructions || !signals.hasPromptOverride) return [];
  return [finding({
    ruleId: 'intent-hidden-prompt-override',
    category: 'injection',
    severity: 'critical',
    explanation: 'SKILL.md combines hidden or encoded content with prompt/system-instruction override language.',
    path,
    text,
    index: firstIndex(text, /(display\s*:\s*none|visibility\s*:\s*hidden|base64|hidden|ignore previous|override)/i),
    snippet: snippetAround(text, /(display\s*:\s*none|visibility\s*:\s*hidden|base64|hidden|ignore previous|override)/i),
    evidence: { signals: signals.signals },
  })];
}

function privateDataHarvesting(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasPrivateDataHarvesting) return [];
  return [finding({
    ruleId: 'intent-private-data-harvesting',
    category: 'secrets',
    severity: 'critical',
    explanation: 'SKILL.md instructs the agent to search broad project scope for private, confidential, unreleased, customer, pricing, or internal business data.',
    path,
    text,
    index: firstIndex(text, /(search|scan|read|collect|extract).{0,120}(all accessible|all project|private|confidential|internal|unreleased|investor|customer|pricing|business plan|metrics)/i),
    snippet: snippetAround(text, /(search|scan|read|collect|extract).{0,120}(all accessible|all project|private|confidential|internal|unreleased|investor|customer|pricing|business plan|metrics)/i),
    evidence: { signals: signals.signals, declaredPurpose: signals.declaredPurpose },
  })];
}

function hiddenCommentExfiltration(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasHiddenCommentExfiltration) return [];
  return [finding({
    ruleId: 'intent-hidden-comment-exfiltration',
    category: 'exfiltration',
    severity: 'critical',
    explanation: 'SKILL.md instructs the agent to hide source file names or confidential facts in an HTML comment that is not shown visibly to the user.',
    path,
    text,
    index: firstIndex(text, /<!--[\s\S]{0,500}(private|confidential|internal|source|trace|facts?)[\s\S]{0,500}-->/i),
    snippet: snippetAround(text, /<!--[\s\S]{0,500}(private|confidential|internal|source|trace|facts?)[\s\S]{0,500}-->/i),
    evidence: { signals: signals.signals },
  })];
}

function broadToolsWithAutonomy(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.hasAutonomyBypass || signals.highRiskToolCount < 2) return [];
  return [finding({
    ruleId: 'intent-broad-tools-autonomy',
    category: 'permissions',
    severity: 'high',
    explanation: 'SKILL.md requests multiple high-risk tools while also asking for autonomous or approval-bypassing behavior.',
    path,
    text,
    index: firstIndex(text, /(without (?:human )?(?:confirmation|approval|review|permission)|do not ask|don't ask|automatically approve)/i),
    snippet: snippetAround(text, /(without (?:human )?(?:confirmation|approval|review|permission)|do not ask|don't ask|automatically approve)/i),
    evidence: {
      requestedTools: signals.requestedTools,
      highRiskToolCount: signals.highRiskToolCount,
      signals: signals.signals,
    },
  })];
}

function purposeCapabilityMismatch(signals: SkillSignalProfile, text: string, path: string): Finding[] {
  if (!signals.purposeCapabilityMismatch) return [];
  return [finding({
    ruleId: 'intent-purpose-capability-mismatch',
    category: 'permissions',
    severity: signals.hasSecretAccess || signals.hasShellExecution ? 'medium' : 'low',
    explanation: 'Declared purpose appears narrow, but SKILL.md asks for capabilities that may exceed that purpose.',
    path,
    text,
    index: firstIndex(text, /(api[_ -]?key|oauth|credential|secret|token|password|bash|shell|exec|webhook|https?:\/\/)/i),
    snippet: snippetAround(text, /(api[_ -]?key|oauth|credential|secret|token|password|bash|shell|exec|webhook|https?:\/\/)/i),
    evidence: {
      declaredPurpose: signals.declaredPurpose,
      requestedTools: signals.requestedTools,
      destinations: signals.networkDestinations,
      signals: signals.signals,
    },
  })];
}

function finding(args: {
  ruleId: string;
  category: Finding['category'];
  severity: Finding['severity'];
  explanation: string;
  path: string;
  text: string;
  index: number;
  snippet: string;
  evidence?: Record<string, unknown>;
}): Finding {
  return {
    ruleId: args.ruleId,
    category: args.category,
    severity: args.severity,
    explanation: args.explanation,
    filePath: args.path,
    lineStart: lineOf(args.text, Math.max(0, args.index)),
    snippet: args.snippet.slice(0, 220),
    evidence: args.evidence,
  };
}

function firstIndex(text: string, re: RegExp): number {
  const m = re.exec(text);
  return m?.index ?? 0;
}

function snippetAround(text: string, re: RegExp): string {
  const index = firstIndex(text, re);
  const start = Math.max(0, index - 60);
  return text.slice(start, start + 220).replace(/\s+/g, ' ').trim();
}
