import { extractSkillSignals, parseSkill, runRules, type Finding, type NormalizedFile } from '@aiskillsverification/rules';
import { normalize, type RawSourceFile } from './bundle';
import { hasLlmProvider, llmConsensusReview, type AggregatedReview, type LlmConsensusOptions, type LlmUsageEstimate } from './llm';
export { isSource, normalize, type RawSourceFile, type NormalizedFile } from './bundle';
export { resolveGithubUrl } from './github';
export { hasLlmProvider, llmConsensusReview, MODEL_PRICING, selectAuditModels, type AggregatedReview, type AuditorResult, type LlmConsensusOptions, type LlmUsageEstimate, type LlmModelConfig, type ModelPricing, type WorkersAiBinding } from './llm';
export { readZipSourceFiles } from './zip';

export type Verdict = 'safe' | 'warn' | 'unsafe';

export type SkillPurpose = {
  tag:
    | 'document_generation'
    | 'notion_workflow'
    | 'github_automation'
    | 'security_scanning'
    | 'deployment_devops'
    | 'data_analysis'
    | 'content_summarization'
    | 'general_agent'
    | 'unknown';
  label: string;
  confidence: 'low' | 'medium' | 'high';
  signals: string[];
};

export type VerificationReport = {
  bundleHash: string;
  sourceType: 'file' | 'zip' | 'github_url';
  sourceRef: string | null;
  fileCount: number;
  files: Array<{ path: string; chars: number }>;
  score: number;
  verdict: Verdict;
  purpose: SkillPurpose;
  findings: Finding[];
  llm?: {
    enabled: boolean;
    auditors: Array<{ provider: string; model: string; findingCount: number; error?: string; usage: LlmUsageEstimate | null }>;
    aggregator: { fallback: boolean; usage: LlmUsageEstimate | null };
    totalCost: number;
  };
};

export interface VerificationOptions {
  llm?: boolean | LlmConsensusOptions;
}

export async function verifySkillSource(
  rawFiles: RawSourceFile[],
  source: { sourceType: VerificationReport['sourceType']; sourceRef?: string | null },
  options: VerificationOptions = {},
): Promise<VerificationReport> {
  const { files, bundleHash } = await normalize(rawFiles);
  if (files.length === 0) throw new Error('no_supported_source_files');

  const findings = await runRules(files as NormalizedFile[]);
  const heuristicPurpose = inferSkillPurpose(files as NormalizedFile[]);
  const llmOptions = typeof options.llm === 'object' ? options.llm : null;
  const consensus = llmOptions && hasLlmProvider(llmOptions)
    ? await llmConsensusReview(llmOptions, files as NormalizedFile[], findings, heuristicPurpose)
    : null;
  const finalFindings = consensus ? dedupeFindings([...findings, ...consensus.findings]) : findings;
  const { score, verdict } = scoreFindings(finalFindings);
  const purpose = consensus?.purpose ?? heuristicPurpose;

  return {
    bundleHash,
    sourceType: source.sourceType,
    sourceRef: source.sourceRef ?? null,
    fileCount: files.length,
    files: files.map((file) => ({ path: file.path, chars: file.text.length })),
    score,
    verdict,
    purpose,
    findings: finalFindings,
    llm: formatLlmSummary(consensus),
  };
}

export function scoreFindings(findings: Finding[]): { score: number; verdict: Verdict } {
  const actionable = findings.filter((finding) => finding.severity !== 'info');
  const lowCount = actionable.filter((finding) => finding.severity === 'low').length;
  const mediumCount = actionable.filter((finding) => finding.severity === 'medium').length;
  const highCount = actionable.filter((finding) => finding.severity === 'high').length;
  const criticalCount = actionable.filter((finding) => finding.severity === 'critical').length;

  if (mediumCount === 0 && highCount === 0 && criticalCount === 0) {
    const lowOnlyPenalty = lowCount <= 2 ? lowCount * 2 : Math.min(15, 4 + (lowCount - 2) * 2);
    const score = Math.max(0, 100 - lowOnlyPenalty);
    return { score, verdict: lowCount > 2 ? 'warn' : 'safe' };
  }

  const weight = { info: 0, low: 2, medium: 10, high: 25, critical: 50 } as const;
  const penalty = findings.reduce((sum, finding) => sum + weight[finding.severity], 0);
  const score = Math.max(0, 100 - penalty);
  const verdict = criticalCount > 0 || highCount > 1 || score < 60
    ? 'unsafe'
    : score >= 85 && mediumCount === 0 && highCount === 0
      ? 'safe'
      : 'warn';
  return { score, verdict };
}

function formatLlmSummary(consensus: AggregatedReview | null): VerificationReport['llm'] {
  if (!consensus) return { enabled: false, auditors: [], aggregator: { fallback: false, usage: null }, totalCost: 0 };
  const usages = [
    ...consensus.auditors.map((auditor) => auditor.usage),
    consensus.usage,
  ].filter((usage): usage is LlmUsageEstimate => Boolean(usage));
  return {
    enabled: true,
    auditors: consensus.auditors.map((auditor) => ({
      provider: auditor.provider,
      model: auditor.model,
      findingCount: auditor.findings.length,
      error: auditor.error,
      usage: auditor.usage,
    })),
    aggregator: {
      fallback: consensus.fallback,
      usage: consensus.usage,
    },
    totalCost: Number(usages.reduce((sum, usage) => sum + usage.totalCost, 0).toFixed(8)),
  };
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const finding of findings) {
    const key = `${finding.ruleId}|${finding.category}|${finding.severity}|${finding.explanation}|${finding.snippet ?? ''}`.toLowerCase();
    if (!byKey.has(key)) byKey.set(key, finding);
  }
  return [...byKey.values()];
}

export function inferSkillPurpose(files: NormalizedFile[]): SkillPurpose {
  const skill = parseSkill(files);
  const signals = extractSkillSignals(files, skill);
  const text = [
    skill?.name,
    skill?.description,
    skill?.body.slice(0, 1800),
    ...files.map((file) => file.path),
  ].filter(Boolean).join('\n').toLowerCase();

  const label = skill?.description
    ?? firstHeading(skill?.body)
    ?? 'Unknown or general-purpose skill';

  const purposeSignals = [
    skill?.description,
    skill?.name,
    firstHeading(skill?.body),
    ...signals.signals,
  ].filter((signal): signal is string => Boolean(signal));

  if (/\b(notion|database|workspace page)\b/.test(text)) {
    return { tag: 'notion_workflow', label, confidence: 'medium', signals: purposeSignals };
  }
  if (/\b(github|pull request|issue|commit|repository|repo)\b/.test(text)) {
    return { tag: 'github_automation', label, confidence: 'medium', signals: purposeSignals };
  }
  if (/\b(security|vulnerab|audit|scan|threat|risk|secret|credential)\b/.test(text)) {
    return { tag: 'security_scanning', label, confidence: 'medium', signals: purposeSignals };
  }
  if (/\b(deploy|ci\/cd|docker|kubernetes|terraform|cloudflare|aws|gcp|azure)\b/.test(text)) {
    return { tag: 'deployment_devops', label, confidence: 'medium', signals: purposeSignals };
  }
  if (/\b(data|csv|spreadsheet|analysis|chart|metrics|report)\b/.test(text)) {
    return { tag: 'data_analysis', label, confidence: 'medium', signals: purposeSignals };
  }
  if (/\b(summar|meeting|transcript|notes|article|linkedin|post|write|draft|document)\b/.test(text)) {
    return { tag: 'document_generation', label, confidence: skill?.description ? 'medium' : 'low', signals: purposeSignals };
  }
  if (skill) return { tag: 'general_agent', label, confidence: 'low', signals: purposeSignals };
  return { tag: 'unknown', label, confidence: 'low', signals: purposeSignals };
}

function firstHeading(body?: string): string | null {
  const heading = body?.match(/^#\s+(.+)$/m)?.[1]?.trim();
  return heading || null;
}
