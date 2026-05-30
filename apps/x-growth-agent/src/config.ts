import type { Bindings, StrategyDoc } from './types';

/**
 * Rotating post formats, adapted from OpenFang's "7 rotating formats" idea.
 * Each format is also a learnable `pattern` whose performance the learn loop
 * tracks, so the mix self-adjusts toward whatever the audience rewards.
 */
export const POST_FORMATS = [
  'news_take', // curated AI-security news + our opinionated angle
  'insight', // a standalone insight distilled from a blog article
  'build_in_public', // what we shipped / discovered in the product
  'contrarian', // a defensible against-the-grain take
  'how_to', // a concrete tip the reader can apply today
  'thread_opener', // first tweet of a value thread
  'question', // an open question to drive replies (replies are weighted 27x)
] as const;

export type PostFormat = (typeof POST_FORMATS)[number];

/**
 * X recommendation-algorithm weights (from the released "the-algorithm" repo,
 * via igorbrigadir/awesome-twitter-algo). We optimize a *reward* shaped like
 * the heavy ranker rather than raw like counts: replies and author-conversation
 * dominate, reports/blocks are heavily negative. Normalized per-impression in
 * scoring.ts so a high-reach post isn't unfairly favored over a sharp one.
 */
export const ENGAGEMENT_WEIGHTS = {
  likes: 0.5,
  replies: 27,
  reposts: 1,
  quotes: 1,
  profileClicks: 12,
  urlClicks: 12, // proxy for "drove traffic to the site" = the real business goal
} as const;

/** Three-signal ranking weights, from AutoViralAI. */
export const RANK_WEIGHTS = { ai: 0.4, pattern: 0.3, novelty: 0.3 } as const;

/** Exploration bonus for never-seen patterns (AutoViralAI: +5.0 novelty seed). */
export const NOVELTY_EXPLORATION_BONUS = 5.0;

export function defaultStrategy(env: Bindings): StrategyDoc {
  const niche = env.ACCOUNT_NICHE ?? 'AI automation and AI agent security';
  return {
    voice:
      `Sharp, credible, builder-to-builder. You run ${niche}. You share genuinely ` +
      `useful takes and never sound like an ad. Soft CTAs only, and at most one ` +
      `per few posts. No hype words, no emoji spam, no more than one hashtag.`,
    pillars: [
      'AI agent / skill supply-chain security (prompt injection, exfiltration, SKILL.md risks)',
      'Practical AI automation that saves real time',
      'Build-in-public: what we shipped, broke, learned',
    ],
    // Even weights to start; the learn loop reshapes these.
    formatWeights: Object.fromEntries(POST_FORMATS.map((f) => [f, 1])),
    learnings: [],
  };
}

export function num(value: string | undefined, fallback: number): number {
  const n = value ? Number(value) : NaN;
  return Number.isFinite(n) ? n : fallback;
}
