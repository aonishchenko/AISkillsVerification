import type { Bindings, StrategyDoc } from './types';
import { Store } from './store';
import { Llm } from './llm';
import { XClient } from './x-client';
import { computeReward, rewardTo0to10 } from './scoring';
import { POST_FORMATS } from './config';

/**
 * The LEARN loop (AutoViralAI's learning pipeline, daily):
 *   1. collect engagement for posts whose 24h check is due
 *   2. compute X-algo-weighted reward + update per-pattern EWMA scores
 *   3. analyze recent winners/losers and rewrite the strategy doc
 * The rewritten strategy + pattern scores feed straight back into the create
 * loop, so the agent gets measurably better each day with zero human input.
 */
export async function runLearnLoop(env: Bindings, store: Store): Promise<string> {
  const x = new XClient(env);

  // 1 + 2. Engagement collection and pattern-score updates.
  const due = await store.dueMetricJobs(20);
  let measured = 0;
  for (const postId of due) {
    const tweetId = await store.getTweetId(postId);
    if (!tweetId) continue;
    const metrics = await x.tweetMetrics(tweetId).catch(() => null);
    if (!metrics) continue; // leave the job; retry next run
    const reward = computeReward(metrics);
    await store.saveMetrics(postId, metrics, reward);
    const pattern = await store.patternOf(postId);
    if (pattern) await store.updatePatternScore(pattern, rewardTo0to10(reward));
    measured += 1;
  }

  // 3. Rewrite strategy from recent reward samples.
  const samples = await store.rewardSamples(14 * 86400);
  if (samples.length >= 3) {
    await rewriteStrategy(env, store, samples);
  }

  // Reshape format weights directly from learned pattern scores so the create
  // loop favors high-reward formats while keeping a floor for exploration.
  const strategy = await store.getStrategy();
  const weights: Record<string, number> = {};
  for (const f of POST_FORMATS) {
    const s = await store.patternScore(f);
    weights[f] = Math.max(0.2, s / 5); // score 5 (neutral) -> weight 1.0
  }
  strategy.formatWeights = weights;
  await store.saveStrategy(strategy);

  return `learn: measured=${measured} samples=${samples.length}`;
}

async function rewriteStrategy(
  env: Bindings,
  store: Store,
  samples: Array<{ pattern: string; reward: number; text: string }>,
): Promise<void> {
  // Strategy rewrite is high-value reasoning -> use the stronger writer model.
  const llm = Llm.create(env, 'writer');
  const sorted = [...samples].sort((a, b) => b.reward - a.reward);
  const top = sorted.slice(0, 5);
  const bottom = sorted.slice(-5);
  const strategy = await store.getStrategy();

  const res = await llm.json<{ learnings: string[] }>(
    'You are a social-media strategist analyzing what drove engagement, then ' +
      'producing concise, actionable learnings to steer future posts.',
    `Top posts (high reward):\n${top.map((s) => `- [${s.pattern}] ${s.text}`).join('\n')}\n\n` +
      `Weak posts (low reward):\n${bottom.map((s) => `- [${s.pattern}] ${s.text}`).join('\n')}\n\n` +
      `Return {"learnings": ["...", "..."]} with 3-6 short, specific, non-generic rules ` +
      `(hooks, topics, structures, what to avoid) for the next batch of posts.`,
    512,
  );

  if (res?.learnings?.length) {
    const next: StrategyDoc = { ...strategy, learnings: res.learnings.slice(0, 6) };
    await store.saveStrategy(next);
  }
}
