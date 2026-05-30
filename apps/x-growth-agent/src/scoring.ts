import { ENGAGEMENT_WEIGHTS } from './config';
import type { EngagementMetrics } from './types';

/**
 * Reward function = X heavy-ranker shape, normalized per-impression so a sharp
 * low-reach post can out-score a viral-but-shallow one. This is the signal the
 * agent learns to maximize, NOT raw likes.
 */
export function computeReward(m: EngagementMetrics): number {
  const w = ENGAGEMENT_WEIGHTS;
  const weighted =
    m.likes * w.likes +
    m.replies * w.replies +
    m.reposts * w.reposts +
    m.quotes * w.quotes +
    m.profileClicks * w.profileClicks +
    m.urlClicks * w.urlClicks;
  const denom = Math.max(m.impressions, 100); // smooth low-impression noise
  return weighted / denom;
}

/**
 * Map a raw reward into a 0-10 score for EWMA pattern updates. Rewards are
 * small positive ratios; this log-curve keeps early samples meaningful while
 * compressing outliers. Calibrated so a "decent" post (~0.1) lands near 5.
 */
export function rewardTo0to10(reward: number): number {
  if (reward <= 0) return 0;
  const scaled = (Math.log10(reward * 100 + 1) / Math.log10(101)) * 10;
  return Math.max(0, Math.min(10, scaled));
}
