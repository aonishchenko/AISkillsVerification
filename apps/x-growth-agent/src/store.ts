import type {
  Bindings,
  Candidate,
  CandidateSource,
  EngagementMetrics,
  PostVariant,
  StrategyDoc,
} from './types';
import { defaultStrategy } from './config';

const now = () => Math.floor(Date.now() / 1000);

/**
 * Thin data-access layer over D1. This is the agent's "knowledge base": the
 * create loop reads strategy + pattern scores from here; the learn loop writes
 * them back from observed engagement.
 */
export class Store {
  constructor(private readonly env: Bindings) {}

  private get db() {
    return this.env.DB;
  }

  // --- Candidates ---------------------------------------------------------

  async addCandidate(c: Omit<Candidate, 'fetchedAt'>): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO candidates (id, source, url, title, body, fetched_at, used)
         VALUES (?, ?, ?, ?, ?, ?, 0)`,
      )
      .bind(c.id, c.source, c.url, c.title, c.body, now())
      .run();
  }

  async unusedCandidates(limit: number): Promise<Candidate[]> {
    const res = await this.db
      .prepare(
        `SELECT id, source, url, title, body, fetched_at AS fetchedAt
         FROM candidates WHERE used = 0 ORDER BY fetched_at DESC LIMIT ?`,
      )
      .bind(limit)
      .all<Candidate & { fetchedAt: number }>();
    return (res.results ?? []) as Candidate[];
  }

  async markCandidateUsed(id: string): Promise<void> {
    await this.db.prepare(`UPDATE candidates SET used = 1 WHERE id = ?`).bind(id).run();
  }

  // --- Posts --------------------------------------------------------------

  async recordPublished(
    id: string,
    tweetId: string,
    variant: PostVariant,
    candidateId: string | null,
    metricsDueAt: number,
  ): Promise<void> {
    const ts = now();
    await this.db.batch([
      this.db
        .prepare(
          `INSERT INTO posts
             (id, tweet_id, text, format, pattern, candidate_id,
              ai_score, pattern_score, novelty_score, composite_score, published_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          id,
          tweetId,
          variant.text,
          variant.format,
          variant.pattern,
          candidateId,
          variant.aiScore,
          variant.patternScore,
          variant.noveltyScore,
          variant.compositeScore,
          ts,
        ),
      this.db.prepare(`INSERT INTO post_log (posted_at) VALUES (?)`).bind(ts),
      this.db
        .prepare(`INSERT OR REPLACE INTO metric_jobs (post_id, due_at) VALUES (?, ?)`)
        .bind(id, metricsDueAt),
    ]);
  }

  async recentPostTexts(limit: number): Promise<string[]> {
    const res = await this.db
      .prepare(`SELECT text FROM posts ORDER BY published_at DESC LIMIT ?`)
      .bind(limit)
      .all<{ text: string }>();
    return (res.results ?? []).map((r) => r.text);
  }

  async postsPerLast24h(): Promise<number> {
    const res = await this.db
      .prepare(`SELECT COUNT(*) AS c FROM post_log WHERE posted_at > ?`)
      .bind(now() - 86400)
      .first<{ c: number }>();
    return res?.c ?? 0;
  }

  async lastPostAt(): Promise<number | null> {
    const res = await this.db
      .prepare(`SELECT MAX(posted_at) AS t FROM post_log`)
      .first<{ t: number | null }>();
    return res?.t ?? null;
  }

  // --- Metric jobs (due engagement checks) --------------------------------

  async dueMetricJobs(limit: number): Promise<string[]> {
    const res = await this.db
      .prepare(`SELECT post_id FROM metric_jobs WHERE due_at <= ? LIMIT ?`)
      .bind(now(), limit)
      .all<{ post_id: string }>();
    return (res.results ?? []).map((r) => r.post_id);
  }

  async getTweetId(postId: string): Promise<string | null> {
    const res = await this.db
      .prepare(`SELECT tweet_id FROM posts WHERE id = ?`)
      .bind(postId)
      .first<{ tweet_id: string | null }>();
    return res?.tweet_id ?? null;
  }

  async saveMetrics(postId: string, m: EngagementMetrics, reward: number): Promise<void> {
    await this.db.batch([
      this.db
        .prepare(
          `UPDATE posts SET metrics_checked = 1, likes = ?, replies = ?, reposts = ?,
             quotes = ?, impressions = ?, profile_clicks = ?, url_clicks = ?, reward = ?
           WHERE id = ?`,
        )
        .bind(
          m.likes,
          m.replies,
          m.reposts,
          m.quotes,
          m.impressions,
          m.profileClicks,
          m.urlClicks,
          reward,
          postId,
        ),
      this.db.prepare(`DELETE FROM metric_jobs WHERE post_id = ?`).bind(postId),
    ]);
  }

  async patternOf(postId: string): Promise<string | null> {
    const res = await this.db
      .prepare(`SELECT pattern FROM posts WHERE id = ?`)
      .bind(postId)
      .first<{ pattern: string }>();
    return res?.pattern ?? null;
  }

  // --- Pattern scores -----------------------------------------------------

  async patternScore(pattern: string): Promise<number> {
    const res = await this.db
      .prepare(`SELECT score FROM pattern_scores WHERE pattern = ?`)
      .bind(pattern)
      .first<{ score: number }>();
    return res?.score ?? 5.0;
  }

  /** EWMA update so recent engagement dominates without being whipsawed. */
  async updatePatternScore(pattern: string, rewardScore0to10: number): Promise<void> {
    const alpha = 0.3;
    const current = await this.db
      .prepare(`SELECT score, n_samples FROM pattern_scores WHERE pattern = ?`)
      .bind(pattern)
      .first<{ score: number; n_samples: number }>();
    const prev = current?.score ?? 5.0;
    const n = (current?.n_samples ?? 0) + 1;
    const next = prev + alpha * (rewardScore0to10 - prev);
    await this.db
      .prepare(
        `INSERT INTO pattern_scores (pattern, score, n_samples, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(pattern) DO UPDATE SET score = ?, n_samples = ?, updated_at = ?`,
      )
      .bind(pattern, next, n, now(), next, n, now())
      .run();
  }

  // --- Strategy -----------------------------------------------------------

  async getStrategy(): Promise<StrategyDoc> {
    const res = await this.db
      .prepare(`SELECT doc FROM strategy WHERE id = 1`)
      .first<{ doc: string }>();
    if (res?.doc) {
      try {
        return JSON.parse(res.doc) as StrategyDoc;
      } catch {
        /* fall through to default */
      }
    }
    const def = defaultStrategy(this.env);
    await this.saveStrategy(def);
    return def;
  }

  async saveStrategy(doc: StrategyDoc): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO strategy (id, doc, updated_at) VALUES (1, ?, ?)
         ON CONFLICT(id) DO UPDATE SET doc = ?, updated_at = ?`,
      )
      .bind(JSON.stringify(doc), now(), JSON.stringify(doc), now())
      .run();
  }

  /** Recent reward samples grouped by pattern, for the learn loop's analysis. */
  async rewardSamples(sinceSeconds: number): Promise<
    Array<{ pattern: string; reward: number; text: string }>
  > {
    const res = await this.db
      .prepare(
        `SELECT pattern, reward, text FROM posts
         WHERE metrics_checked = 1 AND reward IS NOT NULL AND published_at > ?
         ORDER BY published_at DESC LIMIT 50`,
      )
      .bind(now() - sinceSeconds)
      .all<{ pattern: string; reward: number; text: string }>();
    return res.results ?? [];
  }
}

export const candidateId = async (source: CandidateSource, key: string): Promise<string> => {
  const data = new TextEncoder().encode(`${source}:${key}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 24);
};
