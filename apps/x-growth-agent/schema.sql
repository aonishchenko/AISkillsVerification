-- Knowledge base for the X growth agent.
-- Ported from AutoViralAI's four namespaces (config / strategy / performance /
-- content) into D1 (SQLite). The create loop reads strategy + pattern scores;
-- the learn loop writes them back from observed engagement.

-- Raw content candidates pulled from RSS, Telegram, and the website blog.
CREATE TABLE IF NOT EXISTS candidates (
  id            TEXT PRIMARY KEY,          -- stable hash of the source url/text
  source        TEXT NOT NULL,             -- 'blog' | 'news_rss' | 'telegram' | 'linkedin'
  url           TEXT,
  title         TEXT,
  body          TEXT NOT NULL,
  fetched_at    INTEGER NOT NULL,          -- unix seconds
  used          INTEGER NOT NULL DEFAULT 0 -- 1 once a post was generated from it
);
CREATE INDEX IF NOT EXISTS idx_candidates_unused ON candidates (used, fetched_at);

-- Every post we publish, plus the variant metadata used for learning.
CREATE TABLE IF NOT EXISTS posts (
  id              TEXT PRIMARY KEY,        -- our internal id
  tweet_id        TEXT,                    -- X-assigned id once published
  text            TEXT NOT NULL,
  format          TEXT NOT NULL,           -- rotating format key (see config.ts)
  pattern         TEXT NOT NULL,           -- learnable "pattern" label
  candidate_id    TEXT,
  ai_score        REAL,                    -- variant viral score 0-10
  pattern_score   REAL,                    -- historical pattern score at gen time
  novelty_score   REAL,                    -- embedding-distance novelty 0-10
  composite_score REAL,
  published_at    INTEGER,
  -- Engagement, filled in by the learn loop from the X API.
  metrics_checked INTEGER NOT NULL DEFAULT 0,
  likes           INTEGER,
  replies         INTEGER,
  reposts         INTEGER,
  quotes          INTEGER,
  impressions     INTEGER,
  profile_clicks  INTEGER,
  url_clicks      INTEGER,
  reward          REAL                     -- X-algo-weighted engagement score
);
CREATE INDEX IF NOT EXISTS idx_posts_pending_metrics ON posts (metrics_checked, published_at);

-- Pending "check engagement 24-48h later" jobs.
CREATE TABLE IF NOT EXISTS metric_jobs (
  post_id    TEXT PRIMARY KEY,
  due_at     INTEGER NOT NULL              -- unix seconds; learn loop processes when due
);

-- Rolling performance score per (format, pattern). EWMA of reward.
CREATE TABLE IF NOT EXISTS pattern_scores (
  pattern     TEXT PRIMARY KEY,
  score       REAL NOT NULL DEFAULT 5.0,   -- 0-10, seeded neutral
  n_samples   INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL DEFAULT 0
);

-- Single-row evolving strategy document (the thing the agent "rewrites").
CREATE TABLE IF NOT EXISTS strategy (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  doc         TEXT NOT NULL,               -- JSON: voice, pillars, format weights, learnings
  updated_at  INTEGER NOT NULL
);

-- Posting budget ledger so cron frequency is decoupled from posts/day.
CREATE TABLE IF NOT EXISTS post_log (
  posted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_post_log_time ON post_log (posted_at);
