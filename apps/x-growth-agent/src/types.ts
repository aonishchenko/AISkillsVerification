import type { Ai } from '@cloudflare/workers-types';

export type Bindings = {
  AI: Ai;
  DB: D1Database;
  AGENT: DurableObjectNamespace;

  MAX_POSTS_PER_DAY?: string;
  MIN_MINUTES_BETWEEN_POSTS?: string;
  ACCOUNT_NICHE?: string;
  WEBSITE_URL?: string;
  RSS_FEEDS?: string;
  TELEGRAM_CHAT_IDS?: string;
  CF_WRITER_MODEL?: string;
  CF_RANKER_MODEL?: string;

  // Secrets.
  X_API_KEY?: string;
  X_API_SECRET?: string;
  X_ACCESS_TOKEN?: string;
  X_ACCESS_SECRET?: string;
  TELEGRAM_BOT_TOKEN?: string;
};

export type CandidateSource = 'blog' | 'news_rss' | 'telegram' | 'linkedin';

export interface Candidate {
  id: string;
  source: CandidateSource;
  url: string | null;
  title: string | null;
  body: string;
  fetchedAt: number;
}

export interface PostVariant {
  text: string;
  format: string;
  pattern: string;
  aiScore: number;
  patternScore: number;
  noveltyScore: number;
  compositeScore: number;
}

export interface PublishedPost {
  id: string;
  tweetId: string | null;
  text: string;
  format: string;
  pattern: string;
  candidateId: string | null;
  publishedAt: number;
}

export interface EngagementMetrics {
  likes: number;
  replies: number;
  reposts: number;
  quotes: number;
  impressions: number;
  profileClicks: number;
  urlClicks: number;
}

export interface StrategyDoc {
  voice: string;
  pillars: string[];
  formatWeights: Record<string, number>;
  learnings: string[];
}
