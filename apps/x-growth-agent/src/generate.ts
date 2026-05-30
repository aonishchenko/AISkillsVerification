import type { Bindings, Candidate, PostVariant, StrategyDoc } from './types';
import { Store } from './store';
import { Llm, cosineDistance } from './llm';
import { XClient } from './x-client';
import {
  NOVELTY_EXPLORATION_BONUS,
  POST_FORMATS,
  RANK_WEIGHTS,
  num,
} from './config';

const MAX_TWEET_LEN = 280;

/**
 * The CREATE loop (adapted from AutoViralAI's creation pipeline):
 *   budget check -> collect candidate -> generate variants -> 3-signal rank
 *   -> auto editor/brand-safety gate (replaces the human approval node)
 *   -> publish -> schedule a 24h metrics check.
 * Returns a short status string for logging.
 */
export async function runCreateLoop(env: Bindings, store: Store): Promise<string> {
  // 1. Budget guardrails: cron may fire often; we cap real posts/day + spacing.
  const maxPerDay = num(env.MAX_POSTS_PER_DAY, 4);
  const minGapMin = num(env.MIN_MINUTES_BETWEEN_POSTS, 180);
  if ((await store.postsPerLast24h()) >= maxPerDay) return 'skip: daily budget reached';
  const last = await store.lastPostAt();
  if (last && Date.now() / 1000 - last < minGapMin * 60) return 'skip: min spacing not elapsed';

  // 2. Pick a fresh candidate.
  const candidates = await store.unusedCandidates(20);
  if (candidates.length === 0) return 'skip: no candidates';
  const candidate = candidates[0];

  const strategy = await store.getStrategy();
  const llm = new Llm(env.AI, env.CF_WRITER_MODEL ?? '@cf/meta/llama-3.3-70b-instruct');

  // 3. Choose which formats to draft, weighted by learned performance.
  const formats = pickFormats(strategy, 3);

  // 4. Generate one variant per chosen format.
  const drafts: Array<{ text: string; format: string }> = [];
  for (const format of formats) {
    const text = await draftPost(llm, strategy, candidate, format, env);
    if (text) drafts.push({ text: clip(text), format });
  }
  if (drafts.length === 0) return 'skip: no drafts produced';

  // 5. Three-signal ranking.
  const recent = await store.recentPostTexts(20);
  const recentEmb = await Promise.all(recent.map((t) => llm.embed(t)));
  const variants: PostVariant[] = [];
  for (const d of drafts) {
    const aiScore = await aiViralScore(llm, strategy, d.text);
    const patternScore = await store.patternScore(d.format);
    const novelty = await noveltyScore(llm, d.text, recentEmb);
    const composite =
      RANK_WEIGHTS.ai * aiScore +
      RANK_WEIGHTS.pattern * patternScore +
      RANK_WEIGHTS.novelty * novelty;
    variants.push({
      text: d.text,
      format: d.format,
      pattern: d.format,
      aiScore,
      patternScore,
      noveltyScore: novelty,
      compositeScore: composite,
    });
  }
  variants.sort((a, b) => b.compositeScore - a.compositeScore);

  // 6. Auto editor / brand-safety gate (no human in the loop).
  let chosen: PostVariant | null = null;
  for (const v of variants) {
    if (await passesEditor(llm, strategy, v.text)) {
      chosen = v;
      break;
    }
  }
  if (!chosen) return 'skip: all variants failed editor gate';

  // 7. Publish + schedule metrics check 24h out.
  const x = new XClient(env);
  const tweetId = await x.postTweet(chosen.text);
  const postId = crypto.randomUUID();
  const dueAt = Math.floor(Date.now() / 1000) + 24 * 3600;
  await store.recordPublished(postId, tweetId, chosen, candidate.id, dueAt);
  await store.markCandidateUsed(candidate.id);
  return `posted ${tweetId} format=${chosen.format} composite=${chosen.compositeScore.toFixed(2)}`;
}

function pickFormats(strategy: StrategyDoc, n: number): string[] {
  const weighted: Array<{ f: string; w: number }> = POST_FORMATS.map((f) => ({
    f,
    w: Math.max(0.05, strategy.formatWeights[f] ?? 1),
  }));
  const picks: string[] = [];
  const pool = [...weighted];
  for (let i = 0; i < n && pool.length > 0; i += 1) {
    const total = pool.reduce((s, p) => s + p.w, 0);
    let r = Math.random() * total;
    let idx = 0;
    for (let j = 0; j < pool.length; j += 1) {
      r -= pool[j].w;
      if (r <= 0) {
        idx = j;
        break;
      }
    }
    picks.push(pool[idx].f);
    pool.splice(idx, 1);
  }
  return picks;
}

async function draftPost(
  llm: Llm,
  strategy: StrategyDoc,
  candidate: Candidate,
  format: string,
  env: Bindings,
): Promise<string> {
  // Prompt architecture borrowed from LangChain's social-media-agent:
  // business context + structure + content rules + the source material.
  const system =
    `You write tweets for an X account about ${env.ACCOUNT_NICHE ?? 'AI automation and security'}.\n` +
    `VOICE: ${strategy.voice}\n` +
    `CONTENT PILLARS: ${strategy.pillars.join('; ')}\n` +
    (strategy.learnings.length ? `WHAT HAS WORKED LATELY: ${strategy.learnings.join('; ')}\n` : '') +
    `FORMAT = "${format}". ${FORMAT_GUIDE[format] ?? ''}\n` +
    `RULES: <=280 chars; no more than one hashtag; no emoji spam; sound human, ` +
    `not like an ad; only a soft CTA to ${env.WEBSITE_URL ?? 'the site'} when it ` +
    `genuinely fits (at most occasionally). Output ONLY the tweet text.`;
  const user =
    `Source material (${candidate.source}${candidate.url ? `, ${candidate.url}` : ''}):\n` +
    `${candidate.title ? candidate.title + '\n' : ''}${candidate.body}`;
  return llm.chat(system, user, 200);
}

const FORMAT_GUIDE: Record<string, string> = {
  news_take: 'React to the news with a sharp, specific opinion others would not state.',
  insight: 'Distill one non-obvious lesson. Make the reader feel smarter.',
  build_in_public: 'Share a concrete thing built/discovered, with a real detail.',
  contrarian: 'Take a defensible against-the-grain stance and back it in one line.',
  how_to: 'Give one actionable tip the reader can use today.',
  thread_opener: 'Write a strong hook line that promises a thread of value.',
  question: 'Ask a genuine, specific question that invites replies.',
};

async function aiViralScore(llm: Llm, strategy: StrategyDoc, text: string): Promise<number> {
  const res = await llm.json<{ score: number }>(
    'You rate a tweet 0-10 for hook strength, emotional/intellectual trigger, and shareability for a niche audience.',
    `Niche pillars: ${strategy.pillars.join('; ')}\nTweet: "${text}"\nReturn {"score": <0-10>}.`,
    64,
  );
  return clamp10(res?.score ?? 5);
}

async function noveltyScore(llm: Llm, text: string, recentEmb: number[][]): Promise<number> {
  if (recentEmb.length === 0) return NOVELTY_EXPLORATION_BONUS;
  const emb = await llm.embed(text);
  let minDist = 1;
  for (const e of recentEmb) minDist = Math.min(minDist, cosineDistance(emb, e));
  return clamp10(minDist * 10); // farther from recent posts = more novel
}

async function passesEditor(llm: Llm, strategy: StrategyDoc, text: string): Promise<boolean> {
  if (text.length > MAX_TWEET_LEN || text.length < 15) return false;
  const res = await llm.json<{ ok: boolean }>(
    'You are a strict brand-safety + quality editor for an AI-security company tweet.',
    `Reject if: factually overclaims, hallucinates a feature, off-brand, spammy, ` +
      `offensive, or could trigger reports. Voice: ${strategy.voice}\n` +
      `Tweet: "${text}"\nReturn {"ok": true|false}.`,
    64,
  );
  return res?.ok === true;
}

function clip(text: string): string {
  const t = text.replace(/^["']|["']$/g, '').trim();
  return t.length <= MAX_TWEET_LEN ? t : t.slice(0, MAX_TWEET_LEN - 1).trimEnd() + '…';
}

function clamp10(n: number): number {
  return Math.max(0, Math.min(10, Number.isFinite(n) ? n : 5));
}
