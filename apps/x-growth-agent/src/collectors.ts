import type { Bindings, CandidateSource } from './types';
import { Store, candidateId } from './store';

/**
 * Compliant ingestion only:
 *   - RSS for the website blog, AI-security news, Google News queries, and a
 *     LinkedIn RSS-bridge feed.
 *   - Telegram via the official Bot API (getUpdates), not scraping.
 * We never scrape X's website — that is what gets accounts banned. X is used
 * for posting + reading our own organic metrics through the official API only.
 */
export async function collect(env: Bindings, store: Store): Promise<number> {
  let added = 0;
  const feeds = (env.RSS_FEEDS ?? '').split(',').map((s) => s.trim()).filter(Boolean);

  for (const feed of feeds) {
    try {
      const source: CandidateSource = feed.includes('linkedin')
        ? 'linkedin'
        : feed.includes(new URL(env.WEBSITE_URL ?? 'https://example.com').hostname)
          ? 'blog'
          : 'news_rss';
      added += await collectRss(feed, source, store);
    } catch (err) {
      console.error('rss collect failed', feed, String(err));
    }
  }

  if (env.TELEGRAM_BOT_TOKEN) {
    try {
      added += await collectTelegram(env, store);
    } catch (err) {
      console.error('telegram collect failed', String(err));
    }
  }

  return added;
}

async function collectRss(url: string, source: CandidateSource, store: Store): Promise<number> {
  const res = await fetch(url, { headers: { 'user-agent': 'x-growth-agent/0.1 (+rss)' } });
  if (!res.ok) return 0;
  const xml = await res.text();
  const items = parseRssItems(xml).slice(0, 10);
  let added = 0;
  for (const item of items) {
    const id = await candidateId(source, item.link || item.title);
    await store.addCandidate({
      id,
      source,
      url: item.link || null,
      title: item.title || null,
      body: `${item.title}\n\n${item.description}`.trim().slice(0, 2000),
    });
    added += 1;
  }
  return added;
}

interface RssItem {
  title: string;
  link: string;
  description: string;
}

/** Minimal, dependency-free RSS/Atom extraction good enough for headlines. */
function parseRssItems(xml: string): RssItem[] {
  const items: RssItem[] = [];
  const blocks = xml.match(/<(item|entry)[\s\S]*?<\/(item|entry)>/gi) ?? [];
  for (const block of blocks) {
    items.push({
      title: decode(pick(block, 'title')),
      link: pickLink(block),
      description: decode(pick(block, 'description') || pick(block, 'summary') || pick(block, 'content')),
    });
  }
  return items;
}

function pick(block: string, tag: string): string {
  const m = block.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
  if (!m) return '';
  return m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, '').trim();
}

function pickLink(block: string): string {
  const rss = block.match(/<link[^>]*>([\s\S]*?)<\/link>/i);
  if (rss && rss[1].trim()) return rss[1].trim();
  const atom = block.match(/<link[^>]*href=["']([^"']+)["']/i);
  return atom ? atom[1] : '';
}

function decode(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

async function collectTelegram(env: Bindings, store: Store): Promise<number> {
  const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getUpdates?limit=20&allowed_updates=["channel_post","message"]`;
  const res = await fetch(url);
  if (!res.ok) return 0;
  const data = (await res.json()) as {
    result?: Array<{ channel_post?: { text?: string; message_id: number }; message?: { text?: string; message_id: number } }>;
  };
  let added = 0;
  for (const u of data.result ?? []) {
    const post = u.channel_post ?? u.message;
    const text = post?.text;
    if (!text || text.length < 40) continue;
    const id = await candidateId('telegram', String(post!.message_id));
    await store.addCandidate({ id, source: 'telegram', url: null, title: null, body: text.slice(0, 2000) });
    added += 1;
  }
  return added;
}
