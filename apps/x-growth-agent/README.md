# X Growth Agent

A fully autonomous, self-learning agent that maintains and indirectly promotes a
small-business X (Twitter) account. It posts 1–4 times/day about AI automation
and AI-agent security, sourcing material from RSS (your blog + news), Telegram
channels, and a LinkedIn RSS bridge — then **learns from real engagement** and
improves what it posts, with **zero human involvement** after deployment.

It runs almost entirely on Cloudflare's free tier (Workers + Durable Objects +
D1 + Workers AI). The only paid dependency is the X API Basic tier, which is the
only ToS-compliant way to auto-post.

## LLM provider (Workers AI or Claude)

`LLM_PROVIDER` selects the brain used for drafting, scoring, the editor gate,
and the daily strategy rewrite:

- `workers-ai` (default) — free Cloudflare models. ~$0/mo.
- `anthropic` — Claude. Noticeably better brand voice, editing, and strategy
  reasoning. **Sonnet** drafts/edits/strategizes; **Haiku** runs the cheap
  scoring calls; the repeated system prompt is **prompt-cached** to cut input
  cost ~90%. ~$3–5/mo at 1–4 posts/day.

Embeddings for the novelty signal always use Cloudflare's free model, so the
Anthropic path needs no embeddings key.

To use Claude, set `LLM_PROVIDER = "anthropic"` in `wrangler.toml` and:

```bash
wrangler secret put ANTHROPIC_API_KEY
```

## How it works

Two cron-driven loops share one knowledge base (D1), modeled on the open-source
projects researched for this design:

| Borrowed from | What we reuse |
|---|---|
| [AutoViralAI](https://github.com/kgarbacinski/AutoViralAI) | The self-learning loop: create + learn pipelines, 3-signal ranking (AI viral score 0.4 / historical pattern 0.3 / novelty 0.3 + exploration bonus), and "rewrite strategy from what worked". |
| [awesome-twitter-algo](https://github.com/igorbrigadir/awesome-twitter-algo) | The reward weights (replies 27×, profile clicks 12×, reposts 1×, likes 0.5×) so we optimize reach-shaped engagement, not raw likes. |
| [OpenFang](https://github.com/RightNow-AI/openfang) | Rotating post formats, each a learnable pattern. |
| [LangChain social-media-agent](https://github.com/langchain-ai/social-media-agent) | Prompt architecture: business context + few-shot + structure + content rules. |

### Create loop (budget-capped to 1–4/day)
`collect candidates → generate variants per format → rank (3 signals) →
auto editor/brand-safety gate → publish via X API → schedule 24h metrics check`

The auto-editor replaces AutoViralAI's human Telegram approval node, so the
system is fully autonomous.

### Learn loop (daily)
`collect 24h engagement → compute X-algo-weighted reward → update per-pattern
EWMA scores → rewrite strategy learnings → reshape format weights`

Higher-reward formats automatically get drafted more often; a floor keeps
exploration alive so the agent keeps discovering new winners.

## Why it won't get the account banned

- **Posting only via the official X API v2** (sanctioned automation).
- **Reading news via RSS + the Telegram Bot API** — never scraping X.
- **No auto-follow / auto-like / auto-reply** — the behaviors X actually
  penalizes are simply not in the agent's action space.
- Reads only **our own** organic metrics.

## Setup

```bash
pnpm install

# 1. Create the D1 database and put its id in wrangler.toml.
cp apps/x-growth-agent/wrangler.example.toml apps/x-growth-agent/wrangler.toml
wrangler d1 create x_growth_agent          # paste database_id into wrangler.toml
pnpm --filter @aiskillsverification/x-growth-agent db:init

# 2. Secrets (X API Basic tier; Telegram optional).
wrangler secret put X_API_KEY
wrangler secret put X_API_SECRET
wrangler secret put X_ACCESS_TOKEN
wrangler secret put X_ACCESS_SECRET
wrangler secret put TELEGRAM_BOT_TOKEN     # optional

# 3. Point RSS_FEEDS / niche / website at your business in wrangler.toml.

# 4. Deploy. Cron then runs everything autonomously.
pnpm --filter @aiskillsverification/x-growth-agent deploy
```

Manual triggers for testing (no need to wait for cron):

```bash
curl -X POST https://<your-worker>/run/collect
curl -X POST https://<your-worker>/run/create
curl -X POST https://<your-worker>/run/learn
```

## Cost

- Cloudflare (Workers, Durable Objects, D1, embeddings): ~$0/mo at this volume.
- LLM brain: ~$0/mo on `workers-ai`, or ~$3–5/mo on `anthropic` (Claude).
- X API Basic tier: ~$100/mo — required for compliant auto-posting, and the
  dominant cost regardless of LLM provider.

## Tuning

- `MAX_POSTS_PER_DAY`, `MIN_MINUTES_BETWEEN_POSTS` — cadence.
- `RSS_FEEDS` — your blog, AI-security news, Google News RSS queries, LinkedIn bridge.
- Format list and reward weights live in `src/config.ts`.
- Cron times live in `wrangler.toml` (`[triggers].crons`).
