import type { Ai } from '@cloudflare/workers-types';
import type { Bindings } from './types';

/**
 * Pluggable LLM: the chat/json brain is either Cloudflare Workers AI (free) or
 * the Anthropic API (Claude — better voice, editing, and strategy reasoning),
 * chosen by env.LLM_PROVIDER. Embeddings for the novelty signal always use
 * Cloudflare's free model regardless of provider, so no embeddings key needed.
 */

type ChatProvider = (system: string, user: string, maxTokens: number) => Promise<string>;

export type LlmRole = 'writer' | 'ranker';

export class Llm {
  private constructor(
    private readonly ai: Ai,
    private readonly chatProvider: ChatProvider,
  ) {}

  static create(env: Bindings, role: LlmRole): Llm {
    const provider = (env.LLM_PROVIDER ?? 'workers-ai').toLowerCase();
    if (provider === 'anthropic') {
      return new Llm(env.AI, anthropicProvider(env, role));
    }
    return new Llm(env.AI, workersAiProvider(env, role));
  }

  async chat(system: string, user: string, maxTokens = 512): Promise<string> {
    return this.chatProvider(system, user, maxTokens);
  }

  /** Returns parsed JSON of type T, or null if the model didn't produce valid JSON. */
  async json<T>(system: string, user: string, maxTokens = 768): Promise<T | null> {
    const raw = await this.chat(
      `${system}\nRespond with ONLY valid minified JSON. No markdown, no prose.`,
      user,
      maxTokens,
    );
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) return null;
    try {
      return JSON.parse(match[0]) as T;
    } catch {
      return null;
    }
  }

  async embed(text: string): Promise<number[]> {
    const res = (await this.ai.run('@cf/baai/bge-base-en-v1.5' as never, {
      text: [text.slice(0, 2000)],
    } as never)) as { data?: number[][] };
    return res.data?.[0] ?? [];
  }
}

// --- Workers AI ----------------------------------------------------------

function workersAiProvider(env: Bindings, role: LlmRole): ChatProvider {
  const model =
    role === 'writer'
      ? (env.CF_WRITER_MODEL ?? '@cf/meta/llama-3.3-70b-instruct')
      : (env.CF_RANKER_MODEL ?? '@cf/meta/llama-3.3-70b-instruct');
  return async (system, user, maxTokens) => {
    const res = (await env.AI.run(model as never, {
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
      max_tokens: maxTokens,
      temperature: 0.8,
    } as never)) as { response?: string };
    return (res.response ?? '').trim();
  };
}

// --- Anthropic (Claude) with prompt caching ------------------------------

function anthropicProvider(env: Bindings, role: LlmRole): ChatProvider {
  const model =
    role === 'writer'
      ? (env.ANTHROPIC_MODEL_WRITER ?? 'claude-sonnet-4-6')
      : (env.ANTHROPIC_MODEL_RANKER ?? 'claude-haiku-4-5-20251001');
  return async (system, user, maxTokens) => {
    const apiKey = env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error('anthropic_api_key_missing');
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        temperature: 0.8,
        // System prompt (voice, pillars, format guide, rubrics) repeats across
        // calls, so cache it to cut input cost ~90%.
        system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
        messages: [{ role: 'user', content: user }],
      }),
    });
    if (!res.ok) throw new Error(`anthropic_failed_${res.status}:${await res.text()}`);
    const data = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
    return (data.content ?? [])
      .filter((b) => b.type === 'text')
      .map((b) => b.text ?? '')
      .join('')
      .trim();
  };
}

export function cosineDistance(a: number[], b: number[]): number {
  if (a.length === 0 || b.length === 0 || a.length !== b.length) return 1;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  if (denom === 0) return 1;
  return 1 - dot / denom;
}
