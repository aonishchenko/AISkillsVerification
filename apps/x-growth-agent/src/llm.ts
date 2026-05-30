import type { Ai } from '@cloudflare/workers-types';

/** Thin Workers AI wrapper: chat completion + embeddings, both free-tier. */
export class Llm {
  constructor(
    private readonly ai: Ai,
    private readonly textModel: string,
  ) {}

  async chat(system: string, user: string, maxTokens = 512): Promise<string> {
    const res = (await this.ai.run(this.textModel as never, {
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
      max_tokens: maxTokens,
      temperature: 0.8,
    } as never)) as { response?: string };
    return (res.response ?? '').trim();
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
