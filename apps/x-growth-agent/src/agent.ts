import type { Bindings } from './types';
import { Store } from './store';
import { collect } from './collectors';
import { runCreateLoop } from './generate';
import { runLearnLoop } from './learn';

/**
 * Durable Object holding the long-lived, stateful agent (the Cloudflare Agents
 * pattern). A single instance owns both loops, which serializes posting so two
 * overlapping cron invocations can never double-post.
 */
export class XGrowthAgent {
  private readonly store: Store;

  constructor(
    _state: DurableObjectState,
    private readonly env: Bindings,
  ) {
    this.store = new Store(env);
  }

  async fetch(req: Request): Promise<Response> {
    const { pathname } = new URL(req.url);
    try {
      if (pathname === '/run/create') {
        await collect(this.env, this.store); // refresh candidates first
        const status = await runCreateLoop(this.env, this.store);
        return Response.json({ ok: true, status });
      }
      if (pathname === '/run/learn') {
        const status = await runLearnLoop(this.env, this.store);
        return Response.json({ ok: true, status });
      }
      if (pathname === '/run/collect') {
        const added = await collect(this.env, this.store);
        return Response.json({ ok: true, added });
      }
      return new Response('not found', { status: 404 });
    } catch (err) {
      console.error('agent error', pathname, String(err));
      return Response.json({ ok: false, error: String(err) }, { status: 500 });
    }
  }
}
