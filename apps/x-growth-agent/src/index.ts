import { Hono } from 'hono';
import type { Bindings } from './types';

export { XGrowthAgent } from './agent';

const app = new Hono<{ Bindings: Bindings }>();

app.get('/healthz', (c) => c.json({ ok: true }));
app.get('/readyz', (c) => c.json({ ok: true }));

// Single shared agent instance owns all state and serializes the loops.
function agent(env: Bindings) {
  return env.AGENT.get(env.AGENT.idFromName('singleton'));
}

// Manual triggers (handy for testing without waiting for cron).
app.post('/run/:loop', async (c) => {
  const loop = c.req.param('loop');
  if (!['create', 'learn', 'collect'].includes(loop)) return c.json({ error: 'unknown_loop' }, 400);
  const res = await agent(c.env).fetch(new Request(`https://do/run/${loop}`));
  return new Response(res.body, { status: res.status, headers: res.headers });
});

export default {
  fetch: app.fetch,

  /**
   * Cron router. Two schedules in wrangler.toml:
   *   - learn loop runs on its single morning cron
   *   - every other firing drives the create loop (budget-capped to 1-4/day)
   */
  async scheduled(event: ScheduledController, env: Bindings, ctx: ExecutionContext): Promise<void> {
    const learnCron = '30 6 * * *';
    const loop = event.cron === learnCron ? 'learn' : 'create';
    ctx.waitUntil(
      agent(env)
        .fetch(new Request(`https://do/run/${loop}`))
        .then(async (r) => console.log(`cron ${loop}:`, await r.text()))
        .catch((err) => console.error(`cron ${loop} failed`, String(err))),
    );
  },
} satisfies ExportedHandler<Bindings>;
