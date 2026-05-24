import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { z } from 'zod';
import { readZipSourceFiles, resolveGithubUrl, verifySkillSource, type RawSourceFile } from '@aiskillsverification/engine';

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

const app = new Hono();

app.use('/v1/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
}));

app.get('/healthz', (c) => c.json({ ok: true }));
app.get('/readyz', (c) => c.json({ ok: true }));

app.post('/v1/verify', async (c) => {
  try {
    const contentType = c.req.header('content-type') ?? '';
    let files: RawSourceFile[] = [];
    let sourceType: 'file' | 'zip' | 'github_url' = 'file';
    let sourceRef: string | null = null;

    if (contentType.startsWith('multipart/form-data')) {
      const form = await c.req.formData();
      const file = form.get('file');
      if (!(file instanceof File)) return c.json({ error: 'no_file' }, 400);
      if (file.size > MAX_UPLOAD_BYTES) return c.json({ error: 'file_too_large', maxBytes: MAX_UPLOAD_BYTES }, 413);

      sourceRef = file.name;
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (file.name.toLowerCase().endsWith('.zip')) {
        sourceType = 'zip';
        files = await readZipSourceFiles(bytes, MAX_UPLOAD_BYTES);
      } else {
        files = [{ path: file.name || 'skill.md', bytes }];
      }
    } else {
      const body = await c.req.json().catch(() => null);
      const parsed = z.object({
        githubUrl: z.string().url().regex(/^https:\/\/(github\.com|raw\.githubusercontent\.com)\//),
      }).safeParse(body);
      if (!parsed.success) return c.json({ error: 'expected_multipart_file_or_github_url' }, 400);
      sourceType = 'github_url';
      sourceRef = parsed.data.githubUrl;
      files = await resolveGithubUrl(parsed.data.githubUrl);
    }

    const report = await verifySkillSource(files, { sourceType, sourceRef });
    return c.json(report);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'verification_failed';
    const status = message === 'no_supported_source_files' ? 400 : 422;
    return c.json({ error: message }, status);
  }
});

export default app;
