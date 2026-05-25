# AI Skills Verification

Open-source verification engine for AI agent skills, extracted from the core logic of [SafeSkillMD.com](https://safeskillmd.com/)

It checks skill files and bundles for prompt injection, data exfiltration, secret access, risky helpers, hidden instructions, and excessive permissions before you add them to an agent environment. The engine includes both static rules and the optional two-auditor LLM consensus flow used by the hosted service.

## What Is Included

```
.
├── apps/
│   ├── api/       # Minimal Cloudflare Worker API: POST /v1/verify
│   └── web/       # Minimal React UI for local/manual verification
├── packages/
│   ├── rules/     # Static rule engine
│   └── engine/    # Bundle loading, static rules, LLM consensus, scoring, purpose inference
└── examples/      # Clean and malicious sample skills
```

## Supported Inputs

- Single source files: `.md`, `.mdx`, `.txt`, `.yml`, `.yaml`, `.json`, `.toml`, `.py`, `.js`, `.ts`, `.tsx`, `.jsx`, `.sh`, `.rb`, `.go`, `.rs`
- ZIP bundles containing supported source files
- GitHub file URLs
- GitHub folder URLs
- GitHub repository URLs that contain one or more `SKILL.md` files

Unsupported/binary files are ignored during normalization.

## Verification Pipeline

1. Load source files from upload, ZIP, or GitHub.
2. Normalize text and compute a content hash.
3. Parse skill metadata from `SKILL.md` or the primary Markdown file.
4. Run static rules over the bundle.
5. Infer skill purpose from frontmatter and text signals.
6. If configured, run two LLM auditors in parallel.
7. Aggregate auditor outputs with the cheaper auditor model.
8. Score findings into `safe`, `warn`, or `unsafe`.

Static-only verification works without API keys. Full LLM consensus works with Cloudflare Workers AI, or with external OpenAI, Anthropic, or Google API keys. If more than one external key is configured, the engine selects the cheapest external model as the second auditor. Aggregation uses the cheaper of the two auditor models.

## Quick Start

```bash
pnpm install
pnpm test
pnpm typecheck
```

Run the smoke example:

```bash
pnpm exec tsx examples/smoke.mjs
```

Run the local API:

```bash
cp apps/api/wrangler.example.toml apps/api/wrangler.toml
pnpm dev:api
```

The included Wrangler config enables Cloudflare Workers AI by default:

```toml
[ai]
binding = "AI"
```

Optional external providers can be configured as Worker secrets:

```bash
wrangler secret put OPENAI_API_KEY
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put GOOGLE_API_KEY
```

Optional model overrides are exposed as environment variables:

```toml
OPENAI_TEXT_MODEL = "gpt-5.4-nano"
ANTHROPIC_TEXT_MODEL = "claude-haiku-4-5-20251001"
GOOGLE_TEXT_MODEL = "gemini-3.1-flash-lite"
```

Run the web UI:

```bash
pnpm dev
```

The web UI runs on `http://localhost:5173` and proxies `/v1` requests to the Worker dev server on `http://127.0.0.1:8787`.

## API

### Verify A File Or ZIP

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/verify \
  -F "file=@examples/mal-lipost.md"
```

### Verify A GitHub URL

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"githubUrl":"https://github.com/owner/repo/tree/main/path/to/skill"}'
```

### Health

```bash
GET /healthz
GET /readyz
```

## Engine Usage

```ts
import { verifySkillSource } from '@aiskillsverification/engine';

const encoder = new TextEncoder();
const report = await verifySkillSource(
  [{ path: 'SKILL.md', bytes: encoder.encode(markdown) }],
  { sourceType: 'file', sourceRef: 'SKILL.md' },
  {
    llm: {
      workersAi: env.AI,
      openaiApiKey: env.OPENAI_API_KEY,
      anthropicApiKey: env.ANTHROPIC_API_KEY,
      googleApiKey: env.GOOGLE_API_KEY,
    },
  },
);

console.log(report.score, report.verdict, report.findings);
```

## License

Apache-2.0
