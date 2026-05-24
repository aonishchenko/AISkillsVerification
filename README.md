# AI Skills Verification

Open-source verification engine for AI agent skills, extracted from the core logic of SafeSkillMD.com

It checks skill files and bundles for prompt injection, data exfiltration, secret access, risky helpers, hidden instructions, and excessive permissions before you add them to an agent environment.

This repository intentionally excludes the hosted product pieces:

- no user registration or authentication
- no Stripe subscription or billing logic
- no Resend/contact email integration
- no terms, privacy, cookie, contact, or site-map pages
- no account, quota, or subscription UI

## What Is Included

```
.
├── apps/
│   ├── api/       # Minimal Cloudflare Worker API: POST /v1/verify
│   └── web/       # Minimal React UI for local/manual verification
├── packages/
│   ├── rules/     # Static rule engine
│   └── engine/    # Bundle normalization, ZIP/GitHub loading, scoring, purpose inference
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
6. Score findings into `safe`, `warn`, or `unsafe`.

The open-source engine is deterministic and does not require LLM API keys.

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
);

console.log(report.score, report.verdict, report.findings);
```

## License

MIT
