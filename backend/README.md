# PhishShield AI — Backend API

Node + Express backend for the GRAVITON 2026 PhishShield project. Implements
`API_CONTRACT.md` (see the main draft folder). The analysis engine is
`analyzer.js` — the **same file** as the browser draft, kept byte-identical,
so API responses match the draft's behavior by construction.

## Run locally

```bash
npm install
node server.js
# or: npm start
```

The server listens on `PORT` (default `3000`). No database, no auth, no API
key. Inputs are analyzed in memory and never stored.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness check: `{ status: "ok", ... }` |
| POST | `/api/analyze` | Body `{ input, type? }` (`type`: `"auto"` default, `"url"`, `"message"`). Returns `{ kind, score, verdict, reasons, host?, urls?, note?, redirectChain?, finalUrl?, threatIntel?, ai? }`. URL mode only: shortener links get redirect-chain analysis, non-official URLs get a URLhaus lookup (see contract). Borderline engine scores (30–59) get an AI second opinion in `ai` when `AI_SERVICE_URL` is set. Verdict bands: 0–29 safe, 30–59 suspicious, 60–100 phishing. Rate-limited: 100 requests per 15 minutes per IP (429 `RATE_LIMITED`). |
| GET | `/api/samples` | Demo samples for the frontend's "Try a sample" chips. |

Errors are always `{ error: { code, message } }`: `MISSING_INPUT` (400),
`INVALID_TYPE` (400), `INPUT_TOO_LONG` (413, input over 5000 chars),
`RATE_LIMITED` (429, with `Retry-After` header),
`NOT_FOUND` (404), `INTERNAL_ERROR` (500). CORS is open (`*`) in v1 for the
hackathon demo — tighten before any real deployment.

Try it:

```bash
curl -s http://localhost:3000/api/health
curl -s -X POST http://localhost:3000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"input": "Dear customer, your SBI KYC is incomplete. Your account will be blocked within 24 hours. Update KYC now: http://sbi-kyc-update.xyz/verify"}'
```

## Tests

Contract tests run against a live server on port 3101. Enrichment is disabled
for deterministic runs (redirect following and URLhaus both need network):

```bash
PORT=3101 REDIRECT_ENABLED=0 URLHAUS_ENABLED=0 node server.js &
node tests/api-contract.test.js
node tests/new-engine.test.js
```

`api-contract.test.js` covers all endpoints, error codes, CORS and samples.
`new-engine.test.js` covers the extended-engine cases (Hinglish, electricity,
APK, new brands/TLDs/shorteners, sender impersonation).

Unit tests need no server (they use local mock servers):

```bash
node tests/rate-limit.test.js
node tests/redirect.test.js
node tests/urlhaus.test.js
node tests/ai.test.js
```

`ai.test.js` covers the AI second-opinion client and server wiring against
local mock AI services (valid/invalid/timeout/unavailable/disabled cases +
borderline-only gating).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port (Render sets it automatically). |
| `RATE_LIMIT_MAX` | `100` | Max `/api/analyze` requests per window per IP. |
| `RATE_LIMIT_WINDOW_MS` | `900000` (15 min) | Rate-limit window. |
| `REDIRECT_ENABLED` | `1` | Set `0` to disable redirect following (deterministic tests). |
| `REDIRECT_ALLOW_PRIVATE` | unset | Test-only: set `1` to allow redirect fetches to loopback/private hosts. Never set in production (SSRF guard). |
| `URLHAUS_ENABLED` | `1` | Set `0` to disable URLhaus lookups (deterministic tests). |
| `URLHAUS_API_URL` | `https://urlhaus-api.abuse.ch/v1/url/` | Override for tests (point at a mock server). |
| `URLHAUS_AUTH_KEY` | (none) | Free Auth-Key from abuse.ch (auth.abuse.ch). Required for URLhaus lookups; without it lookups report `unknown`. Never commit a real key — set it in Render's dashboard env vars. |
| `AI_SERVICE_URL` | (none) | Base URL of Member 3's AI service (e.g. its Render URL). Unset = AI second opinion disabled, no `ai` field. |
| `AI_TIMEOUT_MS` | `8000` | Timeout for the AI service call; on timeout the `ai` field is omitted. |

## Deploy to Render (free tier)

1. Push these files to the team repo (backend folder or repo root — either
   works as long as the start command runs from the folder containing
   `package.json`).
2. Render dashboard → New → Web Service → connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Render provides `PORT` automatically. Set `URLHAUS_AUTH_KEY` (threat intel)
   and, when ready, `AI_SERVICE_URL` (AI second opinion) in the dashboard
   env vars.
5. Copy the deployed URL (e.g. `https://phishshield-api.onrender.com`) into
   the frontend's API base URL env var (e.g. `VITE_API_URL`). Do not hard-code
   it in frontend source.

## Project structure

```text
server.js       Express app: routes, validation, CORS, error mapping
analyzer.js     Heuristic engine (identical to the browser draft — do not fork it)
rateLimit.js    In-memory rate limiter for /api/analyze
redirect.js     Redirect-chain follower with SSRF guards
urlhaus.js      URLhaus (abuse.ch) lookup, best-effort
ai.js           AI second-opinion client (borderline-only, env-gated, fail-open)
package.json    Express dependency + start script
tests/          Contract + engine + unit tests
```

## Implementation status (verified 2026-10-31)

Implemented and demonstrated with tests + live Render checks:
- URLhaus lookup (Auth-Key header; listed +60, clean/unknown otherwise)
- Shortener-only redirect chains (max 5 hops, 5s total, SSRF-guarded)
- Sender-name impersonation (+30; legit brand senders not flagged)
- Rate limiting (100 requests / 15 min / IP on /api/analyze, 429 + Retry-After)
- Error handling + validation (MISSING_INPUT, INVALID_TYPE, INPUT_TOO_LONG,
  INVALID_JSON, NOT_FOUND; enrichments never break the base verdict)
- Timeouts: redirect 5s, URLhaus 5s, AI service 8s
- AI second-opinion wiring (borderline engine scores 30–59 only, additive
  `ai` field, engine verdict never changed) — code + mock tests done

Still pending (deployment/coordination steps, not code gaps):
- AI service deployment (separate Render service + Member 3's GEMINI_API_KEY)
- Live AI integration check once the AI service URL exists (set
  AI_SERVICE_URL on the backend Render service)
- Frontend rendering of the `ai` second-opinion panel (Member 1)
- Live 429 demonstration from a single fixed IP (this VM's egress IPs rotate,
  so the loop never tripped the limiter; local rate-limit tests pass 9/9)

Known limits: the rate limiter is in-memory, so a Render restart/sleep resets
buckets; CORS is open (`*`) for the v1 demo only.

## Notes for the team

- If the engine gains a check, update `analyzer.js` in **both** the draft and
  here, and record the new reason label in the API contract first.
- Score is a risk signal, not a probability — the frontend must never display
  it as "95% sure".
- Out of scope for v1: destination-page *content* fetching (redirect chains
  are followed, page bodies never are), auth, accounts, history,
  batch analysis, ML model layer, full domain-age/reputation lookups.
