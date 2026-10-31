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
| POST | `/api/analyze` | Body `{ input, type? }` (`type`: `"auto"` default, `"url"`, `"message"`). Returns `{ kind, score, verdict, reasons, host?, urls?, note?, redirectChain?, finalUrl?, threatIntel?, ai?, assessment }`. URL mode only: shortener links get redirect-chain analysis, non-official URLs get a URLhaus lookup (see contract). Every valid scan gets an AI second opinion in `ai` when `AI_SERVICE_URL` is set. Every valid scan also carries `assessment` (see contract): the headline `finalVerdict` is the highest JUSTIFIED severity across backend + AI; top-level `score`/`verdict` stay the backend result. Verdict bands: 0–29 safe, 30–59 suspicious, 60–100 phishing. Rate-limited: 100 requests per 15 minutes per IP (429 `RATE_LIMITED`). |
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
all-level AI calls + stricter backend re-validation: duplicate signal
types, max 5 signals, length caps, non-empty details, assessment/confidence
vs signals consistency).

`redirect.test.js` covers redirect chains against a local server plus the
SSRF classifier (IPv6 unique-local/link-local/multicast/documentation,
IPv4-mapped and NAT64 forms, CGNAT, benchmarking ranges).

`normalization.test.js` covers URL normalisation, the removed "do not
share" deduction, the HTTP/HTTPS detection, and the weak-signal
corroboration rule (lone word/TLD score 0, pairs score).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port (Render sets it automatically). |
| `RATE_LIMIT_MAX` | `100` | Max `/api/analyze` requests per window per IP. |
| `RATE_LIMIT_WINDOW_MS` | `900000` (15 min) | Rate-limit window. |
| `RATE_LIMIT_MAX_ENTRIES` | `5000` | Bound on the rate-limit bucket map (distinct IPs); at the cap the oldest bucket is evicted, so a flood of distinct IPs cannot grow memory without limit. |
| `REDIRECT_ENABLED` | `1` | Set `0` to disable redirect following (deterministic tests). |
| `REDIRECT_ALLOW_PRIVATE` | unset | Test-only: set `1` to allow redirect fetches to loopback/private hosts. Never set in production (SSRF guard). |
| `URLHAUS_ENABLED` | `1` | Set `0` to disable URLhaus lookups (deterministic tests). |
| `URLHAUS_API_URL` | `https://urlhaus-api.abuse.ch/v1/url/` | Override for tests (point at a mock server). |
| `URLHAUS_AUTH_KEY` | (none) | Free Auth-Key from abuse.ch (auth.abuse.ch). Required for URLhaus lookups; without it lookups report `unknown`. Never commit a real key — set it in Render's dashboard env vars. |
| `URLHAUS_CACHE_TTL_MS` | `1800000` (30 min) | How long definitive URLhaus results (listed/clean) stay cached in memory. `unknown` results are never cached. |
| `AI_SERVICE_URL` | (none) | Base URL of Member 3's AI service (e.g. its Render URL). Unset = AI second opinion disabled, no `ai` field. |
| `AI_TIMEOUT_MS` | `8000` | Timeout for the AI service call; on timeout the `ai` field is omitted. |
| `AI_SERVICE_KEY` | (none) | Shared secret sent as `X-AI-Service-Key` to the AI service. Set the same value on the AI service and the backend; unset = no header sent. |

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
urlhaus.js      URLhaus (abuse.ch) lookup, best-effort, in-memory cache for definitive results
ai.js           AI second-opinion client (env-gated, fail-open)
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
- No score deduction for reassuring phrases: a "do not share" warning earns
  zero points, since scammers copy such phrases to shave their own score
- URL normalisation: trailing dots stripped, percent-encoded hosts decoded,
  default ports (:443/:80) not flagged as unusual
- URLhaus result cache: definitive listed/clean results cached in memory
  (30 min TTL, 1000 entries); unknown results never cached
- Structured request logs: one JSON line per request (method, path, status,
  duration, score band). Inputs, URLs, hosts, headers, and IPs are never logged
- Punjabi support: Gurmukhi script + Roman Punjabi message checks mirroring
  the English signals (urgency, block threat, prize, OTP request, KYC,
  financial brand, electricity), plus a Punjabi section in the AI prompt
- Hindi support: Devanagari message checks mirroring the English signals
  (urgency, block threat, prize, OTP / bank-info request with a do-not-share
  negation guard, KYC, financial brand, electricity), plus a Devanagari
  section in the AI prompt; cross-script pairs (Latin KYC + Devanagari
  action and vice versa) are caught once, never double-counted
- New scam types: digital-arrest threats (+30, +20 more when payment is
  demanded), fake police / arrest threats (+25), upfront-fee requests
  (+20), guaranteed-profit investment bait (+30), blackmail / sextortion
  threats (+30); @ URLs now score 30 (suspicious on their own); the
  English and Hindi OTP-request rules now skip negated warnings per match
  ("do not share your OTP", "OTP मत बताएं") while still catching the
  "share it with us" referral trick
- Fake-testimonial reward lure (+30): a first-person money-received claim
  ("mil gaye", "got", "received") plus an urge for others to try it
  ("tum log bhi try karo", "you guys try") plus a link — the
  referral-scam shape; bank alerts (no urge, no link) and link-less
  claims do not fire
- P0 audit fixes: ID-document request rule (+30, Aadhaar/PAN/bank/card
  details + share/send/provide/submit/enter/give, with negation guard;
  "tell" and "about" phrasings excluded); KYC completion guards
  (English "is complete/completed", Hindi/Punjabi complete + done
  marker) so receipts no longer read suspicious; brand + action rule
  ignores "update you/us/me" status notifications; customs +
  clearance fees join the upfront-fee list; profit bait covers
  "double your bitcoin/btc/crypto"
- Brand matching is token-based, not substring: a brand fires only
  when it IS a host token or STARTS one (dot labels, then hyphen
  tokens, after leetspeak normalisation). Substring matching fired
  inside unrelated words ("upi" in "stupid"/"cupinfo"/"ubuntupit",
  "sbi" in "massbio"/"ridethisbike", "apple" in "thebigapplegirl")
  — the combined evaluation's biggest false-positive source.
  Official domains extended with airtel.in, airtelxstream.in, jio.com
  and amazonaws.cn (AWS China); pnb.com.ph deliberately left flagged
  as an abbreviation collision (Philippine vs Punjab National Bank).
  Bare-link extraction fixed in the same change: it truncated
  multi-label domains to two labels ("i.airtel.in/2gb_rc2" became
  "i.airtel"), so message-mode checks ran on a wrong host; it now
  captures all labels and still ignores email addresses
- SSRF pinning for redirect fetches: each hop resolves once and the
  connection is pinned to a validated address (no second DNS lookup, so
  DNS rebinding cannot steer a fetch to a private host); hostname still
  used for Host header and TLS verification. Private-range checks extended
  to IPv6 unique-local (fc00::/7), link-local edges, multicast,
  documentation, IPv4-mapped and NAT64 forms, plus CGNAT/benchmarking IPv4
- Weak-signal corroboration in URL scoring: a lone pressure word or a lone
  suspicious TLD scores 0; either scores only alongside another signal,
  or together with each other (verified: existing demo scores unchanged)
- Stricter backend AI validation (defence in depth): the backend
  re-validates the AI service's response — duplicate signal types, max 5
  signals, detail/explanation/action length caps, non-empty details, and
  assessment/confidence backed by at least one signal
- AI second-opinion wiring (every valid scan, additive
  `ai` field, engine verdict never changed) — code + mock tests done
- Dual-verdict aggregation (`backend/assessment.js`, pure function): every
  response carries `assessment` { finalVerdict, backendVerdict, aiVerdict,
  disagreement, aiJustified, combinedEvidence, recommendation }. The final
  verdict is the highest JUSTIFIED severity (safe < suspicious <
  phishing), never a naive max and never a score comparison: the backend
  verdict always counts, an AI verdict above it counts only with >= 1
  signal and medium/high confidence; a low-confidence or signal-less AI
  claim is recorded (aiVerdict, disagreement, evidence) but does not move
  the headline. Top-level score/verdict/reasons/ai are unchanged. The AI
  now judges the POST-enrichment engine snapshot in URL mode (review
  item 3, option B, decided with this change)

Still pending (deployment/coordination steps, not code gaps):
- AI service deployed 2026-10-31 (Render, `ai-service/` root) and backend
  integration verified live for borderline scans; all-level `ai` field
  coverage pending live verification after this change
- Restrictive CORS: still open origin for the demo; tightening needs the
  Vercel frontend URL, which is not yet recorded
- Uptime monitoring: nothing watches the Render services yet
- Frontend AI second-opinion panel (Member 1): the Result page renders
  the `ai` card with agreement/disagreement display (verified in Frontend2.0)
- Labelled dataset + precision/recall/F1 (Member 4's deferred corpus work)
- Frontend rendering of the `ai` second-opinion panel (Member 1)
- Frontend final-verdict display (Member 1): the Result page headline
  becomes `assessment.finalVerdict` with the engine + AI breakdown kept
  inspectable (spec: `goals/graviton-2026-phishshield-ai-build/files/phishshield-aggregator-frontend-handoff.md`); backend + contract are done, display is pending
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
