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
| POST | `/api/analyze` | Body `{ input, type? }` (`type`: `"auto"` default, `"url"`, `"message"`). Returns `{ kind, score, verdict, reasons, host?, urls?, note? }`. Verdict bands: 0–29 safe, 30–59 suspicious, 60–100 phishing. |
| GET | `/api/samples` | Demo samples for the frontend's "Try a sample" chips. |

Errors are always `{ error: { code, message } }`: `MISSING_INPUT` (400),
`INVALID_TYPE` (400), `INPUT_TOO_LONG` (413, input over 5000 chars),
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

Contract tests run against a live server on port 3101:

```bash
PORT=3101 node server.js &
node tests/api-contract.test.js
node tests/new-engine.test.js
```

`api-contract.test.js` covers all endpoints, error codes, CORS and samples.
`new-engine.test.js` covers the extended-engine cases (Hinglish, electricity,
APK, new brands/TLDs/shorteners).

## Deploy to Render (free tier)

1. Push these files to the team repo (backend folder or repo root — either
   works as long as the start command runs from the folder containing
   `package.json`).
2. Render dashboard → New → Web Service → connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Render provides `PORT` automatically — no env vars to set.
5. Copy the deployed URL (e.g. `https://phishshield-api.onrender.com`) into
   the frontend's API base URL env var (e.g. `VITE_API_URL`). Do not hard-code
   it in frontend source.

## Project structure

```text
server.js       Express app: routes, validation, CORS, error mapping
analyzer.js     Heuristic engine (identical to the browser draft — do not fork it)
package.json    Express dependency + start script
```

## Notes for the team

- If the engine gains a check, update `analyzer.js` in **both** the draft and
  here, and record the new reason label in the API contract first.
- Score is a risk signal, not a probability — the frontend must never display
  it as "95% sure".
- Out of scope for v1: destination-page fetching, auth, accounts, history,
  batch analysis, ML model layer.
