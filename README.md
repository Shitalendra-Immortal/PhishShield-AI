# PhishShield AI — GRAVITON 2026

PhishShield AI analyses pasted links, SMS messages, and emails for phishing,
impersonation, and social-engineering tricks — and explains its verdict in
plain language, with reasons, instead of a black-box score.

Built for **GRAVITON 2026** (CGC University, Mohali), problem statement **#02
PhishShield AI**.

## Live

- Backend API: https://phishshield-ai-u284.onrender.com
  - Health: `GET /api/health`
  - Analyse: `POST /api/analyze` with `{ "input": "...", "type": "auto" }`
- Frontend: deployment pending (Vite + React app in this repo).

## How it works

1. **Heuristic engine** (`backend/analyzer.js`, the single source of truth)
   scores a link or message from visible signals: IP hosts, @ tricks,
   shortened links, punycode, brand impersonation (incl. leetspeak),
   suspicious TLDs, urgency/threat/prize/KYC patterns, Hinglish pressure
   phrasing, fake-app lures, and sender-name impersonation
   (`"Brand" <address@other-domain>`).
2. **Verdict bands:** 0–29 Looks Safe, 30–59 Suspicious, 60–100 Likely
   Phishing. The score is a risk signal, never a probability.
3. **Backend enrichment (URL mode):** short links get their redirect chain
   followed (SSRF-guarded) and the destination analysed; non-official URLs
   are checked against the abuse.ch URLhaus malicious-URL database
   (free Auth-Key via `URLHAUS_AUTH_KEY`); `/api/analyze` is rate-limited
   (100 requests / 15 min / IP).
4. **AI second opinion** (`ai-service/`, optional): a Gemini-powered service
   that returns a structured assessment, confidence, social-engineering
   signals, and a plain-language explanation for borderline cases. It never
   overrides the engine verdict.

## Repository layout

- `backend/` — Express API (Node). See `backend/README.md` and
  `API_CONTRACT.md` (the frontend/backend contract).
- `ai-service/` — Independent Gemini second-opinion service. See
  `ai-service/README.md`.
- Frontend — Vite + React + TypeScript app in `frontend/` (`index.html`,
  `src/`, `package.json`): dashboard, URL/SMS/email scanner, results page
  with risk visualisation, and scan history.

## Run locally

Backend:

```bash
cd backend
npm install
npm start   # listens on PORT (default 3000)
```

AI service:

```bash
cd ai-service
npm install
GEMINI_API_KEY=your-key npm start   # listens on PORT (default 4000)
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL` to the backend URL when deploying the frontend.

## API contract

`API_CONTRACT.md` at the repo root is the agreed contract between frontend
and backend: endpoints, response fields, verdict bands, and error codes.
Backend changes that affect the contract update this document first.

## Team (GRAVITON 2026)

- Member 1 — Frontend (dashboard, scanners, results, risk visualisation)
- Member 2 — Backend lead (Express APIs, analyzer, validation, security)
- Member 3 — AI engineer (Gemini second-opinion service)
- Member 4 — Cybersecurity (threat intel, sample testing, security testing)

## Notes

- Hackathon demo build: no auth, no database, no stored inputs. Scans are
  analysed in memory and never kept.
- Scores are risk signals, not probabilities — never display them as
  "% sure".
