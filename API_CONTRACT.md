# PhishShield AI — API Contract (v1)

**Status:** agreed contract for the hackathon build. Frontend builds against this
document; backend implements exactly this. If backend and this document disagree,
the document wins and backend is fixed.

**Stack:** Node + Express backend. The analysis engine is `analyzer.js` from the
existing draft, required directly by the backend — one source of truth, so API
responses match the draft's behavior exactly. No database, no auth, no API key
in v1. Inputs are analyzed in memory and **never stored**.

**Base URL:** set by environment, never hard-coded in frontend code.

- Local: `http://localhost:3000`
- Production: the deployed backend URL (Render). Fill this in once deployed;
  frontend reads it from an env var (e.g. `VITE_API_URL`).

**General rules**

- All requests and responses are JSON. `Content-Type: application/json`.
- CORS: `Access-Control-Allow-Origin: *` in v1 (hackathon demo only; tighten
  before any real deployment).
- Rate limiting: 100 requests per 15 minutes per IP on `POST /api/analyze`
  only (generous demo limit; exceeding it returns 429 `RATE_LIMITED` with a
  `Retry-After` header). No auth in v1.
- Breaking changes go to `/api/v2`, never by silently changing v1.

---

## 1. `GET /api/health`

Lets the frontend check the backend is up before sending analysis requests.

**Response — 200**

```json
{
  "status": "ok",
  "service": "phishshield-api",
  "version": "1.0.0",
  "engine": "heuristic-v1"
}
```

---

## 2. `POST /api/analyze`

The main endpoint. Analyzes one pasted link or message.

**Request body**

```json
{
  "input": "Dear customer, your SBI KYC is incomplete...",
  "type": "auto"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `input` | string | yes | The pasted link or message. Max 5000 characters. |
| `type` | string | no | `"auto"` (default), `"url"`, or `"message"`. Forces the analysis mode. |

**How `type: "auto"` decides (same rule as the engine):** input that is a single
token looking like a URL or bare domain, with no spaces, is analyzed as a URL;
everything else is analyzed as a message. Forcing `"url"` on text that is not a
valid URL returns score 0 with `note: "No valid URL found."`.

**Response — 200**

```json
{
  "kind": "message",
  "score": 95,
  "verdict": {
    "level": "phishing",
    "label": "Likely Phishing",
    "advice": "Do not click, do not reply, and never share an OTP, PIN or password. Delete it and, if it claims to be your bank, call the bank on its official number."
  },
  "reasons": [
    { "label": "Urgency pressure", "detail": "Scammers rush you so you act before you think.", "points": 15 },
    { "label": "Threat: account blocked or suspended", "detail": "A threat of losing access is the most common phishing lever.", "points": 10 },
    { "label": "KYC update trick", "detail": "Fake KYC messages are the top UPI-era scam in India.", "points": 20 },
    { "label": "Financial brand + alarming action", "detail": "Combines a trusted money brand with an action you are pushed to take.", "points": 10 },
    { "label": "In the link: Suspicious top-level domain (.xyz)", "detail": "This ending is cheap, lightly policed, and heavily abused by scam sites.", "points": 15 },
    { "label": "In the link: Hyphen-stuffed domain (2 hyphens)", "detail": "Real brand domains rarely stack hyphens like this; fakes do.", "points": 10 },
    { "label": "In the link: Brand name \"sbi\" in an unofficial domain", "detail": "The address borrows a trusted brand name but is not that brand's site.", "points": 30 },
    { "label": "In the link: No HTTPS encryption", "detail": "Login and payment pages without HTTPS expose anything you type.", "points": 10 },
    { "label": "In the link: Pressure word in the URL: \"verify\"", "detail": "Scam links love words like verify, secure and update to feel urgent.", "points": 8 },
    { "label": "Link risk capped at 40 points in message mode", "detail": "The link itself scored 73; message mode counts at most 40 of it.", "points": 0 }
  ],
  "urls": ["http://sbi-kyc-update.xyz/verify"],
  "note": null
}
```

(The example above is the engine's real output for the UPI KYC sample. Note the
message-mode math: message signals 55 + link risk capped at 40 = 95.)

**Response fields**

| Field | Type | Notes |
|---|---|---|
| `kind` | string | `"url"` or `"message"` — which mode ran. |
| `score` | integer | 0–100, capped at 100. |
| `verdict.level` | string | **Fixed enum:** `"safe"`, `"suspicious"`, `"phishing"`. Frontend styles badges off this, never off the label text. |
| `verdict.label` | string | Human label: `"Looks Safe"`, `"Suspicious"`, `"Likely Phishing"`. |
| `verdict.advice` | string | What the user should do next. Display it verbatim. |
| `reasons` | array | Every triggered check: `{ label, detail, points }`. `points` can be `0` (info row, e.g. the cap notice) or negative (good signal, e.g. "warns you never to share credentials", −10). Empty array means no signals found. |
| `host` | string | URL mode only: the analyzed hostname, e.g. `"secure-update-verify.xyz"`. |
| `urls` | string[] | Message mode only: URLs found inside the message (max 3 analyzed, highest link score used). |
| `note` | string or null | Extra context when present, e.g. `"Official domain of Amazon India."` for exact official domains (score 0), or `"No valid URL found."`. Display it when non-null. |
| `redirectChain` | string[] | URL mode only: every URL actually fetched while following a redirect chain, input first. `[]` when no redirect was followed (including when following was skipped or failed). |
| `finalUrl` | string or null | URL mode only: the last fetched URL in the chain, or `null` when nothing was fetched. |
| `threatIntel` | object | URL mode only: `{ status, threat }` where `status` is `"listed"` (URL appears in abuse.ch URLhaus), `"clean"` (checked, not listed), or `"unknown"` (lookup failed, skipped, or disabled); `threat` is the URLhaus threat type (e.g. `"malware_download"`) or `null`. |
| `ai` | object (optional) | Present only when an AI second opinion was obtained: `AI_SERVICE_URL` is configured on the backend AND the AI service answered with `available: true`. The backend asks for every valid scan, regardless of score. Shape: `{ available: true, assessment, confidence, signals: [{ type, detail }], explanation, recommendedAction }` (see the AI service contract). It never changes `score` or `verdict`; when absent, show the engine verdict alone. |

**Verdict bands (fixed in v1 — do not change without a contract update)**

| Score | Level | Label |
|---|---|---|
| 0–29 | `safe` | Looks Safe |
| 30–59 | `suspicious` | Suspicious |
| 60–100 | `phishing` | Likely Phishing |

**Mode-specific rules the frontend must know**

- **URL mode:** an exact official domain (Google, Amazon India, SBI, HDFC, Paytm,
  PhonePe, and the rest of the engine's list) short-circuits to score 0 with a
  note naming the brand. No other checks run.
- **Message mode:** URLs inside the message are scanned with the URL checks;
  at most 3 URLs are analyzed, the highest link score is used, and it is capped
  at 40 points toward the message score. A "do not share credentials" warning in
  the text subtracts 10 (score never goes below 0).

**URL-mode enrichment (backend-only, added 2026-10-31)**

- **Redirect following:** when the input URL's host is a known link shortener,
  the backend follows its redirect chain (max 5 hops, 5 second total timeout)
  and analyzes the final destination. Destination signals not already present
  are added to `reasons` with the prefix `"Redirect destination: "` and their
  points added to the score (still capped at 100). `redirectChain` and
  `finalUrl` report the chain. Private/loopback hosts are never fetched (SSRF
  guard); a failed or blocked lookup leaves the base score untouched. Message
  mode does not follow redirects.
- **URLhaus lookup:** when the URL is not an exact official domain, the backend
  checks the final destination (or the input URL, when no redirect ran)
  against the abuse.ch URLhaus malicious-URL database (requires a free
  Auth-Key, supplied via the `URLHAUS_AUTH_KEY` env var and never committed
  to the repo; without a key the API answers 401 and lookups report
  `unknown`). If
  listed, a reason `"Listed in URLhaus malicious-URL database"` (+60 points) is
  added, which forces the Phishing band. If the lookup fails or is skipped,
  `threatIntel.status` is `"unknown"` and the base verdict stands. Message mode
  does not run this lookup.
- **Sender check (engine):** message mode now flags `"Brand"
  <address@other-domain>` sender-name impersonation (+30 points, Suspicious
  boundary on its own). A brand sender from its official domain is not flagged.
- **AI second opinion (backend-only, additive):** for every valid scan, when
  `AI_SERVICE_URL` is set, the backend asks Member 3's
  AI service for a second opinion (8 second timeout). On success the response
  gains an `ai` field (assessment, confidence, signals, explanation,
  recommended action); on any failure the field is omitted and the engine
  verdict stands alone. The AI never changes `score` or `verdict.level`.

**More real examples (engine output, for frontend test fixtures)**

Suspicious URL — input `http://secure-update-verify.xyz/login` →
score 43, level `suspicious`, reasons: suspicious TLD (.xyz) +15, hyphen-stuffed
domain +10, no HTTPS +10, pressure word "verify" +8. `host`:
`"secure-update-verify.xyz"`, `note`: null.

Safe URL — input `https://www.amazon.in/gp/order` → score 0, level `safe`,
reasons `[]`, `host`: `"www.amazon.in"`, note: `"Official domain of Amazon India."`.

**Errors**

| HTTP | `error.code` | When |
|---|---|---|
| 400 | `MISSING_INPUT` | `input` missing, not a string, or empty/whitespace-only. |
| 400 | `INVALID_TYPE` | `type` is present but not `"auto"`, `"url"`, or `"message"`. |
| 413 | `INPUT_TOO_LONG` | `input` longer than 5000 characters. |
| 429 | `RATE_LIMITED` | More than 100 `/api/analyze` requests in 15 minutes from one IP. `Retry-After` header gives seconds until reset. |
| 500 | `INTERNAL_ERROR` | Anything else goes wrong server-side. |

Error body shape (all errors):

```json
{ "error": { "code": "MISSING_INPUT", "message": "input is required." } }
```

---

## 3. `GET /api/samples`

Demo samples for the frontend's "Try a sample" chips, so samples live in one
place and both sides stay in sync. `expectedLevel` is informational (for chips
and tests); it is **not** returned by `/api/analyze`.

**Response — 200**

```json
{
  "samples": [
    {
      "id": "upi-kyc",
      "label": "UPI KYC scam",
      "input": "Dear customer, your SBI KYC is incomplete. Your account will be blocked within 24 hours. Update KYC now: http://sbi-kyc-update.xyz/verify",
      "expectedLevel": "phishing"
    },
    {
      "id": "prize-sms",
      "label": "Prize SMS",
      "input": "Congratulations! You have won Rs 50,000 Paytm cashback. Claim now: bit.ly/xyz123",
      "expectedLevel": "suspicious"
    },
    {
      "id": "legit-link",
      "label": "Legit link",
      "input": "https://www.amazon.in/gp/order",
      "expectedLevel": "safe"
    }
  ]
}
```

(Expected levels are the engine's real outputs: 95 phishing, 45 suspicious,
0 safe. Note the prize SMS lands in Suspicious, not Phishing — do not "fix"
this in the frontend; if the team wants it to score higher, that is an engine
change, agreed and recorded here first.)

---

## Frontend integration notes

```js
const API_BASE_URL = import.meta.env.VITE_API_URL; // or your framework's env var

const res = await fetch(`${API_BASE_URL}/api/analyze`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ input })
});
const data = await res.json();
if (!res.ok) {
  // data.error.code / data.error.message — show the message, keep the form.
} else {
  // badge class = data.verdict.level; score bar width = data.score + '%'
  // render data.reasons as label + points + detail; show data.note when non-null
  // show data.verdict.advice verbatim
}
```

UI states to handle: idle, loading, success, error (network failure and API
error are both "error" — show a retry, never a fake verdict).

---

## Stability promises (v1)

- `verdict.level` values never change; frontend may switch on them safely.
- `score` is always an integer 0–100; bands above are fixed for v1.
- Existing response fields are never removed or renamed in v1; new fields may
  be added.
- New reason `label`s may appear as the engine gains checks; existing labels
  keep their meaning.
- Score is a risk signal, not a probability — never display it as "95% sure".

## Out of scope for v1 (add only by contract update)

- Fetching and analyzing destination page *content* (redirect chains are
  followed for shortener links, but page bodies are never fetched).
- Full domain-age or domain-reputation lookups (URLhaus covers
  known-malicious lists only).
- Auth, accounts, saved history, or analytics.
- `POST /api/analyze/batch` (multiple inputs at once).
- A trained ML model layer (engine is heuristic scoring in v1).
