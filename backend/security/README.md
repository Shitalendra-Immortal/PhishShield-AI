# backend/security/ — Member 4, adapted to the team repo

**Copy only this `security/` folder into the repo, at `backend/security/`.**
Do not copy anything else from the adapted folder. Do not overwrite
`backend/analyzer.js`, `backend/urlhaus.js`, `backend/redirect.js` or
`backend/server.js` — this delivery changes none of them.

## What changed vs the first starter module

The first starter (`phishshield-url-security`) was written before the
repo was checked. It contained its own URLhaus service, its own
redirect analyser, and its own scorer. The repo already has all three,
better integrated, so this adapted version **removes the duplicates**:

| First starter | Adapted version |
|---|---|
| `urlHaus.service.js` (own, `URLHAUS_API_KEY`, `not_listed`) | **Deleted.** Reuses `../urlhaus.js`: env `URLHAUS_AUTH_KEY`, status `listed` / `clean` / `unknown` |
| `redirectAnalyzer.js` (own, HEAD, 5 hops) | **Deleted.** Reuses `../redirect.js`: `followRedirects()`, max 5 hops, 5s total, SSRF-guarded |
| `urlAnalyzer.js` (own scorer, +50 for listed) | **Deleted.** `analyzer.js` stays the single source of truth. Server already adds +60 for listed, and redirect-destination reasons |
| Heuristic re-scoring (IP, shortener, brand, TLD…) | **Deleted.** `analyzer.js` already scores all of these |
| URL brand impersonation in the checker | **Removed when no sender is given.** `analyzer.js` already gives +30 for that |

## What this folder actually adds (new, not duplicate)

- `urlParser.js` — structured parsing analyzer.js does not expose:
  protocol, hostname, registrable domain, subdomains, path, `isIP`,
  `isPrivateIP`, `isBlockedHost`.
- `impersonationChecker.js` — **structured** sender checks analyzer.js
  does not have: sender email/domain (e.g. from a mail header) vs link
  domain, and a brand claim vs sender domain. Analyzer.js only handles
  sender spoofing inside message text.
- `securityReport.js` — one combined report using the repo's own
  modules, in API-contract field names: `redirectChain`, `finalUrl`,
  `threatIntel`. It does not re-score anything.
- `security.test.js` — 12 tests, verified against the real repo files
  (see below). `index.js` is just a convenience re-export.

## Output shape

```js
const { buildSecurityReport } = require('./security/securityReport');
const report = await buildSecurityReport('https://bit.ly/abc', {
  sender: 'support@sbi.co.in',   // optional, structured metadata only
  senderDisplayName: 'SBI',      // optional
});
// report = {
//   url, host, parsed,
//   redirectChain: [...], finalUrl, redirectBlocked,
//   threatIntel: { status: 'listed'|'clean'|'unknown', threat },
//   senderCheck: { checked, senderDomain, indicators },
//   riskIndicators: [ /* NEW evidence only, points: null */ ],
//   limitations: [...], blocked, enrichmentSkipped, error
// }
```

Rules, mirroring `server.js`:
- Blocked hosts (`localhost`, private/internal IPs) are never fetched
  and never sent to URLhaus. `blocked: true, error: 'SSRF_BLOCKED'`.
- Official domains skip enrichment, exactly as `server.js` does.
- Redirects are followed for shorteners only by default
  (`PhishShield.isShortener`), or always if `followRedirects: true`.
- URLhaus failure is `unknown`, never `clean`. `clean` means checked
  and not listed. Failure is **not** proof a URL is clean.
- `riskIndicators` carry `points: null` on purpose. Member 2 must
  decide in a contract update before adding any of them to the
  `analyzer.js` score, otherwise the same signal is counted twice.

## How Member 2 can use it (without breaking the contract)

This delivery does **not** change `POST /api/analyze` by itself.
That is deliberate: the v1 contract has no sender field and no
`securityReport` field.

Option A — use it now, outside the API: for Member 4 testing, demo
evidence, and security review. Run the tests, show the report.

Option B — wire it in later, with a contract update: if the API ever
accepts structured sender metadata, `server.js` can call
`buildSecurityReport()` in the URL-enrichment block, additively, and
expose its `senderCheck` / `limitations` in a new field. Do not
silently add its points to the v1 score.

## Test it (in the repo, not from this folder alone)

```bash
# from the repo root, after copying backend/security/ in:
cp -r backend/security /path/to/repo/backend/security
cd /path/to/repo/backend
node security/security.test.js
# 12 passed, 0 failed (verified 2026-10-31 against the real repo files)
node tests/urlhaus.test.js   # repo's own: 8 passed
node tests/redirect.test.js  # repo's own: 24 passed
```

The security tests import `../analyzer.js`, `../urlhaus.js` and
`../redirect.js`, so they only pass inside the repo checkout. Most
tests use injected mock functions; one test uses the real repo
`lookupUrlhaus()` against a local mock URLhaus server.

## Environment (repo names, not the starter's)

| Variable | Used by |
|---|---|
| `URLHAUS_AUTH_KEY` | `../urlhaus.js` — free key from abuse.ch. Without it, lookups report `unknown` |
| `URLHAUS_API_URL` | `../urlhaus.js` — override for tests (point at a mock server) |
| `REDIRECT_ALLOW_PRIVATE` | `../redirect.js` — test-only. Never set in production |

Do not commit a real key. Set it in Render's dashboard env vars.

## False positives, false negatives, API failures

- **False positive:** a legit site flagged. Guarded here by not
  re-scoring URL patterns, and by treating sender mismatch as medium
  evidence only — newsletters legitimately link from other domains.
  Short-name lookalike guard: `bit` is 2 edits from `sbi`, but short
  names now need distance ≤ 1, so `bit.ly` is not flagged as SBI.
- **False negative:** a bad site missed. URLhaus only knows reported
  URLs; a brand-new phishing domain can be `clean`. Scores are a risk
  signal, not a probability, and never display them as "% sure".
- **API failure / timeout / 401:** `threatIntel.status = 'unknown'`,
  with a limitation saying this is not proof the URL is clean.
  The rest of the report still runs.
- **Brand name alone:** not flagged. Only a domain mismatch counts,
  and only when sender metadata is actually supplied.

## Limitations (honest)

- Brand list is kept in sync with `analyzer.js` `SENDER_BRANDS` by
  hand — if that list changes, update this folder too.
- Registrable-domain logic uses a curated suffix list, not the full
  public-suffix list. It now covers the major free-hosting suffixes
  (github.io, vercel.app, netlify.app, pages.dev, appspot.com, …),
  which is where the phishing-relevant gap was; full PSL coverage
  would need a maintained package (`psl` or `tldts`) as a dependency.
- IPv6 URLs: WHATWG URL keeps brackets on IPv6 hostnames, so
  `parseUrl` strips them — otherwise `net.isIP()` sees `[::1]` as
  not-an-IP and IPv6 URLs slip past the block checks entirely.
- No page-content fetching, no JavaScript rendering, no domain-age
  check — those are out of scope for v1 in the repo README.
- DNS-rebinding: fixed in `redirect.js` (each hop resolves once and
  the connection is pinned to a validated address); this report
  inherits the fix through the repo's `followRedirects()`.

## Pushing to branch `feature/url-security`

```bash
git checkout -b feature/url-security
cp -r backend/security <repo>/backend/security
git add backend/security
git commit -m "Add security report: URL parser, sender-domain checks, repo-native URLhaus/redirect report"
git push -u origin feature/url-security
```

Push **only** `backend/security/`. Do not push the first starter's
`urlHaus.service.js`, `redirectAnalyzer.js` or scorer — those are
superseded by this adapted version.
