// PhishShield AI — backend API (v1).
// Implements API_CONTRACT.md exactly. The analysis engine is analyzer.js —
// the SAME file as the browser draft, required directly, so API responses
// match the draft's behavior by construction. No database, no auth, no
// storage: inputs are analyzed in memory and never kept.
'use strict';

const express = require('express');
const PhishShield = require('./analyzer.js');
const { createRateLimiter } = require('./rateLimit.js');
const { followRedirects } = require('./redirect.js');
const { lookupUrlhaus } = require('./urlhaus.js');
const { getAiOpinion } = require('./ai.js');

const PORT = process.env.PORT || 3000;
const MAX_INPUT = 5000;

const SAMPLES = [
  {
    id: 'upi-kyc',
    label: 'UPI KYC scam',
    input: 'Dear customer, your SBI KYC is incomplete. Your account will be blocked within 24 hours. Update KYC now: http://sbi-kyc-update.xyz/verify',
    expectedLevel: 'phishing'
  },
  {
    id: 'prize-sms',
    label: 'Prize SMS',
    input: 'Congratulations! You have won Rs 50,000 Paytm cashback. Claim now: bit.ly/xyz123',
    expectedLevel: 'suspicious'
  },
  {
    id: 'legit-link',
    label: 'Legit link',
    input: 'https://www.amazon.in/gp/order',
    expectedLevel: 'safe'
  }
];

const app = express();

// Structured request logs, registered first so every request is logged
// even when body parsing fails. Deliberately minimal: method, path,
// status, duration, and (for analyze) the score band only. NEVER the input
// text, URLs, hosts, headers, or IPs — submitted links can carry private
// tokens, and log lines must stay safe to paste into a chat or ticket.
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const entry = {
      ts: new Date().toISOString(),
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - start
    };
    if (res.locals.log) Object.assign(entry, res.locals.log);
    if (res.locals.errorCode) entry.error = res.locals.errorCode;
    console.log(JSON.stringify(entry));
  });
  next();
});

// Behind Render's proxy, so client IPs (for rate limiting) come from
// X-Forwarded-For. Demo scope: a spoofed header only changes which bucket
// a client counts against.
app.set('trust proxy', 1);

// CORS first, so even parse errors carry the headers (v1 demo: open origin).
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json({ limit: '100kb' }));

// Rate limit on analyze only (health/samples stay unthrottled). Generous
// defaults so normal demo use never trips it; override via env for tests.
app.use('/api/analyze', createRateLimiter({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 100,
  maxEntries: Number(process.env.RATE_LIMIT_MAX_ENTRIES) || 5000
}));

function sendError(res, status, code, message) {
  res.locals.errorCode = code;
  return res.status(status).json({ error: { code, message } });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'phishshield-api', version: '1.0.0', engine: 'heuristic-v1' });
});

app.get('/api/samples', (req, res) => {
  res.json({ samples: SAMPLES });
});

app.post('/api/analyze', async (req, res) => {
  const body = req.body || {};
  const input = body.input;
  const type = body.type === undefined ? 'auto' : body.type;

  if (typeof input !== 'string' || input.trim() === '') {
    return sendError(res, 400, 'MISSING_INPUT', 'input is required.');
  }
  if (input.length > MAX_INPUT) {
    return sendError(res, 413, 'INPUT_TOO_LONG', 'input must be at most 5000 characters.');
  }
  if (type !== 'auto' && type !== 'url' && type !== 'message') {
    return sendError(res, 400, 'INVALID_TYPE', 'type must be "auto", "url", or "message".');
  }

  let result;
  if (type === 'url') {
    // Mirror the engine's analyze() URL branch, including the 100 cap.
    const u = PhishShield.analyzeUrl(input);
    result = {
      kind: 'url',
      score: Math.min(100, u.score),
      verdict: PhishShield.verdictFor(u.score),
      reasons: u.reasons,
      host: u.host,
      note: u.note
    };
  } else if (type === 'message') {
    const m = PhishShield.analyzeMessage(input);
    result = {
      kind: 'message',
      score: Math.min(100, m.score),
      verdict: PhishShield.verdictFor(m.score),
      reasons: m.reasons,
      urls: m.urls,
      note: null
    };
  } else {
    // Auto mode: the engine's own detection. Empty input can't reach here
    // (rejected above), so kind is always 'url' or 'message'.
    const r = PhishShield.analyze(input);
    result = { kind: r.kind, score: r.score, verdict: r.verdict, reasons: r.reasons };
    if (r.kind === 'url') {
      result.host = r.host;
      result.note = r.note;
    } else {
      result.urls = r.urls;
      result.note = r.note;
    }
  }

  // Snapshot of the ENGINE result (pre-enrichment), sent as context to
  // the AI second opinion, per AI_SERVICE_CONTRACT.md.
  const engineSnapshot = {
    kind: result.kind,
    score: result.score,
    verdict: result.verdict,
    reasons: result.reasons.slice()
  };

  // URL-mode enrichment (additive only; never breaks the base verdict).
  // Message mode gets no enrichment: short links inside messages are
  // already capped at 40 points by the engine.
  if (result.kind === 'url') {
    result.redirectChain = [];
    result.finalUrl = null;
    result.threatIntel = { status: 'unknown', threat: null };
    const official = result.note && result.note.indexOf('Official domain of') === 0;
    const targetUrl = /^https?:\/\//i.test(input) ? input : 'https://' + input;
    if (!official && result.host) {
      try {
        // Redirect following: shortener hosts only, SSRF-guarded, 5s total.
        if (process.env.REDIRECT_ENABLED !== '0' && PhishShield.isShortener(result.host)) {
          const red = await followRedirects(targetUrl, {
            allowPrivate: process.env.REDIRECT_ALLOW_PRIVATE === '1'
          });
          result.redirectChain = red.chain;
          result.finalUrl = red.finalUrl;
          if (red.reachedFinal && red.chain.length > 1 && red.finalUrl && red.finalUrl !== targetUrl) {
            const dest = PhishShield.analyzeUrl(red.finalUrl);
            const seen = {};
            result.reasons.forEach(function (r) { seen[r.label] = true; });
            dest.reasons.forEach(function (r) {
              if (!seen[r.label]) {
                result.score += r.points;
                result.reasons.push({
                  label: 'Redirect destination: ' + r.label,
                  detail: r.detail,
                  points: r.points
                });
              }
            });
            result.score = Math.min(100, result.score);
            result.verdict = PhishShield.verdictFor(result.score);
          }
        }
        // URLhaus: Auth-Key header from env, best-effort. Listed => +60 (forces Phishing band).
        // Any failure leaves the base verdict untouched.
        if (process.env.URLHAUS_ENABLED !== '0') {
          const intel = await lookupUrlhaus(result.finalUrl || targetUrl, {});
          result.threatIntel = intel;
          if (intel.status === 'listed') {
            result.score = Math.min(100, result.score + 60);
            result.reasons.push({
              label: 'Listed in URLhaus malicious-URL database',
              detail: 'This address appears in abuse.ch URLhaus' +
                (intel.threat ? ' as threat type "' + intel.threat + '"' : '') + '.',
              points: 60
            });
            result.verdict = PhishShield.verdictFor(result.score);
          }
        }
      } catch (e) {
        // Enrichment must never break the base verdict.
      }
    }
  }
  // AI second opinion (additive only): every valid scan, and only when
  // AI_SERVICE_URL is set. Never changes score/verdict; on any failure
  // the field is simply omitted.
  if (process.env.AI_SERVICE_URL) {
    try {
      const opinion = await getAiOpinion(input, engineSnapshot);
      if (opinion) result.ai = opinion;
    } catch (e) {
      // AI is never on the critical path.
    }
  }
  res.locals.log = {
    level: result.verdict.level,
    score: result.score,
    threatIntel: result.threatIntel ? result.threatIntel.status : undefined,
    ai: !!result.ai
  };
  return res.json(result);
});

// Unknown routes: JSON 404, never Express's default HTML page.
app.use((req, res) => sendError(res, 404, 'NOT_FOUND', 'Unknown endpoint.'));

// Body-parser errors (malformed JSON, oversized body) as contract-style JSON.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return sendError(res, 400, 'INVALID_JSON', 'Request body must be valid JSON.');
  }
  if (err && err.type === 'entity.too.large') {
    return sendError(res, 413, 'INPUT_TOO_LONG', 'input must be at most 5000 characters.');
  }
  return next(err);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('PhishShield API listening on port ' + PORT);
  });
}

module.exports = app;
