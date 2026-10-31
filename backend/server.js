// PhishShield AI — backend API (v1).
// Implements API_CONTRACT.md exactly. The analysis engine is analyzer.js —
// the SAME file as the browser draft, required directly, so API responses
// match the draft's behavior by construction. No database, no auth, no
// storage: inputs are analyzed in memory and never kept.
'use strict';

const express = require('express');
const PhishShield = require('./analyzer.js');

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

// CORS first, so even parse errors carry the headers (v1 demo: open origin).
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json({ limit: '100kb' }));

function sendError(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'phishshield-api', version: '1.0.0', engine: 'heuristic-v1' });
});

app.get('/api/samples', (req, res) => {
  res.json({ samples: SAMPLES });
});

app.post('/api/analyze', (req, res) => {
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
