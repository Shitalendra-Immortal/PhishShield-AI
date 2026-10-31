/**
 * server.js — PhishShield AI service, contract v1.
 *
 * Independent service in its own folder. Runs separately (default port 4000).
 * Talks to Gemini via an env-var API key. Never stores inputs. Never fetches
 * URLs — analysis is text-only.
 *
 * RULE ZERO (contract): the engine verdict always wins. This service is a
 * second opinion, shown separately. It never changes the engine score or
 * verdict. The backend is responsible for that; this service only returns
 * its own assessment.
 */
require('dotenv').config();
const express = require('express');
const {
  SYSTEM_PROMPT,
  buildUserPrompt,
  parseAiOutput,
  validateAiOutput,
  unavailableResponse,
} = require('./prompt');

const PORT = Number(process.env.PORT || 4000);
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
// Test-only override (local mock servers). Defaults to the real Gemini API.
// Never set this in production.
const GEMINI_API_BASE_URL = (process.env.GEMINI_API_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/+$/, '');
// Kept under the backend's 8-second timeout so a slow provider does not
// block the demo's main path.
const PROVIDER_TIMEOUT_MS = 7000;
const MAX_INPUT_CHARS = 5000;

// Optional shared secret for /ai/analyze. When set, callers must send it
// as X-AI-Service-Key; without it the endpoint answers 401. When unset the
// endpoint is open (local dev only — always set it on a public deploy).
// The backend sends it from its own AI_SERVICE_KEY env var.
const AI_SERVICE_KEY = process.env.AI_SERVICE_KEY || '';
// Backstop against excessive provider usage (each call costs Gemini quota).
const AI_RATE_LIMIT_MAX = Number(process.env.AI_RATE_LIMIT_MAX) || 100;
const AI_RATE_LIMIT_WINDOW_MS = Number(process.env.AI_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
// Bound on the rate-limit map itself: without one, a flood of distinct
// client IPs grows the map without limit (entries only expire lazily).
// At the cap the oldest bucket is evicted, so memory stays bounded and
// the limiter keeps working (an evicted IP just gets a fresh bucket).
const AI_RATE_LIMIT_MAX_ENTRIES = Number(process.env.AI_RATE_LIMIT_MAX_ENTRIES) || 5000;
// Maximum simultaneous Gemini calls. Each call costs quota and wall
// time; without a cap a burst of scans fans out into unbounded provider
// concurrency. When the cap is hit the request answers available: false
// immediately (fail-open: the engine verdict still shows) instead of
// queueing — queueing would eat into the backend's 8s timeout and turn
// a busy moment into timeouts. Per-process: each Render instance has
// its own cap, same as the rate limiter.
const MAX_CONCURRENT_GEMINI = Number(process.env.AI_MAX_CONCURRENT) || 5;
let activeGemini = 0;

const app = express();

// Behind Render's proxy, so client IPs (for rate limiting) come from
// X-Forwarded-For.
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));

// Tiny in-memory rate limiter for /ai/analyze (same pattern as backend).
const aiHits = new Map();
function aiRateLimiter(req, res, next) {
  const now = Date.now();
  const key = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
  aiHits.forEach((entry, k) => { if (entry.reset <= now) aiHits.delete(k); });
  let entry = aiHits.get(key);
  if (!entry || entry.reset <= now) {
    entry = { count: 0, reset: now + AI_RATE_LIMIT_WINDOW_MS };
    if (!aiHits.has(key) && aiHits.size >= AI_RATE_LIMIT_MAX_ENTRIES) {
      // Evict the oldest bucket (Map preserves insertion order).
      aiHits.delete(aiHits.keys().next().value);
    }
    aiHits.set(key, entry);
  }
  entry.count += 1;
  if (entry.count > AI_RATE_LIMIT_MAX) {
    const retryAfter = Math.ceil((entry.reset - now) / 1000);
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({
      error: { code: 'RATE_LIMITED', message: 'Too many requests, try again later.' },
    });
  }
  return next();
}

function requireServiceKey(req, res, next) {
  if (!AI_SERVICE_KEY) return next();
  if (req.headers['x-ai-service-key'] === AI_SERVICE_KEY) return next();
  return res.status(401).json({
    error: { code: 'UNAUTHORIZED', message: 'Missing or invalid service key.' },
  });
}

function isConfigured() {
  return GEMINI_API_KEY.length > 0;
}

// ---------------------------------------------------------------- health
app.get('/ai/health', (req, res) => {
  // Reports only the presence of a key, never the key itself.
  // model echoes the configured GEMINI_MODEL value (gemini-2.0-flash is
  // an example, not a guarantee — verify it is supported in your account).
  res.json({
    status: 'ok',
    service: 'phishshield-ai',
    model: GEMINI_MODEL,
    configured: isConfigured(),
  });
});

// --------------------------------------------------------------- analyze
app.post('/ai/analyze', requireServiceKey, aiRateLimiter, async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { input } = body;

    // Contract errors: input validation only.
    if (typeof input !== 'string' || input.trim().length === 0) {
      return res.status(400).json({
        error: { code: 'MISSING_INPUT', message: 'input is required.' },
      });
    }
    if (Array.from(input).length > MAX_INPUT_CHARS) {
      return res.status(413).json({
        error: {
          code: 'INPUT_TOO_LONG',
          message: 'input must be at most 5000 characters.',
        },
      });
    }

    // Engine result is context only. If the backend did not send one, or
    // sent a malformed one, analysis still proceeds without it.
    const engine =
      body.engine && typeof body.engine === 'object' && !Array.isArray(body.engine)
        ? body.engine
        : null;

    // Expected provider failures (missing key, API error, timeout, invalid
    // output after one retry) are NOT service failures: HTTP 200 with
    // available: false, so the backend shows the engine verdict alone.
    if (!isConfigured()) {
      return res.json(unavailableResponse());
    }

    // Concurrency cap, fail-open: a busy service still answers, just
    // without the AI opinion, instead of stacking up provider calls.
    if (activeGemini >= MAX_CONCURRENT_GEMINI) {
      return res.json(unavailableResponse());
    }
    activeGemini += 1;
    let result;
    try {
      result = await analyzeWithGemini(input, engine);
    } finally {
      activeGemini -= 1;
    }
    if (!result) {
      return res.json(unavailableResponse());
    }
    return res.json({ available: true, ...result });
  } catch (err) {
    // Genuine service-level failures only reach here.
    console.error('AI service error:', err && err.message ? err.message : err);
    return res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Internal service error.' },
    });
  }
});

// ------------------------------------------------------- Gemini provider
async function analyzeWithGemini(input, engine) {
  // One retry, and only for invalid model output (contract rule).
  // API errors and timeouts return unavailable immediately.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const isRetry = attempt === 1;
    const outcome = await callGeminiOnce(input, engine, isRetry);
    if (outcome.kind === 'ok') return outcome.data;
    if (outcome.kind === 'provider_error') return null;
    // outcome.kind === 'invalid': loop once for the retry, then give up.
  }
  return null;
}

async function callGeminiOnce(input, engine, isRetry) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  try {
    const userText = isRetry
      ? `${buildUserPrompt(input, engine)}\n\nReturn valid JSON only.`
      : buildUserPrompt(input, engine);

    const url =
      `${GEMINI_API_BASE_URL}/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent` +
      `?key=${encodeURIComponent(GEMINI_API_KEY)}`;

    const response = await fetch(url, {
      method: 'POST',
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ role: 'user', parts: [{ text: userText }] }],
        generationConfig: {
          temperature: 0.2,
          responseMimeType: 'application/json',
        },
      }),
    });

    if (!response.ok) {
      // Includes an unavailable model: surfaces as available: false,
      // never as a startup crash or a 500.
      return { kind: 'provider_error' };
    }

    const data = await response.json();
    const text = (data.candidates || [])
      .flatMap((c) => (c.content && c.content.parts ? c.content.parts : []))
      .map((p) => p.text || '')
      .join('');
    if (!text) return { kind: 'invalid' };

    const parsed = parseAiOutput(text);
    if (!parsed) return { kind: 'invalid' };
    const validated = validateAiOutput(parsed);
    if (!validated.ok) return { kind: 'invalid' };
    return { kind: 'ok', data: validated.data };
  } catch (err) {
    // Timeout (AbortError), network failure, bad JSON from the provider:
    // all are provider failures, not service failures.
    return { kind: 'provider_error' };
  } finally {
    clearTimeout(timer);
  }
}

// ------------------------------------------------------------ fallthrough
app.use((req, res) => {
  res.status(404).json({
    error: { code: 'NOT_FOUND', message: 'Route not found.' },
  });
});

// Malformed JSON bodies reach here from express.json().
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: { code: 'INVALID_JSON', message: 'Request body must be valid JSON.' },
    });
  }
  return next(err);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`phishshield-ai listening on port ${PORT} (model: ${GEMINI_MODEL}, configured: ${isConfigured()})`);
  });
}

module.exports = app;
