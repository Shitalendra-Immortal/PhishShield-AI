// AI second-opinion client (backend -> Member 3's independent ai-service).
// Borderline-only, env-gated, fail-open: any problem returns null and the
// caller simply omits the `ai` field. The engine verdict is never changed.
// Follows AI_SERVICE_CONTRACT.md: POST /ai/analyze, 8s timeout default.
'use strict';

var SIGNAL_TYPES = [
  'false_authority', 'manufactured_urgency', 'fake_deadline', 'prize_lure',
  'impersonation', 'credential_request', 'suspicious_link', 'unverifiable_claim',
  'pressure_to_act', 'unusual_sender'
];

function isValidOpinion(data) {
  if (!data || data.available !== true) return false;
  if (['safe', 'suspicious', 'phishing'].indexOf(data.assessment) === -1) return false;
  if (['low', 'medium', 'high'].indexOf(data.confidence) === -1) return false;
  if (!Array.isArray(data.signals)) return false;
  for (var i = 0; i < data.signals.length; i++) {
    var s = data.signals[i];
    if (!s || SIGNAL_TYPES.indexOf(s.type) === -1 || typeof s.detail !== 'string') return false;
  }
  if (typeof data.explanation !== 'string' || typeof data.recommendedAction !== 'string') return false;
  return true;
}

// engine: { kind, score, verdict: { level, label }, reasons: [{ label, points }] }.
// Returns the opinion object, or null when disabled, unavailable, or invalid.
async function getAiOpinion(input, engine, options) {
  var opts = options || {};
  var baseUrl = (opts.baseUrl || process.env.AI_SERVICE_URL || '').replace(/\/+$/, '');
  if (!baseUrl) return null;
  var timeoutMs = opts.timeoutMs || Number(process.env.AI_TIMEOUT_MS) || 8000;
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, timeoutMs);
  try {
    var res = await fetch(baseUrl + '/ai/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        input: input,
        engine: {
          kind: engine.kind,
          score: engine.score,
          verdict: { level: engine.verdict.level, label: engine.verdict.label },
          reasons: (engine.reasons || []).map(function (r) { return { label: r.label, points: r.points }; })
        }
      }),
      signal: controller.signal
    });
    if (!res.ok) return null;
    var data = await res.json();
    if (!isValidOpinion(data)) return null;
    return {
      available: true,
      assessment: data.assessment,
      confidence: data.confidence,
      signals: data.signals,
      explanation: data.explanation,
      recommendedAction: data.recommendedAction
    };
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { getAiOpinion: getAiOpinion };
