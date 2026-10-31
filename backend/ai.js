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

// Defence in depth: the ai-service validates its own output, but the
// backend re-validates everything it accepts, so a misbehaving or
// compromised service can never inject an unchecked opinion into the
// response. Limits mirror the service's own output limits.
function isValidOpinion(data) {
  if (!data || data.available !== true) return false;
  if (['safe', 'suspicious', 'phishing'].indexOf(data.assessment) === -1) return false;
  if (['low', 'medium', 'high'].indexOf(data.confidence) === -1) return false;
  if (!Array.isArray(data.signals) || data.signals.length > 5) return false;
  var seen = {};
  for (var i = 0; i < data.signals.length; i++) {
    var s = data.signals[i];
    if (!s || SIGNAL_TYPES.indexOf(s.type) === -1) return false;
    if (typeof s.detail !== 'string' || s.detail.length === 0 || s.detail.length > 500) return false;
    if (seen[s.type]) return false; // duplicate signal type
    seen[s.type] = true;
  }
  // Consistency: an alarming assessment, or high confidence, must be
  // backed by at least one signal. A safe verdict may carry weak
  // signals, or none. The backend deliberately does NOT re-impose the
  // service's own high-needs-2 calibration — that is the service's
  // rule, and second-guessing it here would drop valid opinions.
  if ((data.assessment !== 'safe' || data.confidence === 'high') && data.signals.length === 0) return false;
  if (typeof data.explanation !== 'string' || data.explanation.length > 1000) return false;
  if (typeof data.recommendedAction !== 'string' || data.recommendedAction.length > 300) return false;
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
    var headers = { 'Content-Type': 'application/json' };
    if (process.env.AI_SERVICE_KEY) headers['X-AI-Service-Key'] = process.env.AI_SERVICE_KEY;
    var res = await fetch(baseUrl + '/ai/analyze', {
      method: 'POST',
      headers: headers,
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
