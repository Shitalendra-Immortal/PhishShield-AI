// Dual-verdict aggregation (pure function, no I/O).
//
// Combines the backend heuristic verdict with the validated AI second
// opinion into one structured assessment. Rules, all deliberate:
//
// - Severity order: safe = 0, suspicious = 1, phishing = 2. The final
//   verdict is the highest JUSTIFIED severity among the valid
//   assessments, by category — never by raw numerical score, and
//   never a naive max. The engine has a 0-100 score; the AI does not,
//   so scores are not comparable across systems and are never
//   combined. "Justified" is the false-positive guard: the backend
//   verdict is always justified (deterministic rules, backed by its
//   reasons), but an AI escalation — AI severity above backend
//   severity — counts only when the AI opinion is backed by at least
//   one signal AND its confidence is medium or high. A low-confidence
//   or signal-less AI claim is still recorded in full (aiVerdict,
//   disagreement, combinedEvidence) and shown to the user, but it
//   does not move the headline: promoting an uncertain model claim
//   to the final verdict is exactly how false positives multiply.
//   aiJustified reports whether the AI opinion meets that bar, so
//   the frontend never has to re-derive the gate (and drift from it).
//   It is only meaningful when aiVerdict exceeds backendVerdict;
//   when the AI agrees or is lower, escalation is not at issue.
// - The original assessments are never overwritten: backendVerdict is
//   always the engine verdict.level, aiVerdict is always the AI
//   assessment, and the top-level score/verdict/reasons/ai fields of
//   the API response are untouched by this module. This object is
//   additive.
// - An absent, unavailable, or invalid AI opinion is aiVerdict: null,
//   NEVER "safe". An API/model error must not read as a clean bill of
//   health. With aiVerdict null, disagreement is false and the final
//   verdict equals the backend verdict (the documented fallback).
// - disagreement is true only when both assessments are present and
//   differ — including when the AI escalation was not justified. In
//   particular, an AI "safe" never downgrades a backend
//   "phishing": the backend severity stands, and disagreement records
//   that the AI saw it differently.
// - combinedEvidence lists each system's findings once, tagged with
//   its source ("engine" or "ai"). Findings from two systems are
//   distinct evidence even when semantically similar, so they are
//   NOT merged or deduplicated across sources — that tagging IS the
//   provenance. There is deliberately no combined score: a summed
//   score would imply a new threshold that does not exist.
// - recommendation is the engine advice text for the final verdict
//   band. When the AI justifiably escalated, the AI's
//   recommendedAction is appended, so the user sees both the
//   standing advice and what the escalating system suggests.
// - An invalid backend verdict throws: that is a programmer error, and
//   the caller (server.js) degrades to omitting the assessment field
//   rather than letting a broken aggregator break the scan.
'use strict';

var PhishShield = require('./analyzer.js');

var SEVERITY = { safe: 0, suspicious: 1, phishing: 2 };

function scoreForLevel(level) {
  return level === 'phishing' ? 60 : level === 'suspicious' ? 30 : 0;
}

function aggregateAssessment(backend, ai) {
  var backendLevel = backend && backend.verdict && backend.verdict.level;
  if (SEVERITY[backendLevel] === undefined) {
    throw new Error('aggregateAssessment: invalid backend verdict level');
  }
  var aiLevel = null;
  if (ai && ai.available === true && SEVERITY[ai.assessment] !== undefined) {
    aiLevel = ai.assessment;
  }
  // Escalation gate (see header): an AI opinion may lift the final
  // verdict only with signal backing and medium/high confidence.
  // ai.js already rejects alarming opinions without signals, but the
  // aggregator enforces the bar itself rather than trusting upstream.
  var aiJustified = aiLevel !== null &&
    Array.isArray(ai.signals) && ai.signals.length >= 1 &&
    (ai.confidence === 'medium' || ai.confidence === 'high');
  var aiEscalates = aiLevel !== null && aiJustified &&
    SEVERITY[aiLevel] > SEVERITY[backendLevel];
  var finalLevel = aiEscalates ? aiLevel : backendLevel;
  var disagreement = aiLevel !== null && aiLevel !== backendLevel;
  var evidence = [];
  var reasons = Array.isArray(backend.reasons) ? backend.reasons : [];
  reasons.forEach(function (r) {
    evidence.push({ source: 'engine', label: r.label, detail: r.detail, points: r.points });
  });
  if (aiLevel !== null) {
    var signals = Array.isArray(ai.signals) ? ai.signals : [];
    signals.forEach(function (s) {
      evidence.push({ source: 'ai', label: s.type, detail: s.detail });
    });
  }
  var recommendation = PhishShield.verdictFor(scoreForLevel(finalLevel)).advice;
  if (aiEscalates &&
      ai && typeof ai.recommendedAction === 'string' && ai.recommendedAction.trim() !== '') {
    recommendation += ' ' + ai.recommendedAction.trim();
  }
  return {
    finalVerdict: finalLevel,
    backendVerdict: backendLevel,
    aiVerdict: aiLevel,
    disagreement: disagreement,
    aiJustified: aiJustified,
    combinedEvidence: evidence,
    recommendation: recommendation
  };
}

module.exports = { aggregateAssessment: aggregateAssessment, SEVERITY: SEVERITY };
