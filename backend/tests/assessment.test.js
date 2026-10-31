// Dual-verdict aggregation tests (pure function, no server).
// The key rule under test: the final verdict is the highest JUSTIFIED
// severity, not a naive max — a low-confidence or signal-less AI claim
// is recorded, never promoted.
// Run: node tests/assessment.test.js
'use strict';
const { aggregateAssessment } = require('../assessment.js');
const PhishShield = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function backend(level, reasons) {
  return {
    verdict: PhishShield.verdictFor(level === 'phishing' ? 60 : level === 'suspicious' ? 30 : 0),
    reasons: reasons || []
  };
}
function ai(assessment, confidence, signals, action) {
  return {
    available: true, assessment: assessment, confidence: confidence,
    signals: signals || [], explanation: 'test explanation',
    recommendedAction: action || 'AI action.'
  };
}
function advice(level) {
  return PhishShield.verdictFor(level === 'phishing' ? 60 : level === 'suspicious' ? 30 : 0).advice;
}
const SIG = [{ type: 'prize_lure', detail: 'prize bait' }];
const ENG = [{ label: 'Prize / reward bait', detail: 'd', points: 25 }];

// Justified escalation: AI above backend, signals + medium/high.
let r = aggregateAssessment(backend('safe'), ai('phishing', 'medium', SIG, 'Do not click.'));
check('justified escalation safe + AI phishing/medium -> phishing',
  r.finalVerdict === 'phishing' && r.disagreement === true && r.aiJustified === true, r);
check('escalation appends AI action to recommendation',
  r.recommendation.indexOf(advice('phishing')) === 0 && r.recommendation.indexOf('Do not click.') !== -1, r.recommendation);
r = aggregateAssessment(backend('safe'), ai('suspicious', 'high', SIG));
check('justified escalation safe + AI suspicious/high -> suspicious',
  r.finalVerdict === 'suspicious' && r.disagreement === true && r.aiJustified === true, r);
r = aggregateAssessment(backend('suspicious'), ai('phishing', 'medium', SIG));
check('justified escalation suspicious + AI phishing -> phishing',
  r.finalVerdict === 'phishing' && r.disagreement === true, r);

// FP guard: low-confidence AI is recorded, never promoted.
r = aggregateAssessment(backend('safe'), ai('phishing', 'low', SIG, 'Do not click.'));
check('UNJUSTIFIED escalation safe + AI phishing/low stays safe',
  r.finalVerdict === 'safe' && r.aiVerdict === 'phishing' && r.disagreement === true
    && r.aiJustified === false, r);
check('unjustified escalation does NOT append AI action',
  r.recommendation === advice('safe') && r.recommendation.indexOf('Do not click.') === -1, r.recommendation);
r = aggregateAssessment(backend('safe'), ai('suspicious', 'low', SIG));
check('unjustified escalation safe + AI suspicious/low stays safe',
  r.finalVerdict === 'safe' && r.aiJustified === false, r);

// Signals gate: alarming AI without signals is not justified even at
// medium confidence (ai.js rejects this upstream; the aggregator
// enforces the bar itself rather than trusting upstream).
r = aggregateAssessment(backend('safe'), ai('phishing', 'medium', []));
check('signal-less AI phishing/medium stays safe',
  r.finalVerdict === 'safe' && r.aiJustified === false, r);

// Agreement and no-downgrade.
r = aggregateAssessment(backend('suspicious'), ai('suspicious', 'high', SIG, 'AI action.'));
check('agreement suspicious + AI suspicious -> suspicious, no disagreement',
  r.finalVerdict === 'suspicious' && r.disagreement === false, r);
check('agreement does NOT append AI action',
  r.recommendation === advice('suspicious'), r.recommendation);
r = aggregateAssessment(backend('suspicious'), ai('safe', 'high', []));
check('AI safe never downgrades backend suspicious',
  r.finalVerdict === 'suspicious' && r.disagreement === true, r);
r = aggregateAssessment(backend('phishing'), ai('safe', 'high', []));
check('AI safe never downgrades backend phishing',
  r.finalVerdict === 'phishing' && r.disagreement === true, r);

// Absent / invalid AI: null, never "safe".
r = aggregateAssessment(backend('phishing'), null);
check('AI absent + backend phishing -> phishing, aiVerdict null',
  r.finalVerdict === 'phishing' && r.aiVerdict === null && r.disagreement === false && r.aiJustified === false, r);
r = aggregateAssessment(backend('safe'), null);
check('AI absent + backend safe -> safe, aiVerdict null',
  r.finalVerdict === 'safe' && r.aiVerdict === null && r.disagreement === false, r);
r = aggregateAssessment(backend('safe'), { available: false, assessment: 'phishing' });
check('AI unavailable -> aiVerdict null, final stays backend',
  r.finalVerdict === 'safe' && r.aiVerdict === null, r);
r = aggregateAssessment(backend('phishing'), ai('bogus', 'high', SIG));
check('invalid AI assessment -> aiVerdict null, never safe-converted',
  r.finalVerdict === 'phishing' && r.aiVerdict === null, r);

// Evidence: source tags, engine first, AI entries carry no points,
// and the object carries exactly the documented keys (no score).
r = aggregateAssessment(backend('safe', ENG), ai('phishing', 'medium',
  [{ type: 'prize_lure', detail: 'p' }, { type: 'manufactured_urgency', detail: 'u' }]));
check('combinedEvidence tags sources, engine first',
  r.combinedEvidence.length === 3
    && r.combinedEvidence[0].source === 'engine'
    && r.combinedEvidence[0].points === 25
    && r.combinedEvidence[1].source === 'ai'
    && r.combinedEvidence[1].label === 'prize_lure'
    && r.combinedEvidence[2].source === 'ai', r.combinedEvidence);
check('AI evidence entries carry no points key',
  !('points' in r.combinedEvidence[1]) && !('points' in r.combinedEvidence[2]), r.combinedEvidence);
check('assessment has exactly the documented keys, no score',
  JSON.stringify(Object.keys(r).sort()) === JSON.stringify(
    ['aiJustified', 'aiVerdict', 'backendVerdict', 'combinedEvidence', 'disagreement', 'finalVerdict', 'recommendation'])
    && !('score' in r), Object.keys(r));

// Invalid backend verdict throws (caller degrades to no field).
let threw = false;
try { aggregateAssessment({ verdict: { level: 'bogus' }, reasons: [] }, null); }
catch (e) { threw = true; }
check('invalid backend verdict throws', threw === true);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
