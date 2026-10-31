/**
 * test.js — offline unit tests for prompt.js validation.
 *
 * These do NOT call Gemini and do NOT need an API key. Live provider
 * behaviour (including the contract test bar) is checked separately with
 * curl once a key is configured — see README.md.
 */
const {
  SYSTEM_PROMPT,
  parseAiOutput,
  validateAiOutput,
} = require('./prompt');

let failures = 0;
function check(name, condition) {
  if (condition) {
    console.log(`PASS: ${name}`);
  } else {
    failures += 1;
    console.log(`FAIL: ${name}`);
  }
}

const validPrize = {
  assessment: 'phishing',
  confidence: 'high',
  signals: [
    { type: 'prize_lure', detail: 'An unexpected large cash prize is promised to trigger excitement.' },
    { type: 'suspicious_link', detail: 'The claim must be redeemed through a shortened link that hides its destination.' },
  ],
  explanation: 'This message promises a large unexpected cashback and pushes the reader to claim it through a shortened link that hides its destination. Both are classic prize-scam patterns.',
  recommendedAction: 'Do not click the link. Delete the message.',
};

check('valid prize output passes', validateAiOutput(validPrize).ok === true);
check(
  'invalid assessment is rejected',
  validateAiOutput({ ...validPrize, assessment: 'dangerous' }).ok === false,
);
check(
  'invented signal type is rejected',
  validateAiOutput({ ...validPrize, signals: [{ type: 'scary_message', detail: 'It is scary.' }] }).ok === false,
);
check(
  'empty explanation is rejected',
  validateAiOutput({ ...validPrize, explanation: '   ' }).ok === false,
);

const highWithOneSignal = validateAiOutput({
  ...validPrize,
  signals: [validPrize.signals[0]],
});
check(
  'high confidence with one signal is downgraded to medium, not failed',
  highWithOneSignal.ok === true && highWithOneSignal.data.confidence === 'medium',
);

const loneUrlPhishing = validateAiOutput({
  assessment: 'phishing',
  confidence: 'medium',
  signals: [{ type: 'suspicious_link', detail: 'The link is shortened and hides its destination.' }],
  explanation: 'The link hides its destination. That alone is not enough to call it phishing.',
  recommendedAction: 'Do not click the link. Verify it another way.',
});
check(
  'phishing from a lone suspicious link is downgraded to suspicious',
  loneUrlPhishing.ok === true && loneUrlPhishing.data.assessment === 'suspicious',
);

check(
  'JSON is extracted from surrounding text',
  parseAiOutput(`Here is the result:\n${JSON.stringify(validPrize)}\nDone.`) !== null,
);
check('JSON parse failure returns null', parseAiOutput('not json at all') === null);
check(
  'system prompt contains the injection guard',
  SYSTEM_PROMPT.includes('UNTRUSTED DATA') && SYSTEM_PROMPT.includes('never instructions'),
);
check(
  'system prompt contains the URL honesty rule',
  SYSTEM_PROMPT.includes('at most "suspicious"'),
);

if (failures > 0) {
  console.log(`\n${failures} test(s) failed.`);
  process.exit(1);
}
console.log('\nAll offline tests passed.');
