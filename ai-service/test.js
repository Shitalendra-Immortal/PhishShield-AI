/**
 * test.js — unit tests for prompt.js validation + server tests against
 * local mock Gemini endpoints.
 *
 * The validation checks do NOT call Gemini and do NOT need an API key.
 * The server checks run the real server against a localhost mock Gemini
 * (also no key). Live provider behaviour (including the contract test bar)
 * is checked separately with curl once a key is configured — see README.md.
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
check(
  'system prompt covers Hinglish understanding',
  SYSTEM_PROMPT.includes('Hinglish') && SYSTEM_PROMPT.includes('band ho jayega'),
);
check(
  'system prompt covers Punjabi understanding',
  SYSTEM_PROMPT.includes('Punjabi') && SYSTEM_PROMPT.includes('ਬੰਦ ਹੋ ਜਾਵੇਗਾ'),
);
check(
  'system prompt distinguishes mention from impersonation',
  SYSTEM_PROMPT.includes('mention is not impersonation'),
);
check(
  'system prompt covers legitimate OTP handling',
  SYSTEM_PROMPT.includes('genuine OTP'),
);
check(
  'system prompt requires uncertainty to be explained',
  SYSTEM_PROMPT.includes('cannot be confirmed as'),
);
check(
  'duplicate signal types are rejected',
  validateAiOutput({ ...validPrize, signals: [validPrize.signals[0], validPrize.signals[0]] }).ok === false,
);
check(
  'more than 5 signals are rejected',
  validateAiOutput({ ...validPrize, signals: [
    { type: 'prize_lure', detail: 'a.' },
    { type: 'suspicious_link', detail: 'b.' },
    { type: 'manufactured_urgency', detail: 'c.' },
    { type: 'pressure_to_act', detail: 'd.' },
    { type: 'unverifiable_claim', detail: 'e.' },
    { type: 'false_authority', detail: 'f.' },
  ] }).ok === false,
);
check(
  '5 signals pass',
  validateAiOutput({ ...validPrize, signals: [
    { type: 'prize_lure', detail: 'a.' },
    { type: 'suspicious_link', detail: 'b.' },
    { type: 'manufactured_urgency', detail: 'c.' },
    { type: 'pressure_to_act', detail: 'd.' },
    { type: 'unverifiable_claim', detail: 'e.' },
  ] }).ok === true,
);
check(
  'explanation over 1000 chars is rejected',
  validateAiOutput({ ...validPrize, explanation: 'x'.repeat(1001) }).ok === false,
);
check(
  'recommendedAction over 300 chars is rejected',
  validateAiOutput({ ...validPrize, recommendedAction: 'x'.repeat(301) }).ok === false,
);
check(
  'signal detail over 500 chars is rejected',
  validateAiOutput({ ...validPrize, signals: [{ type: 'prize_lure', detail: 'x'.repeat(501) }, validPrize.signals[1]] }).ok === false,
);

// ------------------------------------------------------------ server tests
// These start the real server against a local mock Gemini endpoint: no real
// API key, no network beyond localhost. They prove the wire format
// (systemInstruction, not system_instruction), the service-key gate, and
// the rate limiter.
const http = require('http');

function listen(app) {
  return new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
}
function closeSrv(srv) {
  return new Promise((resolve) => srv.close(resolve));
}
async function postAnalyze(port, body, headers) {
  const res = await fetch('http://localhost:' + port + '/ai/analyze', {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => null), headers: res.headers };
}

const SAMPLE_REQ = {
  input: 'Congratulations! You have won Rs 50,000 Paytm cashback. Claim now: bit.ly/xyz123',
  engine: { kind: 'message', score: 45, verdict: { level: 'suspicious', label: 'Suspicious' }, reasons: [{ label: 'Prize bait', points: 25 }] },
};
const MOCK_AI_OUT = {
  assessment: 'phishing', confidence: 'high',
  signals: [
    { type: 'prize_lure', detail: 'An unexpected large cash prize is promised.' },
    { type: 'suspicious_link', detail: 'The claim must be redeemed through a shortened link.' },
  ],
  explanation: 'A prize lure through a hidden link.',
  recommendedAction: 'Do not click the link. Delete the message.',
};

async function runServerTests() {
  let capturedBody = null;
  const gemini = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      try { capturedBody = JSON.parse(raw); } catch { capturedBody = null; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(MOCK_AI_OUT) }] } }] }));
    });
  });
  await new Promise((r) => gemini.listen(0, r));
  const geminiUrl = 'http://localhost:' + gemini.address().port;

  // Instance 1: service key set (auth on).
  process.env.GEMINI_API_KEY = 'test-dummy-key';
  process.env.GEMINI_API_BASE_URL = geminiUrl;
  process.env.GEMINI_MODEL = 'test-model';
  process.env.AI_SERVICE_KEY = 'test-service-key';
  const app1 = require('./server');
  const srv1 = await listen(app1);
  const port1 = srv1.address().port;

  let r = await postAnalyze(port1, SAMPLE_REQ, {});
  check('auth: missing service key -> 401', r.status === 401 && r.json.error.code === 'UNAUTHORIZED');
  r = await postAnalyze(port1, SAMPLE_REQ, { 'X-AI-Service-Key': 'wrong' });
  check('auth: wrong service key -> 401', r.status === 401);
  r = await postAnalyze(port1, SAMPLE_REQ, { 'X-AI-Service-Key': 'test-service-key' });
  check('auth: correct key -> available', r.status === 200 && r.json.available === true && r.json.assessment === 'phishing');
  check('wire: systemInstruction sent (camelCase)',
    capturedBody && capturedBody.systemInstruction &&
    capturedBody.systemInstruction.parts && capturedBody.systemInstruction.parts[0].text.includes('UNTRUSTED DATA'));
  check('wire: no snake_case system_instruction sent', capturedBody && !('system_instruction' in capturedBody));
  const h = await fetch('http://localhost:' + port1 + '/ai/health');
  check('health stays open with key set', h.status === 200);
  await closeSrv(srv1);

  // Instance 2: no service key (open, local-dev mode).
  delete process.env.AI_SERVICE_KEY;
  delete require.cache[require.resolve('./server')];
  const app2 = require('./server');
  const srv2 = await listen(app2);
  const port2 = srv2.address().port;
  r = await postAnalyze(port2, SAMPLE_REQ, {});
  check('auth: no key configured -> open', r.status === 200 && r.json.available === true);
  await closeSrv(srv2);

  // Instance 3: tiny rate limit.
  process.env.AI_RATE_LIMIT_MAX = '2';
  delete require.cache[require.resolve('./server')];
  const app3 = require('./server');
  const srv3 = await listen(app3);
  const port3 = srv3.address().port;
  await postAnalyze(port3, SAMPLE_REQ, {});
  await postAnalyze(port3, SAMPLE_REQ, {});
  r = await postAnalyze(port3, SAMPLE_REQ, {});
  check('rate limit: 3rd call -> 429', r.status === 429 && r.json.error.code === 'RATE_LIMITED');
  check('rate limit: Retry-After header present', r.headers.get('retry-after') !== null);
  await closeSrv(srv3);

  await new Promise((resolve) => gemini.close(resolve));
}

(async () => {
  if (failures > 0) {
    console.log(`\n${failures} offline test(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll offline tests passed.');
  await runServerTests();
  if (failures > 0) {
    console.log(`\n${failures} test(s) failed.`);
    process.exit(1);
  }
  console.log('\nAll tests passed.');
})().catch((e) => {
  console.error('ERROR:', e && e.stack ? e.stack : e);
  process.exit(1);
});
