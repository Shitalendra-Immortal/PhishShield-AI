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
  independentSignalCount,
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

// Independence: two signals from the same cluster are one piece of
// evidence, so high confidence is downgraded; two clusters keep it.
const sig = (type) => ({ type, detail: `Evidence of ${type}.` });
const clusteredHigh = (types) => validateAiOutput({ ...validPrize, signals: types.map(sig) });
check(
  'high from urgency + deadline (one pressure tactic) is downgraded to medium',
  clusteredHigh(['manufactured_urgency', 'fake_deadline']).data.confidence === 'medium',
);
check(
  'high from urgency + threat (one pressure tactic) is downgraded to medium',
  clusteredHigh(['manufactured_urgency', 'pressure_to_act']).data.confidence === 'medium',
);
check(
  'high from impersonation + false authority (one identity claim) is downgraded to medium',
  clusteredHigh(['impersonation', 'false_authority']).data.confidence === 'medium',
);
check(
  'high from urgency + credential request (two clusters) stays high',
  clusteredHigh(['manufactured_urgency', 'credential_request']).data.confidence === 'high',
);
check(
  'high from urgency + deadline + credential request (two clusters) stays high',
  clusteredHigh(['manufactured_urgency', 'fake_deadline', 'credential_request']).data.confidence === 'high',
);
check(
  'high from impersonation + unusual sender stays high (sender mismatch is a separate observable)',
  clusteredHigh(['impersonation', 'unusual_sender']).data.confidence === 'high',
);
check(
  'independentSignalCount counts clusters once',
  independentSignalCount([
    { type: 'manufactured_urgency' }, { type: 'fake_deadline' }, { type: 'prize_lure' },
  ]) === 2,
);
check(
  'system prompt teaches independence, not just signal count',
  SYSTEM_PROMPT.includes('INDEPENDENT pieces of evidence') && SYSTEM_PROMPT.includes('one pressure tactic'),
);

// Cross-field validation: the verdict must cohere with its signals.
const crossField = (assessment, confidence, types) => validateAiOutput({
  assessment, confidence,
  signals: types.map(sig),
  explanation: 'An explanation grounded in the input.',
  recommendedAction: 'Verify through official channels.',
});
check(
  'safe with no signals is accepted',
  crossField('safe', 'low', []).ok === true,
);
check(
  'phishing with no signals is rejected, not shown evidence-free',
  crossField('phishing', 'high', []).ok === false,
);
check(
  'safe with credential request + impersonation is downgraded to suspicious, not phishing',
  (() => { const r = crossField('safe', 'medium', ['credential_request', 'impersonation']); return r.ok === true && r.data.assessment === 'suspicious'; })(),
);
check(
  'safe with credential request + false authority is downgraded too (same identity cluster)',
  (() => { const r = crossField('safe', 'medium', ['credential_request', 'false_authority']); return r.ok === true && r.data.assessment === 'suspicious'; })(),
);
check(
  'safe with a credential request alone stays safe (legitimate contexts are not forced)',
  (() => { const r = crossField('safe', 'low', ['credential_request']); return r.ok === true && r.data.assessment === 'safe'; })(),
);
check(
  'safe with impersonation alone stays safe (the table only flags the pair)',
  (() => { const r = crossField('safe', 'low', ['impersonation']); return r.ok === true && r.data.assessment === 'safe'; })(),
);
check(
  'suspicious with one weak indicator and high confidence is accepted at medium',
  (() => { const r = crossField('suspicious', 'high', ['unusual_sender']); return r.ok === true && r.data.assessment === 'suspicious' && r.data.confidence === 'medium'; })(),
);
check(
  'suspicious with one weak indicator and low confidence stays low',
  (() => { const r = crossField('suspicious', 'low', ['unusual_sender']); return r.ok === true && r.data.confidence === 'low'; })(),
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
  'system prompt covers Devanagari Hindi understanding',
  SYSTEM_PROMPT.includes('Devanagari') && SYSTEM_PROMPT.includes('ओटीपी साझा करें'),
);
check(
  'system prompt covers mixed-script messages',
  SYSTEM_PROMPT.includes('Mixed-language') && SYSTEM_PROMPT.includes('across ALL scripts'),
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

  // Instance 4: concurrency cap (slow mock Gemini, max 2).
  const slowGemini = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify(MOCK_AI_OUT) }] } }] }));
      }, 400);
    });
  });
  await new Promise((r) => slowGemini.listen(0, r));
  process.env.GEMINI_API_KEY = 'test-dummy-key';
  process.env.GEMINI_API_BASE_URL = 'http://localhost:' + slowGemini.address().port;
  process.env.GEMINI_MODEL = 'test-model';
  delete process.env.AI_SERVICE_KEY;
  delete process.env.AI_RATE_LIMIT_MAX;
  process.env.AI_MAX_CONCURRENT = '2';
  delete require.cache[require.resolve('./server')];
  const app4 = require('./server');
  const srv4 = await listen(app4);
  const port4 = srv4.address().port;
  const parallel = await Promise.all([
    postAnalyze(port4, SAMPLE_REQ, {}),
    postAnalyze(port4, SAMPLE_REQ, {}),
    postAnalyze(port4, SAMPLE_REQ, {}),
  ]);
  const withAi = parallel.filter((r) => r.json && r.json.available === true).length;
  const withoutAi = parallel.filter((r) => r.json && r.json.available === false).length;
  check('concurrency: 2 of 3 parallel calls get an AI opinion at cap 2', withAi === 2);
  check('concurrency: the over-cap call fails open (available:false, no 500)', withoutAi === 1);
  await closeSrv(srv4);
  await new Promise((resolve) => slowGemini.close(resolve));

  // Instance 5: bounded rate-limit map (small cap, distinct IPs via
  // X-Forwarded-For, which the service trusts behind Render's proxy).
  process.env.GEMINI_API_BASE_URL = geminiUrl;
  process.env.AI_RATE_LIMIT_MAX = '2';
  process.env.AI_RATE_LIMIT_MAX_ENTRIES = '3';
  delete process.env.AI_MAX_CONCURRENT;
  delete require.cache[require.resolve('./server')];
  const app5 = require('./server');
  const srv5 = await listen(app5);
  const port5 = srv5.address().port;
  const fromIp = (ip) => postAnalyze(port5, SAMPLE_REQ, { 'X-Forwarded-For': ip });
  await fromIp('10.1.0.1'); await fromIp('10.1.0.1');
  let r5 = await fromIp('10.1.0.1');
  check('cap test: 3rd call from same IP -> 429', r5.status === 429);
  await fromIp('10.1.0.2'); await fromIp('10.1.0.3');
  await fromIp('10.1.0.4'); // evicts the oldest bucket (10.1.0.1)
  r5 = await fromIp('10.1.0.1');
  check('cap test: evicted IP gets a fresh bucket instead of staying blocked', r5.status === 200);
  await closeSrv(srv5);

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
