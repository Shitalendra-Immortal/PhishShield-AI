// Tests for the AI second-opinion integration (ai.js + server wiring).
// Uses local mock ai-services; never touches the real Gemini API.
// Run: node tests/ai.test.js  (this file starts its own servers)
'use strict';

const http = require('http');
const { getAiOpinion } = require('../ai.js');

let passed = 0;
function check(name, cond, extra) {
  if (!cond) {
    console.error('FAIL: ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : ''));
    process.exit(1);
  }
  passed++;
  console.log('PASS: ' + name);
}

const ENGINE = {
  kind: 'message', score: 45,
  verdict: { level: 'suspicious', label: 'Suspicious' },
  reasons: [{ label: 'Prize bait', points: 25 }, { label: 'Link shortener hides the destination', points: 20 }]
};

const GOOD = {
  available: true, assessment: 'phishing', confidence: 'high',
  signals: [{ type: 'prize_lure', detail: 'An unexpected prize is promised.' }],
  explanation: 'A prize lure through a hidden link.',
  recommendedAction: 'Do not click the link. Delete the message.'
};

const UNAVAILABLE = {
  available: false, assessment: null, confidence: null,
  signals: [], explanation: null, recommendedAction: null
};

function startMock(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, () => resolve({ srv, url: 'http://localhost:' + srv.address().port }));
  });
}

function close(srv) { return new Promise((resolve) => srv.close(resolve)); }

function jsonRes(res, obj, status) {
  res.writeHead(status || 200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

async function post(path, body, port) {
  const res = await fetch('http://localhost:' + port + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { status: res.status, json: await res.json() };
}

(async () => {
  delete process.env.AI_SERVICE_URL;

  // --- unit: getAiOpinion ---
  let m = await startMock((req, res) => jsonRes(res, GOOD));
  let op = await getAiOpinion('prize sms', ENGINE, { baseUrl: m.url });
  check('valid opinion returned', op && op.assessment === 'phishing' && op.confidence === 'high');
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, UNAVAILABLE));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('available:false -> null', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { assessment: 'malicious' })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('invalid assessment rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: [{ type: 'made_up', detail: 'nope' }] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('invented signal type rejected', op === null);
  await close(m.srv);

  // --- stricter backend re-validation (defence in depth) ---
  const sig = (t) => ({ type: t, detail: 'detail for ' + t });
  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: [sig('prize_lure'), sig('prize_lure')] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('duplicate signal type rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: ['prize_lure', 'manufactured_urgency', 'impersonation', 'credential_request', 'suspicious_link', 'unusual_sender'].map(sig) })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('6 signals rejected (max 5)', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: [{ type: 'prize_lure', detail: '' }] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('empty signal detail rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: [{ type: 'prize_lure', detail: 'x'.repeat(501) }] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('over-long signal detail rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { explanation: 'x'.repeat(1001) })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('over-long explanation rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { recommendedAction: 'x'.repeat(301) })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('over-long recommended action rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: [] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('phishing assessment with no signals rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { assessment: 'safe', confidence: 'high', signals: [] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('high confidence with no signals rejected', op === null);
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { assessment: 'safe', confidence: 'medium', signals: [] })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('safe verdict with no signals accepted', op !== null && op.assessment === 'safe');
  await close(m.srv);

  m = await startMock((req, res) => jsonRes(res, Object.assign({}, GOOD, { signals: ['prize_lure', 'manufactured_urgency', 'impersonation', 'credential_request', 'suspicious_link'].map(sig) })));
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('5 distinct signals accepted', op !== null && op.signals.length === 5);
  await close(m.srv);

  m = await startMock((req, res) => { setTimeout(() => jsonRes(res, GOOD), 400); });
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url, timeoutMs: 50 });
  check('timeout -> null', op === null);
  await close(m.srv);

  m = await startMock((req, res) => { res.writeHead(500); res.end('{}'); });
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('provider 500 -> null', op === null);
  await close(m.srv);

  op = await getAiOpinion('x', ENGINE, {});
  check('disabled (no URL) -> null', op === null);

  // Service-key header: sent only when AI_SERVICE_KEY is configured.
  let seenHeaders = null;
  m = await startMock((req, res) => {
    seenHeaders = req.headers;
    jsonRes(res, GOOD);
  });
  process.env.AI_SERVICE_KEY = 'test-key';
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('service key header sent when configured', op !== null && seenHeaders['x-ai-service-key'] === 'test-key');
  await close(m.srv);
  delete process.env.AI_SERVICE_KEY;
  m = await startMock((req, res) => {
    seenHeaders = req.headers;
    jsonRes(res, GOOD);
  });
  op = await getAiOpinion('x', ENGINE, { baseUrl: m.url });
  check('no service key header when unconfigured', op !== null && !seenHeaders['x-ai-service-key']);
  await close(m.srv);

  // --- server-level: wiring ---
  let mode = 'good';
  m = await startMock((req, res) => {
    if (mode === 'down') { res.writeHead(500); res.end('{}'); return; }
    if (mode === 'unavailable') { jsonRes(res, UNAVAILABLE); return; }
    jsonRes(res, GOOD);
  });
  process.env.AI_SERVICE_URL = m.url;
  process.env.REDIRECT_ENABLED = '0';
  process.env.URLHAUS_ENABLED = '0';
  const app = require('../server.js');
  const appSrv = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
  const port = appSrv.address().port;

  const PRIZE = { input: 'Congratulations! You have won Rs 50,000 Paytm cashback. Claim now: bit.ly/xyz123', type: 'message' };
  const UPI = { input: 'Dear customer, your SBI KYC is incomplete. Your account will be blocked within 24 hours. Update KYC now: http://sbi-kyc-update.xyz/verify', type: 'message' };

  let r = await post('/api/analyze', PRIZE, port);
  check('borderline gets ai field', r.json.ai && r.json.ai.assessment === 'phishing');
  check('engine score/verdict untouched by AI', r.json.score === 45 && r.json.verdict.level === 'suspicious');

  r = await post('/api/analyze', UPI, port);
  check('clear phishing gets ai field', r.json.ai && r.json.ai.assessment === 'phishing');
  check('engine score/verdict untouched by AI on phishing', r.json.score === 95 && r.json.verdict.level === 'phishing');

  const SAFE = { input: 'https://www.amazon.in/gp/order', type: 'url' };
  r = await post('/api/analyze', SAFE, port);
  check('safe gets ai field', r.json.ai && r.json.score === 0 && r.json.verdict.level === 'safe');

  mode = 'unavailable';
  r = await post('/api/analyze', PRIZE, port);
  check('available:false -> field omitted', !('ai' in r.json));

  mode = 'down';
  r = await post('/api/analyze', PRIZE, port);
  check('provider down -> field omitted, request still 200', r.status === 200 && !('ai' in r.json));

  r = await post('/api/analyze', SAFE, port);
  check('provider down on safe scan -> field omitted, request still 200', r.status === 200 && !('ai' in r.json) && r.json.score === 0);

  delete process.env.AI_SERVICE_URL;
  r = await post('/api/analyze', PRIZE, port);
  check('AI disabled -> field omitted', !('ai' in r.json));

  await close(appSrv);
  await close(m.srv);
  console.log('\nALL ' + passed + ' AI CHECKS PASSED');
})().catch((e) => { console.error('ERROR: ' + (e && e.stack || e)); process.exit(1); });
