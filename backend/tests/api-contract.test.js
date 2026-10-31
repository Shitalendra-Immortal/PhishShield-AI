// Contract tests for the PhishShield backend. Run against a live server:
//   PORT=3101 node server.js  (in another terminal)
//   node tests/api-contract.test.js
// Exits non-zero on the first failure, prints PASS lines otherwise.
'use strict';

const BASE = 'http://localhost:3101';
let passed = 0;

function check(name, cond, extra) {
  if (!cond) {
    console.error('FAIL: ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : ''));
    process.exit(1);
  }
  passed++;
  console.log('PASS: ' + name);
}

async function post(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return { status: res.status, json: await res.json(), headers: res.headers };
}

async function get(path) {
  const res = await fetch(BASE + path);
  return { status: res.status, json: await res.json(), headers: res.headers };
}

(async () => {
  // Health
  const h = await get('/api/health');
  check('health status 200', h.status === 200, h.status);
  check('health body', h.json.status === 'ok' && h.json.service === 'phishshield-api' && h.json.version === '1.0.0', h.json);
  check('CORS header present', h.headers.get('access-control-allow-origin') === '*', h.headers.get('access-control-allow-origin'));

  // OPTIONS preflight
  const opt = await fetch(BASE + '/api/analyze', { method: 'OPTIONS' });
  check('OPTIONS returns 204', opt.status === 204, opt.status);

  // Phishing message (real engine output: 95, phishing, 10 reasons)
  const upi = 'Dear customer, your SBI KYC is incomplete. Your account will be blocked within 24 hours. Update KYC now: http://sbi-kyc-update.xyz/verify';
  const a = await post('/api/analyze', { input: upi });
  check('upi status 200', a.status === 200, a.status);
  check('upi score 95', a.json.score === 95, a.json.score);
  check('upi verdict phishing', a.json.verdict.level === 'phishing' && a.json.verdict.label === 'Likely Phishing', a.json.verdict);
  check('upi kind message', a.json.kind === 'message', a.json.kind);
  check('upi 10 reasons', Array.isArray(a.json.reasons) && a.json.reasons.length === 10, a.json.reasons && a.json.reasons.length);
  check('upi urls extracted', Array.isArray(a.json.urls) && a.json.urls.length === 1, a.json.urls);
  check('upi advice present', typeof a.json.verdict.advice === 'string' && a.json.verdict.advice.length > 0);

  // Forced message mode gives the same result
  const am = await post('/api/analyze', { input: upi, type: 'message' });
  check('forced message same score', am.json.score === 95, am.json.score);

  // Suspicious URL (real: 43, suspicious, 4 reasons)
  const s = await post('/api/analyze', { input: 'http://secure-update-verify.xyz/login' });
  check('suspicious score 43', s.json.score === 43, s.json.score);
  check('suspicious verdict', s.json.verdict.level === 'suspicious', s.json.verdict);
  check('suspicious kind url + host', s.json.kind === 'url' && s.json.host === 'secure-update-verify.xyz', s.json);

  // Safe URL with official-domain note
  const l = await post('/api/analyze', { input: 'https://www.amazon.in/gp/order' });
  check('legit score 0 safe', l.json.score === 0 && l.json.verdict.level === 'safe', l.json);
  check('legit official note', l.json.note === 'Official domain of Amazon India.', l.json.note);

  // Forced URL mode on an official domain
  const g = await post('/api/analyze', { input: 'https://www.google.com', type: 'url' });
  check('forced url google safe', g.json.score === 0 && g.json.note === 'Official domain of Google.', g.json);

  // Errors
  const e1 = await post('/api/analyze', {});
  check('missing input 400', e1.status === 400 && e1.json.error.code === 'MISSING_INPUT', e1);
  const e2 = await post('/api/analyze', { input: '   ' });
  check('whitespace input 400', e2.status === 400 && e2.json.error.code === 'MISSING_INPUT', e2);
  const e3 = await post('/api/analyze', { input: 'x'.repeat(5001) });
  check('too long 413', e3.status === 413 && e3.json.error.code === 'INPUT_TOO_LONG', e3);
  const e4 = await post('/api/analyze', { input: 'hello', type: 'bogus' });
  check('bad type 400', e4.status === 400 && e4.json.error.code === 'INVALID_TYPE', e4);
  const e5 = await get('/api/nope');
  check('unknown route 404', e5.status === 404 && e5.json.error.code === 'NOT_FOUND', e5);

  // Samples
  const sm = await get('/api/samples');
  check('samples 3 items', sm.json.samples && sm.json.samples.length === 3, sm.json);
  check('samples expected levels',
    sm.json.samples[0].expectedLevel === 'phishing' &&
    sm.json.samples[1].expectedLevel === 'suspicious' &&
    sm.json.samples[2].expectedLevel === 'safe', sm.json.samples);

  console.log('\nALL ' + passed + ' CHECKS PASSED');
})().catch((err) => {
  console.error('ERROR: ' + err.message);
  process.exit(1);
});
