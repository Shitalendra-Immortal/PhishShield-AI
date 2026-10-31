// Spot checks for the extended engine, via the live backend API.
// Run against a server on port 3101. Expects the NEW engine scores.
'use strict';
const BASE = 'http://localhost:3101';
const cases = [
  ['Aapka SBI account band ho jayega. Turant KYC update karein: http://sbi-kyc-update.xyz/verify', 90, 'phishing'],
  ['Your electricity bill is pending. Power will be disconnected tonight. Pay now: http://electricity-bill-pay.top/', 60, 'phishing'],
  ['http://pnb-kyc-verify.shop/login', 73, 'phishing'],
  ['https://www.onlinesbi.com/', 0, 'safe'],
  ['http://tiny.cc/abc123', 30, 'suspicious']
];
(async () => {
  for (const [input, score, level] of cases) {
    const res = await fetch(BASE + '/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input })
    });
    const data = await res.json();
    const ok = res.status === 200 && data.score === score && data.verdict.level === level;
    console.log((ok ? 'PASS' : 'FAIL') + ' score=' + data.score + ' level=' + data.verdict.level +
      ' (expected ' + score + '/' + level + ') :: ' + input.slice(0, 60));
    if (!ok) process.exit(1);
  }
  console.log('\nALL ' + cases.length + ' NEW-ENGINE API CHECKS PASSED');
})().catch((e) => { console.error('ERROR: ' + e.message); process.exit(1); });
