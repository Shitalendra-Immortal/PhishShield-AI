// PhishShield backend — dataset evaluation (offline, not runtime).
// Usage (from backend/):
//   node tests/dataset-eval.js                    (Hugging Face, default)
//   node tests/dataset-eval.js --dataset junioralive
//   node tests/dataset-eval.js --dataset all       (both datasets)
//   node tests/dataset-eval.js --local path/to/file.csv  (auto-detects
//     text/Msg and label/Label columns)
//
// What it does:
//   1. Fetches the public Hugging Face dataset anmolshrivastav/scam-ham-india
//      (Apache-2.0, no API key, 2272 rows: text + label spam/ham) — OR reads
//      a local CSV given with --local. Nothing is sent to Hugging Face:
//      only the public CSV is downloaded, once, for evaluation.
//   2. Splits spam into PHISHING-LIKE vs MARKETING, because "spam" in this
//      dataset does NOT mean phishing. Most spam is legit telecom/bank
//      marketing and even a CERT-In advisory. Tuning the engine to flag
//      all of that as phishing would destroy ham accuracy.
//      Phishing-like = spam + a clear scam action (share OTP/CVV/account,
//      pay a fee to release/claim, KYC + block/freeze, prize + share/pay/
//      contact/claim, enter a code/password on a website, debit + share OTP).
//   3. Runs analyzer.js over every row and prints:
//      phishing-like recall, ham false-positive rate, all-spam recall,
//      overall accuracy. Exits 1 if phishing recall < 80% or ham FP > 2%.
// This script is test tooling only. It is NOT used by the live /api/analyze
// endpoint, and the dataset is NOT bundled into the production backend.
'use strict';
const fs = require('fs');
const path = require('path');

const DATASETS = {
  hf: {
    name: 'Hugging Face anmolshrivastav/scam-ham-india',
    url: 'https://huggingface.co/datasets/anmolshrivastav/scam-ham-india/resolve/main/scam_hum_india.csv',
  },
  junioralive: {
    name: 'GitHub junioralive/india-spam-sms-classification',
    url: 'https://raw.githubusercontent.com/junioralive/india-spam-sms-classification/main/dataset/spam_ham_india.csv',
  },
};

function loadAnalyzer() {
  const candidates = [
    path.join(__dirname, '..', 'analyzer.js'), // backend/tests/dataset-eval.js
    path.join(__dirname, 'analyzer.js'),       // same folder (patch copy)
  ];
  for (const c of candidates) {
    try { return require(c); } catch (e) { /* try next */ }
  }
  throw new Error('analyzer.js not found next to this script or one level up');
}

function parseCsv(text) {
  const rows = [];
  let field = '', row = [], inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
      } else field += ch;
    } else if (ch === '"') inQuotes = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (ch !== '\r') field += ch;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  // Header-aware: HF uses text,label; junioralive uses Msg,Label.
  // Fall back to first/second column if headers are unrecognised.
  const header = rows.shift().map(h => h.trim().toLowerCase());
  let ti = header.indexOf('text'); if (ti === -1) ti = header.indexOf('msg');
  let li = header.indexOf('label');
  if (ti === -1) ti = 0;
  if (li === -1) li = 1;
  return rows.filter(r => r.length >= 2).map(r => ({
    text: r[ti], label: (r[li] || '').trim(),
  }));
}

function isPhishingLike(text) {
  const s = text.toLowerCase();
  // PATCH v5: a safety warning mentioning a scam action is not a scam.
  // "Never click unknown link or share your Bank details" must not count.
  if (/never[^.]{0,60}share/.test(s) || /(do not|don't)[^.]{0,30}share/.test(s)) return false;
  return (
    /\bshare\b[^.]{0,40}\b(otp|pin|cvv|password|account number|bank details|card number|aadhaar)\b/.test(s) ||
    /\b(otp|pin|cvv|password)\b[^.]{0,40}\bshare\b/.test(s) ||
    /\bpay\b[^.]{0,40}\b(fee|gst)\b[^.]{0,40}\b(release|claim|winning|prize)\b/.test(s) ||
    /\b(fee)\b[^.]{0,30}\b(release|claim)\b/.test(s) ||
    /\bkyc\b[^.]{0,50}\b(block|freeze|lock|suspend|deactivat)/.test(s) ||
    /\b(block|freeze|lock|suspend|deactivat)[^.]{0,50}\bkyc\b/.test(s) ||
    /\b(prize|won|lottery|jackpot)\b[^.]{0,50}\b(share|pay|contact|claim|account)\b/.test(s) ||
    /\bwon\b[^.]{0,40}\b(cash prize|prize)\b/.test(s) ||
    /\benter\b[^.]{0,40}\b(otp|pin|password|code)\b[^.]{0,30}\b(website|link|site)\b/.test(s) ||
    /\benter\b[^.]{0,40}\b(net banking password|password)\b/.test(s) ||
    /\bdebit[^.]{0,60}\bshare\b[^.]{0,20}\botp\b/.test(s) ||
    /\bcall\b[^.]{0,30}\bshare\b[^.]{0,20}\b(cvv|card number)\b/.test(s)
  );
}

async function evaluateOne(analyzer, datasetKey, csvText) {
  const rows = parseCsv(csvText);
  const phishing = rows.filter(r => r.label === 'spam' && isPhishingLike(r.text));
  const marketing = rows.filter(r => r.label === 'spam' && !isPhishingLike(r.text));
  const ham = rows.filter(r => r.label === 'ham');
  const spam = rows.filter(r => r.label === 'spam');
  const score = t => analyzer.analyze(t).score;
  const caught = set => set.filter(r => score(r.text) >= 30).length;
  const pc = caught(phishing), hc = caught(ham), sc = caught(spam);
  const acc = ((sc + (ham.length - hc)) / rows.length * 100).toFixed(1);
  console.log('Rows: ' + rows.length + ' | spam: ' + spam.length + ' | ham: ' + ham.length);
  console.log('PHISHING-LIKE (spam + scam action): ' + pc + '/' + phishing.length + ' = ' + (phishing.length ? (pc / phishing.length * 100).toFixed(1) : 'n/a') + '% caught (>=30)');
  console.log('MARKETING/other spam: ' + caught(marketing) + '/' + marketing.length + ' = ' + (marketing.length ? (caught(marketing) / marketing.length * 100).toFixed(1) : 'n/a') + '% caught (NOT a target)');
  console.log('HAM false positives: ' + hc + '/' + ham.length + ' = ' + (hc / ham.length * 100).toFixed(2) + '%');
  console.log('ALL spam caught: ' + sc + '/' + spam.length + ' = ' + (sc / spam.length * 100).toFixed(1) + '%');
  console.log('OVERALL accuracy (spam>=30, ham<30): ' + acc + '%');
  console.log('Missed phishing-like:');
  phishing.filter(r => score(r.text) < 30).forEach(r => {
    console.log('  ' + score(r.text) + ' | ' + r.text.slice(0, 160));
  });
  const ok = (phishing.length === 0) || ((pc / phishing.length >= 0.8) && (hc / ham.length <= 0.02));
  console.log(ok ? 'PASS: phishing recall >= 80% and ham FP <= 2%' : 'FAIL: phishing recall < 80% or ham FP > 2%');
  return ok;
}

async function main() {
  const analyzer = loadAnalyzer();
  const localIdx = process.argv.indexOf('--local');
  const dsIdx = process.argv.indexOf('--dataset');
  const dsArg = dsIdx !== -1 ? process.argv[dsIdx + 1] : 'hf';
  let overallOk = true;
  if (localIdx !== -1) {
    console.log('\n=== Dataset: local file ===');
    const csvText = fs.readFileSync(process.argv[localIdx + 1], 'utf8');
    overallOk = await evaluateOne(analyzer, 'local', csvText);
  } else {
    const keys = dsArg === 'all' ? ['hf', 'junioralive'] : [dsArg in DATASETS ? dsArg : 'hf'];
    for (const key of keys) {
      console.log('\n=== Dataset: ' + DATASETS[key].name + ' ===');
      console.log('Downloading ' + DATASETS[key].url);
      const res = await fetch(DATASETS[key].url);
      if (!res.ok) throw new Error('Dataset download failed: HTTP ' + res.status);
      const csvText = await res.text();
      const ok = await evaluateOne(analyzer, key, csvText);
      overallOk = overallOk && ok;
    }
  }
  process.exit(overallOk ? 0 : 1);
}
main().catch(e => { console.error('ERROR: ' + e.message); process.exit(1); });
