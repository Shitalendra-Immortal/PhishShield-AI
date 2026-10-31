/**
 * dataset-test.js — accuracy measurement over dataset.json.
 *
 * This is the answer to "passing a small fixed test set does not
 * establish real-world accuracy": live-test.js is the strict gating bar
 * (21 cases, exact sets, must all pass); this script measures accuracy
 * over a larger labelled set (~50 cases across scam types, legitimate
 * types, languages, and edge cases) and reports it per category and
 * per language, so weak spots show up as numbers instead of anecdotes.
 *
 * Usage (two terminals, same as live-test.js):
 *   Terminal 1: cd ai-service && npm start   (with GEMINI_API_KEY set)
 *   Terminal 2: node dataset-test.js
 *   Or: AI_URL=http://localhost:4000 AI_SERVICE_KEY=xxx node dataset-test.js
 *   Optional gate: MIN_ACCURACY=0.8 node dataset-test.js
 *     (exits 1 when overall accuracy is below the threshold; without it,
 *     this script always exits 0 on a completed run — it measures, it
 *     does not gate.)
 *
 * Notes:
 * - Cases are sent WITHOUT an engine result, so this measures the AI's
 *   standalone judgment, not the engine's.
 * - Requests are sequential: 53 calls stay under the 100/15min rate
 *   limit and the 5-way concurrency cap.
 * - available:false answers are reported separately and excluded from
 *   the accuracy denominator (accuracy measures judgment, not uptime;
 *   the live-test already fails on unavailable).
 * - A case passes only when assessment AND confidence are inside their
 *   expected sets AND the signal contract holds (known types, no
 *   duplicates, at most 5, non-empty explanation/action).
 */
const fs = require('fs');
const path = require('path');

const AI_URL = (process.env.AI_URL || 'http://localhost:4000').replace(/\/+$/, '');
const SERVICE_KEY = process.env.AI_SERVICE_KEY || '';
const MIN_ACCURACY = process.env.MIN_ACCURACY ? Number(process.env.MIN_ACCURACY) : null;

const VOCAB = [
  'false_authority', 'manufactured_urgency', 'fake_deadline', 'prize_lure',
  'impersonation', 'credential_request', 'suspicious_link',
  'unverifiable_claim', 'pressure_to_act', 'unusual_sender',
];

function asArray(v) {
  return Array.isArray(v) ? v : [v];
}

async function main() {
  const datasetPath = path.join(__dirname, 'dataset.json');
  let cases;
  try {
    cases = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
  } catch (e) {
    console.error('ERROR: cannot read dataset.json: ' + e.message);
    process.exit(1);
  }
  if (!Array.isArray(cases) || cases.length === 0) {
    console.error('ERROR: dataset.json is empty or not an array.');
    process.exit(1);
  }

  const byCategory = new Map();
  const byLanguage = new Map();
  let evaluated = 0;
  let passed = 0;
  let unavailable = 0;
  let requestErrors = 0;
  const failures = [];

  function tally(map, key, ok) {
    let e = map.get(key);
    if (!e) { e = { pass: 0, total: 0 }; map.set(key, e); }
    e.total += 1;
    if (ok) e.pass += 1;
  }

  for (const c of cases) {
    const headers = { 'Content-Type': 'application/json' };
    if (SERVICE_KEY) headers['X-AI-Service-Key'] = SERVICE_KEY;
    let res;
    let data = null;
    try {
      res = await fetch(AI_URL + '/ai/analyze', {
        method: 'POST',
        headers,
        body: JSON.stringify({ input: c.input }),
      });
      data = await res.json().catch(() => null);
    } catch (e) {
      console.log('ERROR: ' + c.id + ' — request failed: ' + e.message);
      requestErrors += 1;
      continue;
    }
    if (!res.ok) {
      console.log('ERROR: ' + c.id + ' — HTTP ' + res.status);
      if (res.status === 401) console.log('  Hint: if the service has AI_SERVICE_KEY set, pass the same value as AI_SERVICE_KEY env var.');
      requestErrors += 1;
      continue;
    }
    if (!data || !data.available) {
      console.log('UNAVAILABLE: ' + c.id + ' (' + c.category + ') — available:false, excluded from accuracy.');
      unavailable += 1;
      continue;
    }
    const types = (data.signals || []).map((s) => s.type);
    const okA = asArray(c.expect).includes(data.assessment);
    const okC = asArray(c.conf).includes(data.confidence);
    const okSig = types.every((t) => VOCAB.includes(t))
      && new Set(types).size === types.length
      && types.length <= 5
      && typeof data.explanation === 'string' && data.explanation.length > 0
      && typeof data.recommendedAction === 'string' && data.recommendedAction.length > 0;
    const ok = okA && okC && okSig;
    evaluated += 1;
    if (ok) passed += 1;
    else {
      failures.push({ id: c.id, category: c.category, expected: c.expect, conf: c.conf, got: data.assessment, gotConf: data.confidence, signals: types, okA, okC, okSig });
    }
    tally(byCategory, c.category, ok);
    tally(byLanguage, c.language, ok);
  }

  console.log('\n--- failures ---');
  if (failures.length === 0) {
    console.log('(none)');
  } else {
    for (const f of failures) {
      console.log('FAIL ' + f.id + ' [' + f.category + ']: expected ' + asArray(f.expected).join('/') + ' got ' + f.got
        + ' (conf expected ' + asArray(f.conf).join('/') + ' got ' + f.gotConf + ', signals ' + f.signals.join(',') + ')'
        + (!f.okSig ? ' [signal contract broken]' : ''));
    }
  }

  function table(title, map) {
    console.log('\n--- ' + title + ' ---');
    const keys = [...map.keys()].sort();
    for (const k of keys) {
      const e = map.get(k);
      console.log('  ' + k + ': ' + e.pass + '/' + e.total + ' (' + Math.round((e.pass / e.total) * 100) + '%)');
    }
  }
  table('accuracy by category', byCategory);
  table('accuracy by language', byLanguage);

  const accuracy = evaluated > 0 ? passed / evaluated : 0;
  console.log('\n--- overall ---');
  console.log('cases: ' + cases.length + ', evaluated: ' + evaluated + ', passed: ' + passed
    + ', accuracy: ' + (evaluated > 0 ? Math.round(accuracy * 100) + '%' : 'n/a')
    + ', unavailable: ' + unavailable + ', request errors: ' + requestErrors);

  if (evaluated === 0) {
    console.log('No cases evaluated — is the service running with a key configured?');
    process.exit(1);
  }
  if (MIN_ACCURACY !== null && accuracy < MIN_ACCURACY) {
    console.log('Below MIN_ACCURACY (' + MIN_ACCURACY + ').');
    process.exit(1);
  }
  process.exit(0);
}

main().catch((e) => {
  console.error('ERROR:', e && e.stack ? e.stack : e);
  process.exit(1);
});
