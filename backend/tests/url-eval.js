// PhiUSIIL Phishing URL Dataset — offline URL-mode evaluation for PhishShield.
// Test tooling only. Place in backend/tests/ and run:
//   node tests/url-eval.js --local path/to/PhiUSIIL_Phishing_URL_Dataset.csv
//   node tests/url-eval.js --local path/to/file.csv --sample 20000
//   node tests/url-eval.js --local path/to/file.csv --missed out.json
//
// Labels (PhiUSIIL, INVERTED from the usual convention):
//   0 = phishing, 1 = legitimate. Getting this backwards reverses every result.
// Only the URL column is used. PhishShield never fetches a page, so the
// dataset's page features (title, favicon, forms, ...) are ignored on purpose.
// The dataset is ~54 MB and is NOT bundled into production.
// Scoring: phishing caught = analyzeUrl score >= 30 (suspicious or phishing).
// Legitimate FP = legitimate URL with score >= 30.
// Exit 0 only if phishing recall >= 80% and legitimate FP <= 2% — the same
// bar as dataset-eval.js. A URL-only engine will usually NOT pass the
// recall bar on this dataset, and that is an honest result, not a bug to
// chase with generic rules (see NOTES at the bottom).
'use strict';
const fs = require('fs');

function loadAnalyzer() {
  try { return require('../analyzer.js'); } catch (e) { return require('./analyzer.js'); }
}

function parseCsv(text) {
  const rows = [];
  let cur = '', inQ = false, field = '', row = [];
  function pushField() { row.push(field); field = ''; }
  function pushRow() { pushField(); rows.push(row); row = []; }
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else { inQ = false; }
      } else { field += c; }
    } else if (c === '"') { inQ = true; }
    else if (c === ',') { pushField(); }
    else if (c === '\n') { pushRow(); }
    else if (c !== '\r') { field += c; }
  }
  if (field !== '' || row.length) pushRow();
  const header = rows.shift().map(h => h.replace(/^\uFEFF/, '').trim().toLowerCase());
  const ui = header.indexOf('url');
  const li = header.indexOf('label');
  if (ui === -1 || li === -1) throw new Error('CSV must have URL and label columns, got: ' + header.join(','));
  // Keep the feature columns too, for missed/FP breakdowns.
  return rows.filter(r => r.length > Math.max(ui, li) && r[ui]).map(r => {
    const o = { url: r[ui].trim(), label: (r[li] || '').trim() };
    header.forEach((h, idx) => { o[h] = r[idx]; });
    return o;
  });
}

function main() {
  const analyzer = loadAnalyzer();
  const localIdx = process.argv.indexOf('--local');
  if (localIdx === -1) {
    console.log('Usage: node tests/url-eval.js --local path/to/PhiUSIIL_Phishing_URL_Dataset.csv [--sample N] [--missed out.json] [--fp out.json]');
    process.exit(2);
  }
  const sampleIdx = process.argv.indexOf('--sample');
  const sample = sampleIdx !== -1 ? parseInt(process.argv[sampleIdx + 1], 10) : 0;
  const missedIdx = process.argv.indexOf('--missed');
  const fpIdx = process.argv.indexOf('--fp');
  const text = fs.readFileSync(process.argv[localIdx + 1], 'utf8');
  let rows = parseCsv(text);
  console.log('Rows loaded: ' + rows.length);
  if (sample > 0 && rows.length > sample) {
    // Deterministic stride sample, not first-N (the file is grouped).
    const step = rows.length / sample;
    const sampled = [];
    for (let i = 0; i < sample; i++) sampled.push(rows[Math.floor(i * step)]);
    rows = sampled;
    console.log('Sampled (stride): ' + rows.length);
  }
  const t0 = Date.now();
  const phish = [], legit = [];
  const bands = { phish: { safe: 0, susp: 0, phish: 0 }, legit: { safe: 0, susp: 0, phish: 0 } };
  const missed = [], fps = [];
  const byTldMiss = {}, byTldFp = {};
  const tldOf = u => { try { return new URL(/^https?:\/\//i.test(u) ? u : 'https://' + u).hostname.split('.').pop(); } catch (e) { return '?'; } };
  rows.forEach(r => {
    const score = analyzer.analyzeUrl(r.url).score;
    const band = score >= 60 ? 'phish' : score >= 30 ? 'susp' : 'safe';
    if (r.label === '0') {
      phish.push(r); bands.phish[band]++;
      if (score < 30) { missed.push({ url: r.url, score, tld: tldOf(r.url), IsDomainIP: r.isdomainip, NoOfSubDomain: r.noofsubdomain, HasObfuscation: r.hasobfuscation, IsHTTPS: r.ishttps, HasPasswordField: r.haspasswordfield }); byTldMiss[tldOf(r.url)] = (byTldMiss[tldOf(r.url)] || 0) + 1; }
    } else if (r.label === '1') {
      legit.push(r); bands.legit[band]++;
      if (score >= 30) { fps.push({ url: r.url, score, reasons: analyzer.analyzeUrl(r.url).reasons.map(x => x.label) }); byTldFp[tldOf(r.url)] = (byTldFp[tldOf(r.url)] || 0) + 1; }
    }
  });
  const phCaught = bands.phish.susp + bands.phish.phish;
  const fp = bands.legit.susp + bands.legit.phish;
  console.log('Phishing (label 0): ' + phish.length + ' | caught >=30: ' + phCaught + ' (' + (phish.length ? (phCaught / phish.length * 100).toFixed(1) : 'n/a') + '%) | phishing band >=60: ' + bands.phish.phish + ' | missed <30: ' + bands.phish.safe);
  console.log('Legitimate (label 1): ' + legit.length + ' | FP >=30: ' + fp + ' (' + (legit.length ? (fp / legit.length * 100).toFixed(2) : 'n/a') + '%) | FP phishing band >=60: ' + bands.legit.phish);
  console.log('Time: ' + ((Date.now() - t0) / 1000).toFixed(1) + 's for ' + rows.length + ' URLs');
  const top = obj => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([k, v]) => k + ':' + v).join(', ');
  console.log('Missed by TLD (top): ' + top(byTldMiss));
  console.log('FP by TLD (top): ' + top(byTldFp));
  console.log('First 10 missed:');
  missed.slice(0, 10).forEach(m => console.log('  ' + m.score + ' | ' + m.url));
  console.log('First 10 FP:');
  fps.slice(0, 10).forEach(m => console.log('  ' + m.score + ' | ' + m.url + ' | ' + m.reasons.join('; ')));
  if (missedIdx !== -1) fs.writeFileSync(process.argv[missedIdx + 1], JSON.stringify(missed, null, 2));
  if (fpIdx !== -1) fs.writeFileSync(process.argv[fpIdx + 1], JSON.stringify(fps, null, 2));
  const ok = phish.length && (phCaught / phish.length >= 0.8) && (fp / legit.length <= 0.02);
  console.log(ok ? 'PASS' : 'FAIL (see NOTES: URL-only recall on PhiUSIIL is expected to be below 80% — do not chase it with generic rules)');
  process.exit(ok ? 0 : 1);
}
main();

// NOTES — why URL-only recall stays low on PhiUSIIL, honestly:
// Many phishing URLs in this dataset are just a plain, short, HTTPS
// domain with no brand token, no IP, no @, no punycode, no suspicious
// TLD and no hyphen stack — e.g. a random .com with a login page.
// From the URL string alone, that is indistinguishable from a legitimate
// site. Catching those would require fetching the page (title, forms,
// password field) or a blocklist like URLhaus — both outside the
// engine's URL-string scope, and page fetching is forbidden by the
// PhishShield contract (never fetch URLs). A rule that flags every
// unknown domain would raise legitimate FP far above 2% and is not
// a real improvement. The useful signal from this dataset is therefore
// the FP rate and the missed-pattern breakdown, not a single recall number.
