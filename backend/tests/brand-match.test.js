// Brand-matching fix: token-based (not substring) brand detection in
// URLs + extended official domains. Pure engine checks, no server.
// Run: node tests/brand-match.test.js
'use strict';
const { analyze, analyzeUrl } = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function hasBrand(reasons) {
  return reasons.some(function (r) { return r.label.indexOf('Brand name') === 0; });
}
function brandOf(reasons) {
  const r = reasons.filter(function (x) { return x.label.indexOf('Brand name') === 0; });
  return r.length ? r[0].label : null;
}

// Fixed false positives: brand abbreviations embedded mid-word no
// longer fire (the combined evaluation's biggest FP source).
const fixed = [
  'https://www.cupinfo.com', 'https://www.ubuntupit.com',
  'https://www.massbio.org', 'https://www.ridethisbike.com',
  'https://www.thebigapplegirl.com', 'https://stupid.its',
];
fixed.forEach(function (u) {
  const r = analyzeUrl(u);
  check('no brand fire on ' + u, !hasBrand(r.reasons) && r.score === 0, r);
});

// Official domains added by this fix: genuine brand domains that the
// old list missed (their subdomains fired as impersonation).
const official = [
  ['https://www.jio.com', 'Jio'],
  ['https://i.airtel.in/OFFER4', 'Airtel'],
  ['https://open.airtelxstream.in/Sonyliv_Subs_at_Rs1', 'Airtel Xstream'],
  ['https://amazonaws.cn', 'Amazon'],
];
official.forEach(function (pair) {
  const r = analyzeUrl(pair[0]);
  check(pair[1] + ' domain is official: ' + pair[0],
    r.score === 0 && (r.note || '').indexOf('Official domain of ' + pair[1]) === 0, r);
});

// Still flagged: the real phishing shapes (hyphen tokens, brand as a
// subdomain label, glued brand prefixes, leetspeak).
const phishing = [
  ['https://paypal-login.com', 'paypal'],
  ['https://login-paypal.com', 'paypal'],
  ['https://paypallogin.com', 'paypal'],
  ['https://sbiupdate.com', 'sbi'],
  ['https://apple-support.com', 'apple'],
  ['https://paypal.com.evil.com', 'paypal'],
  ['https://paypa1-secure.com', 'paypal'],
  ['https://secure-paytm.xyz', 'paytm'],
];
phishing.forEach(function (pair) {
  const r = analyzeUrl(pair[0]);
  check('brand still fires on ' + pair[0],
    hasBrand(r.reasons) && (brandOf(r.reasons) || '').indexOf('"' + pair[1] + '"') !== -1
      && r.score >= 30, r);
});

// Accepted ambiguities: still flagged, deliberately. These shapes are
// structurally identical to impersonation (brand as a full domain, or
// a hyphen token), so no lexical rule can clear them without also
// clearing real phishing shapes. pnb.com.ph is an abbreviation
// collision (Philippine National Bank vs Punjab National Bank).
const ambiguous = [
  ['https://www.telegram.dog', 'telegram'],
  ['https://www.pnb.com.ph', 'pnb'],
  ['https://apple-history.com', 'apple'],
  ['https://appletozucchini.com.au', 'apple'],
];
ambiguous.forEach(function (pair) {
  const r = analyzeUrl(pair[0]);
  check('ambiguity still flagged (documented): ' + pair[0],
    hasBrand(r.reasons) && (brandOf(r.reasons) || '').indexOf('"' + pair[1] + '"') !== -1, r);
});

// Message mode: a legit Airtel promo no longer picks up a brand
// reason from its official link, while a real KYC phish still does.
// (Message mode prefixes link reasons with "In the link: ", so match
// on substring, not on label start.)
const promo = analyze('Get 2GB data on Airtel Thanks App, download now i.airtel.in/2gb_rc2');
check('Airtel promo message has no brand reason',
  !promo.reasons.some(function (r) { return r.label.indexOf('Brand name') !== -1; }), promo.reasons);
const phish = analyze('SBI: Update your KYC to keep your account active: http://sbi-kyc-update.xyz/verify');
check('KYC phish message still gets a brand reason',
  phish.reasons.some(function (r) { return r.label.indexOf('Brand name') !== -1; }), phish.reasons);

// Link extraction: bare multi-label domains must survive intact.
// The old pattern truncated "i.airtel.in/2gb_rc2" to "i.airtel", so
// message-mode checks ran on a wrong host.
const { extractUrls } = require('../analyzer.js');
check('extractUrls keeps all labels (subdomain bare link)',
  JSON.stringify(extractUrls('download now i.airtel.in/2gb_rc2')) === '["https://i.airtel.in/2gb_rc2"]',
  extractUrls('download now i.airtel.in/2gb_rc2'));
check('extractUrls keeps www bare link intact',
  JSON.stringify(extractUrls('Visit www.example.com for details')) === '["https://www.example.com"]',
  extractUrls('Visit www.example.com for details'));
check('extractUrls keeps bare official domain intact',
  JSON.stringify(extractUrls('Check sbi.co.in now')) === '["https://sbi.co.in"]',
  extractUrls('Check sbi.co.in now'));
check('extractUrls still ignores email addresses',
  JSON.stringify(extractUrls('mail me at a@b.com please')) === '[]',
  extractUrls('mail me at a@b.com please'));

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
