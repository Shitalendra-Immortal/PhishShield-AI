// Punjabi OTP-request fixes: Gurmukhi mixed-script credentials +
// per-match negation guard, and Roman "share" verb + guard.
// The double-count cases are the point: neither fix may inflate a
// score English already covers.
// Run: node tests/punjabi-otp.test.js
'use strict';
const PhishShield = require('../analyzer.js');

let passed = 0, failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
}
function scoreOf(text) { return PhishShield.analyze(text); }
function hasLabel(r, label) { return r.reasons.some(function (x) { return x.label === label; }); }

// --- Gurmukhi ---
let r = scoreOf('ਤੁਹਾਡਾ ਮੋਬਾਈਲ ਨੰਬਰ 2 ਘੰਟਿਆਂ ਵਿੱਚ ਬੰਦ ਹੋ ਜਾਵੇਗਾ। ਨੰਬਰ ਚਾਲੂ ਰੱਖਣ ਲਈ ਤੁਰੰਤ ਆਪਣੀ ਜਾਣਕਾਰੀ ਅਤੇ OTP ਸਾਂਝਾ ਕਰੋ।');
check('reported message 25 -> 55 suspicious with OTP rule',
  r.score === 55 && r.verdict.level === 'suspicious' && hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਤੁਰੰਤ ਆਪਣਾ OTP ਸਾਂਝਾ ਕਰੋ।');
check('mixed request alone: urgency 15 + OTP 30 = 45',
  r.score === 45 && hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਆਪਣਾ ਓਟੀਪੀ ਦੱਸੋ।');
check('pure Gurmukhi request still 30',
  r.score === 30 && hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਕਿਰਪਾ ਕਰਕੇ ਆਪਣਾ ਓਟੀਪੀ ਕਿਸੇ ਨਾਲ ਸਾਂਝਾ ਨਾ ਕਰੋ।');
check('Gurmukhi warning (share na karo) 30 -> 0',
  r.score === 0 && !hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਓਟੀਪੀ ਨਾ ਦੱਸੋ, ਇਹ ਸਿਰਫ਼ ਤੁਹਾਡੇ ਲਈ ਹੈ।');
check('Gurmukhi warning (na dasso) 30 -> 0',
  r.score === 0 && !hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਆਪਣਾ OTP ਸਾਂਝਾ ਨਾ ਕਰੋ।');
check('mixed warning (Latin OTP + guard) 0, not newly flagged',
  r.score === 0 && !hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਓਟੀਪੀ ਨਾ ਦੱਸੋ, ਓਟੀਪੀ ਭੇਜੋ।');
check('warned-then-real pair still fires 30',
  r.score === 30 && hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('ਓਟੀਪੀ ਭੇਜੋ, ਓਟੀਪੀ ਨਾ ਦੱਸੋ।');
check('real-then-warned pair still fires 30',
  r.score === 30 && hasLabel(r, 'Punjabi OTP request'), r);
r = scoreOf('Please share your OTP to verify.');
check('pure English request counted once: 30, not 60',
  r.score === 30, r);
r = scoreOf('Do not share your OTP with anyone.');
check('English warning stays 0',
  r.score === 0, r);

// --- Roman ---
r = scoreOf('Apna OTP share karo, number chalu rakhna hai.');
check('Roman share request 0 -> 30',
  r.score === 30 && hasLabel(r, 'Roman Punjabi OTP request'), r);
r = scoreOf('OTP share na karo, eh sirf tuhade layi hai.');
check('Roman warning (share na karo) stays 0',
  r.score === 0 && !hasLabel(r, 'Roman Punjabi OTP request'), r);
r = scoreOf('OTP na dasso, OTP dasso.');
check('Roman warned-then-real pair fires 30',
  r.score === 30 && hasLabel(r, 'Roman Punjabi OTP request'), r);
r = scoreOf("Don't share your OTP with anyone.");
check('Roman guard covers do-not-share apostrophe form: 0',
  r.score === 0, r);
r = scoreOf('Apna OTP dasso.');
check('existing Roman verb still 30',
  r.score === 30 && hasLabel(r, 'Roman Punjabi OTP request'), r);
r = scoreOf('Do not share your OTP with anyone, share it with us.');
check('referral trick counted once: 30, not 60',
  r.score === 30, r);
r = scoreOf('Apna share karo OTP.');
check('verb-first share with markers counted once: 30, not 60',
  r.score === 30, r);
r = scoreOf('OTP share karo.');
check('credential-first Roman share counted once: 30',
  r.score === 30 && hasLabel(r, 'Roman Punjabi OTP request'), r);

console.log('\n' + passed + ' passed, ' + failed + ' failed.');
process.exit(failed ? 1 : 0);
