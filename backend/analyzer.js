// PhishShield AI — heuristic phishing analysis engine.
// Pure functions, no DOM, no network, no API key. Works in browser and Node.
// Scoring: every triggered check adds points. 0-29 Safe, 30-59 Suspicious, 60+ Likely Phishing.
// A check is only a signal, never proof — the UI says so too.
(function (root) {
  'use strict';

  // Domains whose exact host (or subdomain) is genuinely that brand.
  var OFFICIAL_DOMAINS = {
    'google.com': 'Google', 'youtube.com': 'YouTube', 'amazon.in': 'Amazon India',
    'amazon.com': 'Amazon', 'facebook.com': 'Facebook', 'instagram.com': 'Instagram',
    'apple.com': 'Apple', 'microsoft.com': 'Microsoft', 'netflix.com': 'Netflix',
    'paypal.com': 'PayPal', 'sbi.co.in': 'SBI', 'hdfcbank.com': 'HDFC Bank',
    'onlinesbi.com': 'SBI', 'npci.org.in': 'NPCI', 'uidai.gov.in': 'UIDAI',
    'icicibank.com': 'ICICI Bank', 'axisbank.com': 'Axis Bank', 'kotak.com': 'Kotak',
    'paytm.com': 'Paytm', 'phonepe.com': 'PhonePe', 'whatsapp.com': 'WhatsApp',
    'telegram.org': 'Telegram', 'irctc.co.in': 'IRCTC', 'flipkart.com': 'Flipkart',
    'airtel.in': 'Airtel', 'airtelxstream.in': 'Airtel Xstream',
    'jio.com': 'Jio', 'amazonaws.cn': 'Amazon'
  };

  // Brand names scammers impersonate. If a host token IS one, or
  // STARTS with one, but the host is NOT the official domain, that
  // is impersonation. Leetspeak is normalised first
  // (paypa1 -> paypal) so simple typosquats are caught too.
  var BRANDS = ['paypal', 'google', 'amazon', 'facebook', 'instagram', 'apple',
    'microsoft', 'netflix', 'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm',
    'phonepe', 'gpay', 'whatsapp', 'telegram', 'irctc', 'flipkart', 'upi',
    'pnb', 'baroda', 'canara', 'unionbank', 'idfc', 'indusind', 'yesbank',
    'jio', 'airtel', 'aadhaar', 'epfo'];

  // Display-name brands for the sender-mismatch check: brand key -> official domains.
  var SENDER_BRANDS = {
    'paypal': ['paypal.com'], 'sbi': ['sbi.co.in', 'onlinesbi.com'],
    'hdfc': ['hdfcbank.com'], 'icici': ['icicibank.com'],
    'axis': ['axisbank.com'], 'kotak': ['kotak.com'],
    'paytm': ['paytm.com'], 'phonepe': ['phonepe.com'],
    'google': ['google.com'], 'amazon': ['amazon.in', 'amazon.com'],
    'apple': ['apple.com'], 'microsoft': ['microsoft.com'],
    'netflix': ['netflix.com'], 'facebook': ['facebook.com'],
    'instagram': ['instagram.com'], 'irctc': ['irctc.co.in'],
    'flipkart': ['flipkart.com']
  };

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'cutt.ly', 'shorte.st', 'rebrand.ly',
    'tiny.cc', 'bit.do', 'rb.gy', 't.ly', 'shorturl.at'];

  var SUSPICIOUS_TLDS = ['tk', 'xyz', 'top', 'buzz', 'click', 'link', 'gq',
    'ml', 'cf', 'work', 'live', 'fun', 'icu', 'shop', 'online', 'site',
    'store', 'ru'];

  var URL_SUSPICIOUS_WORDS = ['verify', 'login', 'secure', 'update', 'confirm',
    'account', 'banking', 'signin', 'password', 'wallet', 'kyc',
    'aadhaar', 'recharge', 'electricity', 'lottery'];

  function hostOf(url) {
    try {
      var u = url.match(/^https?:\/\//i) ? url : 'https://' + url;
      var h = new URL(u).hostname.toLowerCase();
      // Normalise before any check runs on it: a trailing dot and a
      // percent-encoded host are the same domain, and must not dodge
      // official-domain or brand matching.
      h = h.replace(/\.+$/, '');
      try { h = decodeURIComponent(h); } catch (e) { /* keep raw host */ }
      return h;
    } catch (e) { return ''; }
  }

  function deleet(s) {
    return s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/5/g, 's').replace(/3/g, 'e');
  }

  function officialBrand(host) {
    var parts = host.split('.');
    for (var i = 0; i < parts.length - 1; i++) {
      var candidate = parts.slice(i).join('.');
      if (OFFICIAL_DOMAINS[candidate]) return OFFICIAL_DOMAINS[candidate];
    }
    return null;
  }

  function extractUrls(text) {
    var m = text.match(/https?:\/\/[^\s<>")]+/gi) || [];
    // Bare domains: capture ALL labels, not just two. The old pattern
    // ([a-z0-9-]+\.[a-z]{2,}) truncated "i.airtel.in/2gb_rc2" to
    // "i.airtel", so message-mode checks ran on a wrong host — the
    // brand check then fired on "airtel" even though the real host is
    // an official domain. This truncation also hit every bare
    // subdomain link ("www.example.com" became "www.example").
    var bare = text.match(/(?:^|[\s(])([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:\/[^\s<>")]+)?)/gi) || [];
    bare.forEach(function (b) {
      var t = b.trim().replace(/^\(/, '');
      if (t.indexOf('http') !== 0 && t.indexOf('.') > 0) m.push('https://' + t);
    });
    // De-duplicate, keep order.
    var seen = {}, out = [];
    m.forEach(function (u) {
      var clean = u.replace(/[.,;!?]+$/, '');
      if (!seen[clean]) { seen[clean] = true; out.push(clean); }
    });
    return out;
  }

  function isShortenerHost(host) {
    return SHORTENERS.indexOf(host.replace(/^www\./, '')) !== -1;
  }

  // URL-only checks. Returns { score, reasons: [{label, detail, points}] }.
  function analyzeUrl(rawUrl) {
    var reasons = [];
    var score = 0;
    function hit(points, label, detail) {
      score += points;
      reasons.push({ label: label, detail: detail, points: points });
    }

    var url = rawUrl.trim();
    var host = hostOf(url);
    if (!host) return { score: 0, reasons: [], host: '', note: 'No valid URL found.' };

    var brand = officialBrand(host);
    if (brand) {
      return { score: 0, reasons: [], host: host, note: 'Official domain of ' + brand + '.' };
    }

    var lower = url.toLowerCase();
    var hostNoWww = host.replace(/^www\./, '');

    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      hit(35, 'IP address instead of a domain name',
        'Real companies link to their domain, not a raw IP like ' + host + '.');
    }
    if (url.indexOf('@') !== -1) {
      // An @ URL hides the real host entirely, so it reaches the
      // suspicious band on its own (20 + an 8-point weak word = 28,
      // safe, was a miss).
      hit(30, '@ symbol in the URL',
        'Everything before @ is ignored by browsers, so the real destination is hidden.');
    }
    if (SHORTENERS.indexOf(hostNoWww) !== -1) {
      hit(20, 'Link shortener hides the destination',
        'Shortened links conceal where they really go — a classic phishing trick.');
    }
    var subCount = hostNoWww.split('.').length - 2;
    if (subCount > 2) {
      hit(10, 'Unusually many subdomains (' + (subCount + 2) + ' parts)',
        'Extra subdomains are used to make a fake address look official.');
    }
    var tld = hostNoWww.split('.').pop();
    // Weak signals: a suspicious TLD or a pressure word on its own is
    // not enough to flag a URL. Either one only scores when something
    // else already fired, or when both are present together (two
    // independent weak signals corroborate each other). A legitimate
    // login page or a harmless .xyz site no longer scores on one word
    // alone. The URLhaus check in URL mode still catches listed domains
    // regardless of this engine score.
    var weakTld = null;
    if (SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
      weakTld = { points: 15, label: 'Suspicious top-level domain (.' + tld + ')',
        detail: 'This ending is cheap, lightly policed, and heavily abused by scam sites.' };
    }
    if (host.indexOf('xn--') !== -1) {
      hit(25, 'Punycode (xn--) in the domain',
        'Lets attackers register lookalike letters that look identical to real brands.');
    }
    if (url.length > 75) {
      hit(5, 'Very long URL (' + url.length + ' characters)',
        'Length is used to bury the suspicious part of the address.');
    }
    var hyphens = (hostNoWww.match(/-/g) || []).length;
    if (hyphens >= 2) {
      hit(10, 'Hyphen-stuffed domain (' + hyphens + ' hyphens)',
        'Real brand domains rarely stack hyphens like this; fakes do.');
    }
    // Brand matching is token-based, not substring. Split the
    // (leetspeak-normalised) host into dot labels, then hyphen tokens,
    // and fire only when a brand IS a token or STARTS a token. Plain
    // substring matching fired inside unrelated words ("upi" in
    // "stupid", "cupinfo", "ubuntupit"; "sbi" in "massbio",
    // "ridethisbike"; "apple" in "thebigapplegirl") — the combined
    // evaluation's biggest false-positive source, measured on the
    // PhiUSIIL sample before this change. Glued prefixes
    // ("paypallogin", "sbiupdate") still fire: that is a real
    // phishing shape. Accepted ambiguity in the other direction: a
    // token starting with a brand ("appletozucchini") still fires,
    // because it is structurally identical to a phishing shape.
    var plain = deleet(hostNoWww);
    var hostTokens = [];
    plain.split('.').forEach(function (label) {
      label.split('-').forEach(function (tok) { if (tok) hostTokens.push(tok); });
    });
    var impersonated = null;
    BRANDS.forEach(function (b) {
      if (impersonated) return;
      hostTokens.forEach(function (tok) {
        if (!impersonated && tok.indexOf(b) === 0) impersonated = b;
      });
    });
    if (impersonated) {
      hit(30, 'Brand name "' + impersonated + '" in an unofficial domain',
        'The address borrows a trusted brand name but is not that brand\'s site.');
    }
    // Plain http only: the first test excludes https, so the second
    // test must match http exactly (the old https? form was equivalent
    // but read as if it could match https too).
    if (!/^https:\/\//i.test(url) && /^http:\/\//i.test(url)) {
      hit(10, 'No HTTPS encryption',
        'Login and payment pages without HTTPS expose anything you type.');
    }
    // WHATWG URL already drops default ports (:443 on https, :80 on http)
    // from .port, so only a real non-default port scores here.
    var port = '';
    try { port = new URL(url.match(/^https?:\/\//i) ? url : 'https://' + url).port; } catch (e) { port = ''; }
    if (port) {
      hit(10, 'Unusual port number in the URL',
        'Legitimate public sites almost never put a port in their address.');
    }
    var foundWord = null;
    URL_SUSPICIOUS_WORDS.forEach(function (w) {
      if (!foundWord && lower.indexOf(w) !== -1) foundWord = w;
    });
    var weakWord = null;
    if (foundWord) {
      weakWord = { points: 8, label: 'Pressure word in the URL: "' + foundWord + '"',
        detail: 'Scam links love words like verify, secure and update to feel urgent.' };
    }
    // Corroboration rule (see the TLD block above): weak signals count
    // only alongside another signal, or together with each other.
    if (reasons.length > 0 || (weakTld && weakWord)) {
      if (weakTld) hit(weakTld.points, weakTld.label, weakTld.detail);
      if (weakWord) hit(weakWord.points, weakWord.label, weakWord.detail);
    }
    return { score: score, reasons: reasons, host: host, note: null };
  }

  // Message-text checks (SMS / email / chat). URLs inside are also scanned.
  function analyzeMessage(text) {
    var reasons = [];
    var score = 0;
    function hit(points, label, detail) {
      score += points;
      reasons.push({ label: label, detail: detail, points: points });
    }

    var lower = text.toLowerCase();

    if (/(urgent|immediately|within 24 hours|act now|last chance|right now|hurry)/.test(lower)) {
      hit(15, 'Urgency pressure',
        'Scammers rush you so you act before you think.');
    }
    // Merged from v6: will-be-deactivated / locked / stop-working variants.
    if (/(account (blocked|suspended|closed|frozen|deactivated)|will be (blocked|suspended|closed|frozen|deactivated|locked)|will stop working|suspended)/.test(lower)) {
      hit(10, 'Threat: account blocked or suspended',
        'A threat of losing access is the most common phishing lever.');
    }
    if (/(won|winner|prize|lottery|cashback|reward|congratulations)/.test(lower)) {
      hit(25, 'Prize / reward bait',
        'Unexpected prizes are bait to get a click or a fee.');
    }
    // Merged from v6: prize claim push, checked independently of the
    // prize word (prize and claim are often in different sentences).
    if (/(won|winner|prize|lottery|jackpot)/.test(lower) &&
        /(claim your|claim the|contact support|click here to (claim|receive)|whatsapp[^.]{0,30}details)/.test(lower)) {
      hit(10, 'Prize claim push',
        'A won-prize message pushing you to claim or contact support is a lure, not a win.');
    }
    // Merged from v6: enter a code/password on a website.
    if (/enter[^.]{0,40}(code|otp|pin|password)[^.]{0,40}(website|link|site|page)/.test(lower)) {
      hit(20, 'Enter code / password on a website',
        'Real services never ask you to enter a code on a linked website to keep an account active.');
    }
    // Fake-testimonial reward lure: "Mujhe laga tha fake hai par sach
    // me Rs 2000 mil gaye, tum log bhi try karo!" + a link. A
    // first-person money-received claim plus an urge for others to
    // try it, with a link to follow, is the referral-scam shape: the
    // "proof" is the bait and the link is the trap. The link is
    // required on purpose — a bank alert ("Rs 10,000 credited") has
    // no urge and no link, and a bare claim with no link could be a
    // genuine friend's referral, so neither fires.
    var testimonialReward = /(mujhe|mujhko|maine|i)\b[^.]{0,50}(mil gaya|mil gaye|mila|received|got)\b[^.]{0,30}(₹|rs\.?|rupees|\$|inr)/.test(lower) ||
      /(₹|rs\.?|rupees|\$|inr)\s?[\d,]+[^.]{0,30}(mil gaya|mil gaye|mila)/.test(lower);
    var referralUrge = /(tum log bhi|tum bhi|aap bhi|try karo|try it|you (guys|all) (try|too)|bhi try|share (this|it) with|forward (this|it) to)/.test(lower);
    if (testimonialReward && referralUrge && extractUrls(text).length > 0) {
      hit(30, 'Fake testimonial reward lure',
        'An "I got the money, you try too" story plus a link is how referral scams spread — real payouts do not arrive through random links.');
    }
    // Legit-OTP negation: the old test matched "share ... OTP" even in
    // "Do not share this OTP", turning a legit OTP notice into
    // 30/suspicious. Each proximity match is now checked: if the verb
    // is preceded (within ~12 chars) by "do not", "never", "don't" or
    // "not" (allowing an intensifier, "do not ever share"), that match
    // is a warning, not a request, and is skipped. The window is lazy
    // on purpose: a greedy window would swallow a second pair ("Do
    // not share your OTP, share your PIN") and let the negation inside
    // it block the real request. Plus a narrow
    // fallback for the trick "do not share your OTP with anyone, share
    // it with us" — the second share has no OTP in the same sentence,
    // but refers back to it, so a non-negated "share it with us" + an
    // OTP anywhere in the message also fires.
    (function () {
      var negBefore = /(do not|never|don'?t|do n'?t|not)\s+(ever\s+)?$/;
      var re = /(share|send|tell|provide|enter)[^.]{0,25}?(otp|pin|cvv|password)/g;
      var m, fired = false;
      while ((m = re.exec(lower)) !== null) {
        var before = lower.slice(Math.max(0, m.index - 12), m.index);
        if (negBefore.test(before)) continue;
        // Merged from v6: "Never click unknown link or share your OTP"
        // is a warning, not a request. The 12-char guard above misses it
        // because "never" is before "click", not before "share". Check
        // the segment before this match, without crossing a comma:
        // never/do-not ... or <verb> at the end means this verb is negated.
        // "Do not share X, share Y" still fires on Y, because the comma
        // breaks the segment before Y.
        var segStart = Math.max(lower.lastIndexOf('.', m.index), lower.lastIndexOf('!', m.index), lower.lastIndexOf('?', m.index), lower.lastIndexOf('\n', m.index)) + 1;
        var segBefore = lower.slice(segStart, m.index);
        if (/(never|do not|don't|not)\b[^,]{0,80}\bor\s*$/.test(segBefore)) continue;
        fired = true;
        break;
      }
      if (!fired && /(otp|pin|cvv|password)/.test(lower) &&
          /\bshare (it|this|that) with (us|me|them|him|her)\b/.test(lower)) {
        // Only fire if that "share with us" is itself non-negated.
        var s = lower.match(/\bshare (it|this|that) with (us|me|them|him|her)\b/);
        var sb = lower.slice(Math.max(0, s.index - 12), s.index);
        if (!negBefore.test(sb)) fired = true;
      }
      if (fired) {
        hit(30, 'Asks you to share an OTP, PIN or password',
          'No real bank or company ever asks for these. This alone is a red flag.');
      }
    })();
    // ID-document request: Aadhaar / PAN / bank / card details asked
    // for over a message, in either order, Roman Hindi included
    // ("Aadhaar share karo" matches: the tokens are Latin). Same
    // philosophy as the OTP rule: one strong signal reaches the
    // suspicious band. "tell" is deliberately NOT a verb here —
    // "tell me about Aadhaar" is a discussion, not a handover — and a
    // match whose filler contains "about" is skipped for the same
    // reason. Negated warnings ("Never share your Aadhaar") are
    // skipped, mirroring the OTP guard.
    (function () {
      var negBefore = /(do not|never|don'?t|do n'?t|not)\s+(ever\s+)?$/;
      var nouns = '(aadhaar|aadhar|pan card|pan number|pan details|bank details|account details|card details|passport|voter id|driving licen[cs]e)';
      var verbs = '(share|send|provide|submit|enter|give)';
      var re = new RegExp('(' + verbs + ')[^.]{0,30}?(' + nouns + ')|(' + nouns + ')[^.]{0,30}?(' + verbs + ')', 'g');
      var m, fired = false;
      while ((m = re.exec(lower)) !== null) {
        var before = lower.slice(Math.max(0, m.index - 12), m.index);
        if (negBefore.test(before)) continue;
        // Merged from v6: "Never click unknown link or share your Bank
        // details" is a warning, not a request. The 12-char guard misses
        // it because "never" is before "click", not before "share".
        var segStart = Math.max(lower.lastIndexOf('.', m.index), lower.lastIndexOf('!', m.index), lower.lastIndexOf('?', m.index), lower.lastIndexOf('\n', m.index)) + 1;
        var segBefore = lower.slice(segStart, m.index);
        if (/(never|do not|don't|not)\b[^,]{0,80}\bor\s*$/.test(segBefore)) continue;
        if (/\babout\b/.test(m[0])) continue;
        if (new RegExp(verbs + '\\s+(not|never)\\b').test(m[0])) continue;
        var after = lower.slice(m.index + m[0].length, m.index + m[0].length + 10);
        if (/^\s*(not|never)\b/.test(after)) continue;
        fired = true;
        break;
      }
      if (fired) {
        hit(30, 'Asks you to share ID documents',
          'No real bank or company asks for Aadhaar, PAN or bank details over a message. This alone is a red flag.');
      }
    })();
    // Merged from v6: share account number, with negation guard.
    // Skipped if the ID-documents rule already fired (bank details /
    // account details), to avoid double-counting the same handover.
    // "Never ... share your Bank details" is a warning, not a request.
    (function () {
      if (reasons.some(function (r) { return r.label === 'Asks you to share ID documents'; })) return;
      var fired = lower.split(/[.!?\n]+/).some(function (sent) {
        var pair = /((share|send|provide|give)[^.]{0,40}(account number|bank details|bank account|account details)|(account number|bank details|bank account|account details)[^.]{0,40}(share|send|provide|give))/.test(sent);
        if (!pair) return false;
        if (/(never|do not|don't|not)\s+(click|share|send|provide|give)/.test(sent)) return false;
        if (/never[^.]{0,60}share/.test(sent)) return false;
        return true;
      });
      if (fired) hit(30, 'Asks you to share account / bank details',
        'No real prize, job or bank asks you to share account details to receive money.');
    })();
    // KYC completion guard: "update is complete" is a receipt, not a
    // push. Without it, a routine completion notice ("Your KYC update
    // is complete") scored 30/suspicious. Pushes say "complete" (do
    // your KYC); receipts say "completed" / "is complete" — the guard
    // only matches receipt phrasing, so pushes still fire.
    if (/(kyc|know your customer)/.test(lower) &&
        /(update|complete|verify|pending|incomplete|expire)/.test(lower) &&
        !/(is complete|completed|successfully updated|updated successfully)/.test(lower)) {
      hit(20, 'KYC update trick',
        'Fake KYC messages are the top UPI-era scam in India.');
    }
    // "We will update you on the status" is a notification, not a
    // push: strip "update you/us/me" before testing, so a status
    // update no longer trips the brand + action rule. "Update your
    // KYC" (update + your) still fires.
    var lowerNoUpdateYou = lower.replace(/update\s+(you|us|me)\b/g, '');
    if (/(bank|sbi|hdfc|icici|paytm|phonepe|upi)/.test(lowerNoUpdateYou) &&
        /(blocked|verify|update|link|reactivate|expired|deactivated)/.test(lowerNoUpdateYou)) {
      hit(10, 'Financial brand + alarming action',
        'Combines a trusted money brand with an action you are pushed to take.');
    }
    if (/\b(turant|jaldi|abhi|foran)\b/.test(lower)) {
      hit(10, 'Hinglish urgency words',
        'Roman-Hindi pressure words (turant, abhi, jaldi) are common in Indian scam SMS.');
    }
    if (/(band ho jayeg[ai]|block ho jayeg[ai]|account band)/.test(lower)) {
      hit(10, 'Hinglish account-block threat',
        'A closure threat written in Roman Hindi, the same lever as the English version.');
    }
    // Merged from v6 (adapted): Roman Hindi OTP request. Verbs are
    // send/tell/batao/bata only — "share" is owned by the Roman Punjabi
    // rule below and "bhejo" by its dasso-family verbs, so no pair is
    // ever counted twice. Skipped when the English OTP rule already
    // fired (verb-first pairs are English's). Negation guards mirror
    // v6: English negations before the verb plus na/mat/kabhi.
    (function () {
      if (reasons.some(function (r) { return r.label === 'Asks you to share an OTP, PIN or password'; })) return;
      var verbs = '(send|tell|batao|bata)';
      var toks = '(otp|pin|cvv|password)';
      var re = new RegExp('(' + toks + '[^.]{0,25}?' + verbs + '|' + verbs + '[^.]{0,25}?' + toks + ')', 'g');
      var fired = lower.split(/[.!?\n]+/).some(function (sent) {
        var m, f = false;
        re.lastIndex = 0;
        while ((m = re.exec(sent)) !== null) {
          var _before = sent.slice(0, m.index);
          if (/(do not|never|don'?t|not)(\s+ever)?\s*$/.test(_before)) continue;
          if (new RegExp('(na|mat|kabhi)\\s+' + verbs).test(m[0])) continue;
          if (new RegExp(verbs + '\\s+(na|mat)(\\s|$)').test(m[0])) continue;
          var after = sent.slice(m.index + m[0].length, m.index + m[0].length + 12);
          if (/^\s*(na|mat)(\s|$)/.test(after)) continue;
          f = true; break;
        }
        return f;
      });
      if (fired) hit(30, 'Roman Hindi OTP request',
        'Asking for an OTP, PIN or password in Roman Hindi is the same red flag as in English.');
    })();
    // Punjabi (Gurmukhi script + Roman Punjabi), mirroring the English
    // checks. Gurmukhi words are script-distinct, so they take the full
    // English point values; Roman urgency words take +10 like the
    // Hinglish urgency block. Shahmukhi (Urdu script) is NOT covered yet.
    if (/(ਤੁਰੰਤ|ਹੁਣੇ|ਜਲਦੀ|ਛੇਤੀ)/.test(lower)) {
      hit(15, 'Punjabi urgency words',
        'Punjabi pressure words (turant, hune, jaldi, chheti) rush you the same way English urgency does.');
    }
    if (/(ਖਾਤਾ ਬੰਦ|ਬੰਦ ਹੋ ਜਾਵੇਗਾ|ਬਲਾਕ ਹੋ ਜਾਵੇਗਾ|ਅਕਾਊਂਟ ਬੰਦ|ਬੰਦ ਹੋ ਸਕਦਾ ਹੈ|ਬਲਾਕ ਹੋ ਸਕਦਾ ਹੈ|ਬੰਦ ਕਰ ਦਿੱਤਾ ਜਾਵੇਗਾ|ਬਲਾਕ ਕਰ ਦਿੱਤਾ ਜਾਵੇਗਾ|ਬੰਦ ਹੋ ਸਕਦਾ|ਬਲਾਕ ਹੋ ਸਕਦਾ)/.test(lower)) {
      hit(10, 'Punjabi account-block threat',
        'A closure threat written in Punjabi, the same lever as the English version.');
    }
    if (/(ਇਨਾਮ|ਜਿੱਤਿਆ|ਜਿੱਤੀ|ਲਾਟਰੀ|ਕੈਸ਼ਬੈਕ|ਵਧਾਈ)/.test(lower)) {
      hit(25, 'Punjabi prize bait',
        'An unexpected prize in Punjabi is the same bait as in English.');
    }
    // Punjabi (Gurmukhi) OTP request, checked per match like the Hindi
    // rule: Latin credentials pair with Gurmukhi verbs ("OTP ਸਾਂਝਾ
    // ਕਰੋ" — the mixed-script shape real messages use), but a pair
    // with no Gurmukhi character is plain English, already covered by
    // the English rule, so it is excluded here and never
    // double-counted. A negated pair ("ਓਟੀਪੀ ਨਾ ਦੱਸੋ",
    // "OTP ਸਾਂਝਾ ਨਾ ਕਰੋ") is a warning and is skipped, but a real
    // pair in the same sentence still fires. Windows are lazy on
    // purpose, so a greedy window cannot swallow a second pair.
    var punjabiCredVerbs = '(ਸਾਂਝਾ|ਭੇਜੋ|ਦੱਸੋ|ਦਿਓ|ਪਾਓ)';
    var punjabiCredPairG = /((ਓਟੀਪੀ|otp|ਪਿੰਨ|pin|ਪਾਸਵਰਡ|password|ਸੀਵੀਵੀ|cvv)[^.।!?]{0,30}?(ਸਾਂਝਾ|ਭੇਜੋ|ਦੱਸੋ|ਦਿਓ|ਪਾਓ)|(ਸਾਂਝਾ|ਭੇਜੋ|ਦੱਸੋ|ਦਿਓ|ਪਾਓ)[^.।!?]{0,30}?(ਓਟੀਪੀ|otp|ਪਿੰਨ|pin|ਪਾਸਵਰਡ|password|ਸੀਵੀਵੀ|cvv))/g;
    var punjabiOtpHit = lower.split(/[।.!?\n]+/).some(function (s) {
      var m, fired = false;
      punjabiCredPairG.lastIndex = 0;
      while ((m = punjabiCredPairG.exec(s)) !== null) {
        if (!/[\u0A00-\u0A7F]/.test(m[0])) continue;
        // Negation before the verb inside the match ("ਓਟੀਪੀ ਨਾ ਦੱਸੋ").
        if (new RegExp('(ਨਾ|ਮਤ)\\s+' + punjabiCredVerbs).test(m[0])) continue;
        // Negation after the verb inside the match ("ਸਾਂਝਾ ਨਾ ਕਰੋ" in one span).
        if (new RegExp(punjabiCredVerbs + '\\s+(ਨਹੀਂ|ਨਾ|ਮਤ)(\\s|$)').test(m[0])) continue;
        // Negation immediately before a verb-first match ("ਨਾ ਦੱਸੋ ਆਪਣਾ ਓਟੀਪੀ").
        if (new RegExp('^' + punjabiCredVerbs).test(m[0])) {
          var before = s.slice(Math.max(0, m.index - 4), m.index);
          if (/(ਨਾ|ਮਤ)\s*$/.test(before)) continue;
        }
        // Negation immediately after the match ("OTP ਸਾਂਝਾ" + " ਨਾ ਕਰੋ").
        var after = s.slice(m.index + m[0].length, m.index + m[0].length + 12);
        if (/^\s*(ਨਹੀਂ|ਨਾ|ਮਤ)(\s|$)/.test(after)) continue;
        fired = true;
        break;
      }
      return fired;
    });
    if (punjabiOtpHit) {
      hit(30, 'Punjabi OTP request',
        'Asking for an OTP, PIN or password in Punjabi is the same red flag as in English.');
    }
    if (/(ਕੇਵਾਈਸੀ|kyc)[^.।]{0,25}(ਅਪਡੇਟ|ਪੂਰਾ|ਪੂਰੀ|ਵੈਰੀਫਾਈ|ਬਕਾਇਆ|ਅਧੂਰਾ|ਅਧੂਰੀ|ਖਤਮ)/.test(lower) &&
        !/(ਪੂਰਾ|ਪੂਰੀ)\s+(ਹੋ ਗਈ|ਹੋ ਗਿਆ)/.test(lower)) {
      hit(20, 'Punjabi KYC trick',
        'A KYC update push written in Punjabi, the top UPI-era scam pattern.');
    }
    // Merged from v6: click-link push in Punjabi.
    if (/(ਲਿੰਕ 'ਤੇ ਕਲਿੱਕ|ਲਿੰਕ ਤੇ ਕਲਿੱਕ|ਇਸ ਲਿੰਕ 'ਤੇ ਕਲਿੱਕ)/.test(lower)) {
      hit(10, 'Click-link instruction (Punjabi)',
        'Telling you to click a link in a bank/KYC message is the phishing push itself.');
    }
    if (/(ਬੈਂਕ|sbi|hdfc|icici|paytm|phonepe|upi)[^.।]{0,40}(ਬੰਦ|ਵੈਰੀਫਾਈ|ਅਪਡੇਟ|ਲਿੰਕ|ਖਤਮ|ਬਲਾਕ)/.test(lower)) {
      hit(10, 'Punjabi financial brand + action',
        'A trusted money brand plus a Punjabi action you are pushed to take.');
    }
    if (/(ਬਿਜਲੀ)[^.।]{0,40}(ਕੱਟ|ਬਕਾਇਆ)/.test(lower)) {
      hit(20, 'Punjabi electricity scam pattern',
        'A fake power-cut warning written in Punjabi.');
    }
    // Merged from v6 (guarded): Punjabi digital arrest. The +30 is
    // skipped when the English rule already fired on the same
    // ਡਿਜੀਟਲ ਅਰੈਸਟ claim — v6 fires both for the same arrest (+30 +30).
    // The +20 payment is guarded independently: it fires when the
    // payment words are Punjabi and the English payment rule did not
    // fire, so a Punjabi arrest + payment still reaches 30 + 20.
    if (/(ਡਿਜੀਟਲ ਅਰੈਸਟ)/.test(lower) &&
        !reasons.some(function (r) { return r.label === 'Digital arrest scam'; })) {
      hit(30, 'Punjabi digital arrest scam',
        'No police, CBI or ED officer arrests you over a video call or demands money to avoid arrest.');
    }
    if (/(ਡਿਜੀਟਲ ਅਰੈਸਟ)/.test(lower) &&
        /(ਭੁਗਤਾਨ|ਜਮ੍ਹਾ|ਟ੍ਰਾਂਸਫਰ|ਪੈਸੇ)/.test(lower) &&
        !reasons.some(function (r) { return r.label === 'Payment demanded under arrest threat'; })) {
      hit(20, 'Payment demanded under arrest threat (Punjabi)',
        'Demanding payment to avoid arrest is the digital-arrest lever.');
    }
    // Merged from v6: Punjabi upfront fee and work-from-home bait.
    if (/(ਰਜਿਸਟ੍ਰੇਸ਼ਨ|ਪ੍ਰੋਸੈਸਿੰਗ|ਡਿਲੀਵਰੀ|ਐਡਵਾਂਸ)[^.।]{0,20}(ਫੀਸ|ਫੀ)|(ਫੀਸ|ਫੀ)[^.।]{0,20}(ਜਮ੍ਹਾ|ਦਿਓ|ਭੁਗਤਾਨ)/.test(lower)) {
      hit(20, 'Upfront fee request (Punjabi)',
        'Real jobs, loans and deliveries do not demand a fee up front to release money or a parcel.');
    }
    if (/(ਘਰ ਬੈਠੇ)[^.।]{0,40}(ਕਮਾਓ|ਕਮਾਈ|ਰੋਜ਼|ਰੋਜ਼ਾਨਾ)/.test(lower)) {
      hit(20, 'Work-from-home earning bait (Punjabi)',
        'Daily earning from home with no experience, plus a fee, is the classic job scam.');
    }
    // Roman Punjabi (SMS-style, as with Hinglish). "KYC update karo" is
    // already caught by the English KYC check, so no Roman KYC rule here
    // — adding one would count the same trick twice.
    if (/\b(hun|hune|chheti|fauran)\b/.test(lower)) {
      hit(10, 'Roman Punjabi urgency words',
        'Roman Punjabi pressure words (hun, chheti) rush you the same way English urgency does.');
    }
    // Roman Punjabi OTP request, checked per match: "share" joins the
    // verbs ("OTP share karo" is the commonest Roman phrasing and was
    // missed entirely — the English rule is verb-first only). A
    // negated pair ("OTP share na karo", "do not share your OTP")
    // is a warning and is skipped, but a real pair in the same
    // sentence still fires. The English negations are in the guard
    // on purpose: adding "share" without them would newly flag
    // "do not share your OTP" through this rule.
    (function () {
      var romanPairG = /((otp|pin|cvv|password)[^.]{0,30}?(dasso|bhejo|deyo|paao|share)|(dasso|bhejo|deyo|paao|share)[^.]{0,30}?(otp|pin|cvv|password))/g;
      var fired = false;
      lower.split(/[.!?\n]+/).forEach(function (s) {
        if (fired) return;
        var m;
        romanPairG.lastIndex = 0;
        while ((m = romanPairG.exec(s)) !== null) {
          // Negation before the verb inside the match ("OTP na dasso").
          if (/((do not|never|don'?t|not|na|mat|nahi)\s+(dasso|bhejo|deyo|paao|share))/.test(m[0])) continue;
          // Negation after the verb inside the match ("share na karo" in one span).
          if (/((dasso|bhejo|deyo|paao|share)\s+(na|mat|nahi|not)(\s|$))/.test(m[0])) continue;
          // Negation immediately before a verb-first match ("na dasso apna OTP").
          if (/^(dasso|bhejo|deyo|paao|share)/.test(m[0])) {
            var before = s.slice(Math.max(0, m.index - 12), m.index);
            if (/((do not|never|don'?t|not|na|mat|nahi)\s*)$/.test(before)) continue;
          }
          // Negation immediately after the match ("OTP share" + " na karo").
          var after = s.slice(m.index + m[0].length, m.index + m[0].length + 12);
          if (/^\s*(na|mat|nahi|not)(\s|$)/.test(after)) continue;
          // "share" is shared with English: a verb-first "share"
          // pair is English's, and a credential-first one counts
          // only in a sentence carrying a Roman Punjabi word —
          // otherwise pure-English pairs and the English referral
          // fallback ("share it with us") would be counted twice.
          // m[3] is the branch-1 verb, m[4] the branch-2 verb.
          var pairVerb = m[3] || m[4];
          if (pairVerb === 'share') {
            if (m[4] !== undefined) continue;
            if (!/\b(apna|tuhada|tuhade|tusi|karo|kar|kise|naal|layi|chalu|rakhna|hai|da|di|ji|deo|karke)\b/.test(s)) continue;
          }
          fired = true;
          break;
        }
      });
      if (fired) {
        hit(30, 'Roman Punjabi OTP request',
          'Asking for an OTP, PIN or password in Roman Punjabi is the same red flag as in English.');
      }
    })();
    if (/\b(inam|jiteya|jitya|vadhai)\b/.test(lower)) {
      hit(25, 'Roman Punjabi prize bait',
        'An unexpected prize in Roman Punjabi is the same bait as in English.');
    }
    // Hindi (Devanagari script), mirroring the English checks the way
    // the Punjabi block does. Devanagari words are script-distinct, so
    // they take the full English point values. Hindi is SOV, so a
    // credential usually precedes its verb ("ओटीपी साझा करें"), but
    // mixed Hindi-English messages use either order, so the credential
    // rule matches both orders and accepts Latin tokens on either side
    // ("अपना OTP साझा करें"). A pair with no Devanagari character at
    // all is plain English, already covered by the English rule, so it
    // is excluded here and never double-counted. A do-not-share
    // warning ("साझा न करें", "OTP मत बताएं") is NOT a request: the
    // negation, before or after the verb, blocks that match, checked
    // per match so a mixed warning-plus-request message still scores
    // on its request.
    if (/(तुरंत|अभी|जल्दी|फौरन|तत्काल)/.test(lower)) {
      hit(15, 'Hindi urgency words',
        'Hindi pressure words (turant, abhi, jaldi) rush you the same way English urgency does.');
    }
    // Merged from v6: ब्लॉक/बंद कर दिया जाएगा, हो सकता है variants.
    if (/(खाता बंद|बंद हो जाएगा|बंद हो जायेगा|ब्लॉक हो जाएगा|अकाउंट बंद|खाता ब्लॉक|ब्लॉक कर दिया जाएगा|बंद कर दिया जाएगा|ब्लॉक हो सकता है|बंद हो सकता है|ब्लॉक कर दिया|बंद कर दिया)/.test(lower)) {
      hit(10, 'Hindi account-block threat',
        'A closure threat written in Hindi, the same lever as the English version.');
    }
    if (/(बधाई|लॉटरी|इनाम|पुरस्कार|कैशबैक|जीती|जीता|जीते)/.test(lower)) {
      hit(25, 'Hindi prize bait',
        'An unexpected prize in Hindi is the same bait as in English.');
    }
    // Hindi OTP / bank-info request, checked per match: a negated pair
    // ("OTP मत बताएं", "OTP साझा न करें") is a warning and is
    // skipped, but a real pair in the same sentence still fires.
    // The windows are lazy on purpose: a greedy window would swallow
    // a second pair ("OTP मत बताएं, OTP भेजो") and let the negation
    // inside it block the real request.
    // "डालें" (enter) joins the verbs, matching the English rule's
    // "enter". A pair with no Devanagari character is plain English,
    // already covered by the English rule, so it is excluded here and
    // never double-counted.
    var hindiCredVerbs = '(साझा|भेजें|भेजो|बताएं|बताओ|दें|दो|डालें)';
    var hindiCredPairG = /((ओटीपी|otp|पिन|pin|पासवर्ड|password|सीवीवी|cvv|बैंक जानकारी|bank details|bank info|खाता विवरण|account details)[^.।!?]{0,30}?(साझा|भेजें|भेजो|बताएं|बताओ|दें|दो|डालें|share|send|tell)|(साझा|भेजें|भेजो|बताएं|बताओ|दें|दो|डालें|share|send|tell)[^.।!?]{0,30}?(ओटीपी|otp|पिन|pin|पासवर्ड|password|सीवीवी|cvv|बैंक जानकारी|bank details|bank info|खाता विवरण|account details))/g;
    var hindiOtpHit = lower.split(/[।.!?\n]+/).some(function (s) {
      var m, fired = false;
      hindiCredPairG.lastIndex = 0;
      while ((m = hindiCredPairG.exec(s)) !== null) {
        if (!/[\u0900-\u097F]/.test(m[0])) continue;
        // Negation before the verb inside the match ("OTP मत बताएं").
        if (new RegExp('(मत|न)\\s+' + hindiCredVerbs).test(m[0])) continue;
        // Negation after the verb inside the match ("साझा न करें" in one span).
        if (new RegExp(hindiCredVerbs + '\\s+(नहीं|न|मत|ना)(\\s|$)').test(m[0])) continue;
        // Negation immediately before a verb-first match ("मत बताएं अपना OTP").
        if (new RegExp('^' + hindiCredVerbs).test(m[0])) {
          var before = s.slice(Math.max(0, m.index - 4), m.index);
          if (/(मत|न)\s*$/.test(before)) continue;
        }
        // Negation immediately after the match ("OTP साझा" + " न करें").
        var after = s.slice(m.index + m[0].length, m.index + m[0].length + 12);
        if (/^\s*(नहीं|न|मत|ना)(\s|$)/.test(after)) continue;
        fired = true;
        break;
      }
      return fired;
    });
    if (hindiOtpHit) {
      hit(30, 'Hindi OTP / bank-info request',
        'Asking for an OTP, PIN, password or bank details in Hindi is the same red flag as in English.');
    }
    // Cross-script pairs only, plus pure Devanagari: same-script pairs
    // are already caught once by the English check (Latin KYC + Latin
    // action) or by this rule's Devanagari arm, so this never counts
    // one KYC trick twice. "KYC update karo" stays exactly 20.
    if (/(केवाईसी[^.।!?]{0,25}(अपडेट|पूरा|पूरी|वेरिफाई|बकाया|अधूरा|अधूरी|खत्म|update|verify|pending|incomplete|expire|complete)|kyc[^.।!?]{0,25}(अपडेट|पूरा|पूरी|वेरिफाई|बकाया|अधूरा|अधूरी|खत्म))/.test(lower) &&
        !/(पूरी|पूरा|अपडेट)\s+(हो गई|हो गया)/.test(lower)) {
      hit(20, 'Hindi KYC trick',
        'A KYC update push written in Hindi, the top UPI-era scam pattern.');
    }
    // Merged from v6: click-link push in Hindi.
    if (/(लिंक पर क्लिक|लिंक पे क्लिक|नीचे दिए गए लिंक)/.test(lower)) {
      hit(10, 'Click-link instruction (Hindi)',
        'Telling you to click a link in a bank/KYC message is the phishing push itself.');
    }
    if (/(बैंक|sbi|hdfc|icici|paytm|phonepe|upi)[^.।!?]{0,40}(बंद|वेरिफाई|अपडेट|लिंक|खत्म|ब्लॉक|निलंबित)/.test(lower)) {
      hit(10, 'Hindi financial brand + action',
        'A trusted money brand plus a Hindi action you are pushed to take.');
    }
    if (/(बिजली)[^.।!?]{0,40}(क[ा]?ट|बकाया|डिस्कनेक्ट)/.test(lower)) {
      hit(20, 'Hindi electricity scam pattern',
        'A fake power-cut warning written in Hindi.');
    }
    // Merged from v6: Hindi fee / guaranteed-profit / govt-scheme /
    // work-from-home bait.
    if (/(रजिस्ट्रेशन|प्रोसेसिंग|डिलीवरी|एडवांस|पंजीकरण)[^.।!?]{0,20}(फीस|शुल्क)|(फीस|शुल्क)[^.।!?]{0,20}(जमा|दें|भुगतान|देनी)/.test(lower)) {
      hit(20, 'Upfront fee request (Hindi)',
        'Real jobs, loans and deliveries do not demand a fee up front to release money or a parcel.');
    }
    if (/(गारंटीड|गारंटी)[^.।!?]{0,20}(मुनाफा|लाभ)|(दोगुना|डबल)[^.।!?]{0,20}(पैसा|मुनाफा)|(100%|सौ प्रतिशत)[^.।!?]{0,20}(मुनाफा|लाभ)/.test(lower)) {
      hit(30, 'Guaranteed-profit investment bait (Hindi)',
        'No real investment guarantees profit or doubles money in days.');
    }
    if (/(सरकारी योजना)[^.।!?]{0,40}(मिलेंगे|पाएं|लाभ|आवेदन|राशि)/.test(lower)) {
      hit(15, 'Government scheme lure (Hindi)',
        'A government-scheme promise plus an apply/claim push is a common Indian scam pattern.');
    }
    if (/(घर बैठे)[^.।!?]{0,40}(कमाएं|कमाओ|कमा|रोज़|रोज)/.test(lower)) {
      hit(20, 'Work-from-home earning bait (Hindi)',
        'Daily earning from home with no experience, plus a fee, is the classic job scam.');
    }
    // Scam types that previously scored 0-35: digital arrest, fake
    // police threats, upfront fees, guaranteed-profit investment bait,
    // and blackmail / sextortion.
    if (/(digital arrest|डिजिटल अरेस्ट)/.test(lower)) {
      hit(30, 'Digital arrest scam',
        'No police, CBI or ED officer arrests you over a video call or demands money to avoid arrest.');
      if (/(pay|transfer|send money|bitcoin|video call)/.test(lower)) {
        hit(20, 'Payment demanded under arrest threat',
          'Demanding payment to avoid arrest is the digital-arrest lever.');
      }
    } else if (/((cbi|police|enforcement directorate|\bed\b)[^.]{0,40}(arrest|video call|money laundering)|(arrest|video call|money laundering)[^.]{0,40}(cbi|police|enforcement directorate|\bed\b))/.test(lower)) {
      hit(25, 'Fake police / arrest threat',
        'A law-enforcement threat used to force an urgent payment.');
    }
    if (/(registration fee|processing fee|delivery fee|advance fee|customs fee|clearance fee)/.test(lower)) {
      hit(20, 'Upfront fee request',
        'Real jobs, loans and deliveries do not demand a fee up front to release money or a parcel.');
    }
    // Merged from v6: GST/tax/handling/service fee to release/claim.
    // Only fee types NOT already in the Upfront list, to avoid double count.
    if (/(gst fee|tax fee|handling fee|service fee)[^.]{0,40}(release|claim)/.test(lower)) {
      hit(20, 'Fee to release / claim winnings',
        'Real prizes never charge a fee to release them; a fee-to-claim is the scam itself.');
    }
    if (/(guaranteed profit|double your (money|bitcoin|btc|crypto)|double.*money.*days|100% profit)/.test(lower)) {
      // 30, not 25: a guaranteed-profit claim on its own reaches the
      // suspicious band, like an OTP request does.
      hit(30, 'Guaranteed-profit investment bait',
        'No real investment guarantees profit or doubles money in days.');
    }
    if (/((private video|personal video)[^.]{0,40}(share|leak|publish|send to)|(share|leak|publish|send to)[^.]{0,40}(private video|personal video))/.test(lower)) {
      hit(30, 'Blackmail / sextortion threat',
        'Threatening to share a private video unless you pay is blackmail, not a real debt.');
    }
    if (/(electricity|bijli|power)[^.]{0,40}(disconnect|cut off|bill[^.]{0,20}(pending|due|unpaid)|payment[^.]{0,20}(pending|due))/.test(lower)) {
      hit(20, 'Electricity disconnection scam pattern',
        'Fake power-cut warnings are a widespread Indian scam.');
    }
    if (/\bapk\b/.test(lower)) {
      hit(15, 'APK download lure',
        'Scam messages push fake bank apps as APK files; real banks never distribute apps this way.');
    }
    if (/(sbi|hdfc|icici|paytm|phonepe|upi|bank)/.test(lower) &&
        /(download|install)[^.]{0,20}app/.test(lower)) {
      hit(10, 'Fake bank app download lure',
        'A money brand plus an app download push is a classic fake-app scam.');
    }
    // Sender-name spoofing: "Brand Name <address@other-domain>".
    var senderMatch = text.match(/"?([A-Za-z][A-Za-z ]{1,40})"?\s*<[^>\s]+@([^>\s]+)>/);
    if (senderMatch) {
      var display = senderMatch[1].toLowerCase();
      var senderDomain = senderMatch[2].toLowerCase().replace(/>$/, '');
      var spoofed = null;
      Object.keys(SENDER_BRANDS).forEach(function (b) {
        if (!spoofed && display.indexOf(b) !== -1) {
          var official = SENDER_BRANDS[b].some(function (d) {
            return senderDomain === d || senderDomain.endsWith('.' + d);
          });
          if (!official) spoofed = b;
        }
      });
      if (spoofed) {
        hit(30, 'Sender name impersonation: "' + spoofed + '" but mail is from ' + senderDomain,
          'The display name borrows a trusted brand, but the address belongs to a different domain.');
      }
    }

    // Any URLs inside the message get the URL checks too (capped at 40).
    var urls = extractUrls(text);
    var urlReasons = [];
    var urlScore = 0;
    urls.slice(0, 3).forEach(function (u) {
      var r = analyzeUrl(u);
      if (r.score > urlScore) { urlScore = r.score; urlReasons = r.reasons; }
    });
    if (urlScore > 0) {
      var capped = Math.min(urlScore, 40);
      score += capped;
      urlReasons.forEach(function (r) {
        reasons.push({ label: 'In the link: ' + r.label, detail: r.detail, points: r.points });
      });
      if (urlScore > 40) {
        reasons.push({ label: 'Link risk capped at 40 points in message mode',
          detail: 'The link itself scored ' + urlScore + '; message mode counts at most 40 of it.', points: 0 });
      }
    }

    // Refund bait: an unexpected money-back lure ("refund pending",
    // "paise wapas") counts only when paired with a credential handover
    // or a suspicious link — a bare refund notice ("your refund has
    // been processed", "refund pending" with no action) is a routine
    // status and scores nothing on its own. Same +25 as the prize bait:
    // it lifts a refund + OTP message from 30 to 55 and a refund +
    // suspicious-link message from safe to suspicious, but it never
    // pushes an OTP case across a band on its own (a legit
    // enter-OTP-on-the-official-website flow already scores 30).
    var refundLure = /(refund|money[- ]back|\bwapas\b|रिफंड|ਰਿਫੰਡ)/.test(lower);
    var handoverFired = reasons.some(function (r) {
      return r.label === 'Asks you to share an OTP, PIN or password' ||
        r.label === 'Hindi OTP / bank-info request' ||
        r.label === 'Punjabi OTP request' ||
        r.label === 'Roman Punjabi OTP request' ||
        r.label === 'Roman Hindi OTP request' ||
        r.label === 'Asks you to share ID documents' ||
        r.label === 'Asks you to share account / bank details';
    });
    if (refundLure && (handoverFired || urlScore > 0)) {
      hit(25, 'Refund bait',
        'An unexpected refund plus a credential handover or a suspicious link is the refund-scam shape; real refunds never need your OTP.');
    }

    // NOTE: a "do not share" warning earns NO deduction. Scammers copy
    // reassuring phrases ("do not share your OTP with anyone...") to shave
    // points off their own message, so the phrase is not evidence either
    // way. Legitimate warnings already score low on their own merits.
    return { score: score, reasons: reasons, urls: urls };
  }

  function verdictFor(score) {
    if (score >= 60) return { level: 'phishing', label: 'Likely Phishing',
      advice: 'Do not click, do not reply, and never share an OTP, PIN or password. Delete it and, if it claims to be your bank, call the bank on its official number.' };
    if (score >= 30) return { level: 'suspicious', label: 'Suspicious',
      advice: 'Treat it as guilty until proven innocent: open the service yourself by typing its address (never via this link) and check there.' };
    return { level: 'safe', label: 'Looks Safe',
      advice: 'No phishing signals found. Stay alert anyway — if anything later asks for an OTP or payment, stop and re-check.' };
  }

  // Main entry: auto-detect URL vs message input.
  function analyze(input) {
    var text = (input || '').trim();
    if (!text) return { verdict: verdictFor(0), score: 0, reasons: [], kind: 'empty', note: 'Nothing to analyse yet.' };
    var looksLikeUrl = /^https?:\/\/\S+$/i.test(text) ||
      (/^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(text) && text.indexOf(' ') === -1);
    if (looksLikeUrl) {
      var u = analyzeUrl(text);
      return { verdict: verdictFor(u.score), score: Math.min(100, u.score),
        reasons: u.reasons, kind: 'url', host: u.host, note: u.note };
    }
    var m = analyzeMessage(text);
    return { verdict: verdictFor(m.score), score: Math.min(100, m.score),
      reasons: m.reasons, kind: 'message', urls: m.urls, note: null };
  }

  var api = { analyze: analyze, analyzeUrl: analyzeUrl, analyzeMessage: analyzeMessage,
    verdictFor: verdictFor, extractUrls: extractUrls, isShortener: isShortenerHost };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.PhishShield = api;
})(typeof window !== 'undefined' ? window : globalThis);
