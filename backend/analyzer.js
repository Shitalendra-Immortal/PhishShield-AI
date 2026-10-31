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
    'telegram.org': 'Telegram', 'irctc.co.in': 'IRCTC', 'flipkart.com': 'Flipkart'
  };

  // Brand names scammers impersonate. If the host contains one but is NOT the
  // official domain, that is impersonation. Leetspeak is normalised first
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
    var bare = text.match(/(?:^|[\s(])([a-z0-9-]+\.[a-z]{2,}(?:\/[^\s<>")]+)?)/gi) || [];
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
    var plain = deleet(hostNoWww);
    var impersonated = null;
    BRANDS.forEach(function (b) {
      if (!impersonated && plain.indexOf(b) !== -1) impersonated = b;
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
    if (/(account (blocked|suspended|closed|frozen)|will be blocked|suspended)/.test(lower)) {
      hit(10, 'Threat: account blocked or suspended',
        'A threat of losing access is the most common phishing lever.');
    }
    if (/(won|winner|prize|lottery|cashback|reward|congratulations)/.test(lower)) {
      hit(25, 'Prize / reward bait',
        'Unexpected prizes are bait to get a click or a fee.');
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
    if (/(kyc|know your customer)/.test(lower) &&
        /(update|complete|verify|pending|incomplete|expire)/.test(lower)) {
      hit(20, 'KYC update trick',
        'Fake KYC messages are the top UPI-era scam in India.');
    }
    if (/(bank|sbi|hdfc|icici|paytm|phonepe|upi)/.test(lower) &&
        /(blocked|verify|update|link|reactivate|expired|deactivated)/.test(lower)) {
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
    // Punjabi (Gurmukhi script + Roman Punjabi), mirroring the English
    // checks. Gurmukhi words are script-distinct, so they take the full
    // English point values; Roman urgency words take +10 like the
    // Hinglish urgency block. Shahmukhi (Urdu script) is NOT covered yet.
    if (/(ਤੁਰੰਤ|ਹੁਣੇ|ਜਲਦੀ|ਛੇਤੀ)/.test(lower)) {
      hit(15, 'Punjabi urgency words',
        'Punjabi pressure words (turant, hune, jaldi, chheti) rush you the same way English urgency does.');
    }
    if (/(ਖਾਤਾ ਬੰਦ|ਬੰਦ ਹੋ ਜਾਵੇਗਾ|ਬਲਾਕ ਹੋ ਜਾਵੇਗਾ|ਅਕਾਊਂਟ ਬੰਦ)/.test(lower)) {
      hit(10, 'Punjabi account-block threat',
        'A closure threat written in Punjabi, the same lever as the English version.');
    }
    if (/(ਇਨਾਮ|ਜਿੱਤਿਆ|ਜਿੱਤੀ|ਲਾਟਰੀ|ਕੈਸ਼ਬੈਕ|ਵਧਾਈ)/.test(lower)) {
      hit(25, 'Punjabi prize bait',
        'An unexpected prize in Punjabi is the same bait as in English.');
    }
    if (/((ਓਟੀਪੀ|ਪਿੰਨ|ਪਾਸਵਰਡ)[^.।]{0,25}(ਸਾਂਝਾ|ਭੇਜੋ|ਦੱਸੋ|ਦਿਓ|ਪਾਓ)|(ਸਾਂਝਾ|ਭੇਜੋ|ਦੱਸੋ|ਦਿਓ|ਪਾਓ)[^.।]{0,25}(ਓਟੀਪੀ|ਪਿੰਨ|ਪਾਸਵਰਡ))/.test(lower)) {
      hit(30, 'Punjabi OTP request',
        'Asking for an OTP, PIN or password in Punjabi is the same red flag as in English.');
    }
    if (/(ਕੇਵਾਈਸੀ|KYC)[^.।]{0,25}(ਅਪਡੇਟ|ਪੂਰਾ|ਪੂਰੀ|ਵੈਰੀਫਾਈ|ਬਕਾਇਆ|ਅਧੂਰਾ|ਅਧੂਰੀ|ਖਤਮ)/.test(lower)) {
      hit(20, 'Punjabi KYC trick',
        'A KYC update push written in Punjabi, the top UPI-era scam pattern.');
    }
    if (/(ਬੈਂਕ|sbi|hdfc|icici|paytm|phonepe|upi)[^.।]{0,40}(ਬੰਦ|ਵੈਰੀਫਾਈ|ਅਪਡੇਟ|ਲਿੰਕ|ਖਤਮ|ਬਲਾਕ)/.test(lower)) {
      hit(10, 'Punjabi financial brand + action',
        'A trusted money brand plus a Punjabi action you are pushed to take.');
    }
    if (/(ਬਿਜਲੀ)[^.।]{0,40}(ਕੱਟ|ਬਕਾਇਆ)/.test(lower)) {
      hit(20, 'Punjabi electricity scam pattern',
        'A fake power-cut warning written in Punjabi.');
    }
    // Roman Punjabi (SMS-style, as with Hinglish). "KYC update karo" is
    // already caught by the English KYC check, so no Roman KYC rule here
    // — adding one would count the same trick twice.
    if (/\b(hun|hune|chheti|fauran)\b/.test(lower)) {
      hit(10, 'Roman Punjabi urgency words',
        'Roman Punjabi pressure words (hun, chheti) rush you the same way English urgency does.');
    }
    if (/((otp|pin|cvv|password)[^.]{0,25}(dasso|bhejo|deyo|paao)|(dasso|bhejo|deyo|paao)[^.]{0,25}(otp|pin|cvv|password))/.test(lower)) {
      hit(30, 'Roman Punjabi OTP request',
        'Asking for an OTP, PIN or password in Roman Punjabi is the same red flag as in English.');
    }
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
    if (/(खाता बंद|बंद हो जाएगा|बंद हो जायेगा|ब्लॉक हो जाएगा|अकाउंट बंद|खाता ब्लॉक)/.test(lower)) {
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
    if (/(केवाईसी[^.।!?]{0,25}(अपडेट|पूरा|पूरी|वेरिफाई|बकाया|अधूरा|अधूरी|खत्म|update|verify|pending|incomplete|expire|complete)|kyc[^.।!?]{0,25}(अपडेट|पूरा|पूरी|वेरिफाई|बकाया|अधूरा|अधूरी|खत्म))/.test(lower)) {
      hit(20, 'Hindi KYC trick',
        'A KYC update push written in Hindi, the top UPI-era scam pattern.');
    }
    if (/(बैंक|sbi|hdfc|icici|paytm|phonepe|upi)[^.।!?]{0,40}(बंद|वेरिफाई|अपडेट|लिंक|खत्म|ब्लॉक|निलंबित)/.test(lower)) {
      hit(10, 'Hindi financial brand + action',
        'A trusted money brand plus a Hindi action you are pushed to take.');
    }
    if (/(बिजली)[^.।!?]{0,40}(कट|बकाया|डिस्कनेक्ट)/.test(lower)) {
      hit(20, 'Hindi electricity scam pattern',
        'A fake power-cut warning written in Hindi.');
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
    if (/(registration fee|processing fee|delivery fee|advance fee)/.test(lower)) {
      hit(20, 'Upfront fee request',
        'Real jobs, loans and deliveries do not demand a fee up front to release money or a parcel.');
    }
    if (/(guaranteed profit|double your money|double.*money.*days|100% profit)/.test(lower)) {
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
