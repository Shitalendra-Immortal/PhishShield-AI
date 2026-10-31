import type { Finding, FindingCategory, ScanType, Severity, Span, UrlVerdict } from "../types";
import { analyzeUrl, BRANDS } from "./urls";

export interface Rule {
  id: string;
  category: FindingCategory;
  title: string;
  detail: string;
  severity: Severity;
  /** Weight applied for the first match. */
  weight: number;
  /** Weight applied for each additional match (defaults to a third of `weight`). */
  repeatWeight?: number;
  /** Maximum number of matches that contribute to the score. */
  maxHits?: number;
  patterns: RegExp[];
  appliesTo?: ScanType[];
}

/* ------------------------------------------------------------------ *
 * Lexical rule set
 * ------------------------------------------------------------------ */

export const RULES: Rule[] = [
  {
    id: "urgency",
    category: "urgency",
    title: "Suspicious urgency",
    detail:
      "The message pushes you to act within a short deadline. Pressure is used to stop you from verifying the request.",
    severity: "medium",
    weight: 18,
    patterns: [
      /\b(urgent(?:ly)?|immediately|right away|as soon as possible|asap)\b/gi,
      /\bwithin (?:the next )?\d{1,3} (?:hours?|minutes?|days?)\b/gi,
      /\b(?:act|respond|reply|click|verify|confirm) (?:now|today|immediately)\b/gi,
      /\b(?:final|last|second) (?:notice|warning|reminder|chance|attempt)\b/gi,
      /\b(?:expires?|expiring|expired) (?:today|tonight|soon|in \d+|within)\b/gi,
      /\btime[- ]sensitive\b/gi,
      /\bdo not (?:delay|ignore|wait)\b/gi,
      /\bimmediate (?:action|attention|response|payment)\b/gi,
    ],
  },
  {
    id: "credentials",
    category: "credentials",
    title: "Credential harvesting",
    detail:
      "You are asked to supply login details or personal identifiers. Legitimate organisations never request these by message.",
    severity: "high",
    weight: 24,
    patterns: [
      /\b(?:verify|confirm|validate|update|re-?enter|re-?confirm|restore)\s+(?:your\s+)?(?:account|identity|password|login|credentials|details|information|payment|billing|card)\b/gi,
      /\b(?:log\s?in|sign\s?in)\s+(?:to|here|now|immediately|at|via|below)\b/gi,
      /\b(?:username|password|passcode|pin code|one[- ]time (?:code|password)|otp|security code|verification code|2fa code|mfa code)\b/gi,
      /\b(?:social security|ssn|national insurance number|card number|cvv|cvc|sort code|account number|routing number|seed phrase|recovery phrase|private key)\b/gi,
      /\b(?:enter|provide|submit|send|share)\s+(?:your\s+)?(?:details|credentials|password|card details|personal information)\b/gi,
      /\b(?:account|password) (?:recovery|reset) (?:link|request|code)\b/gi,
    ],
  },
  {
    id: "intimidation",
    category: "intimidation",
    title: "Threats and consequences",
    detail:
      "The sender warns of suspension, loss of access or legal trouble. Fear is used to force a fast reaction.",
    severity: "medium",
    weight: 17,
    patterns: [
      /\b(?:account|profile|access|card|service|subscription)\s+(?:will be|has been|is being|may be|could be)\s+(?:suspended|locked|closed|terminated|deactivated|restricted|blocked|disabled|limited)\b/gi,
      /\b(?:legal action|law enforcement|court order|lawsuit|prosecution|arrest warrant|penalty of|fine of)\b/gi,
      /\bunauthoris?z?ed (?:access|login|sign[- ]in|transaction|activity|attempt|charge)\b/gi,
      /\bsuspicious (?:activity|login|sign[- ]in|transaction|attempt)\b/gi,
      /\b(?:permanently|immediately) (?:delete|remove|close|suspend|disable)\b/gi,
      /\b(?:failure to (?:comply|respond|verify)|if you do not respond)\b/gi,
    ],
  },
  {
    id: "reward",
    category: "reward",
    title: "Unrealistic reward",
    detail:
      "An unexpected prize, refund or windfall is offered. This is a classic lure to start a conversation.",
    severity: "medium",
    weight: 15,
    patterns: [
      /\byou(?:'ve| have)?\s+(?:been\s+)?(?:won|win|selected|chosen|awarded)\b/gi,
      /\b(?:congratulations|congrats)\b/gi,
      /\b(?:lottery|jackpot|sweepstake|lucky winner|free gift|cash reward|inheritance|unclaimed funds|grant award)\b/gi,
      /\b(?:claim|collect|redeem) (?:your|the)\b/gi,
      /\b(?:tax refund|refund of|rebate of|compensation of)\b/gi,
      /\b(?:100%\s*free|risk[- ]free|no cost to you)\b/gi,
    ],
  },
  {
    id: "payment",
    category: "payment",
    title: "Unusual payment request",
    detail:
      "Payment is requested through channels that cannot be reversed or traced, or an invoice you did not expect is referenced.",
    severity: "high",
    weight: 18,
    patterns: [
      /\b(?:gift cards?|itunes cards?|google play cards?|steam cards?|prepaid cards?)\b/gi,
      /\b(?:bitcoin|btc|ethereum|usdt|crypto(?:currency)?|wallet address|binance pay)\b/gi,
      /\b(?:wire transfer|western union|moneygram|bank transfer|payment (?:is )?(?:due|required|pending|overdue)|outstanding (?:invoice|balance|payment)|unpaid (?:invoice|fee|bill|toll))\b/gi,
      /\b(?:pay|settle|clear|transfer)\s+(?:a|the|this)?\s*(?:small\s+)?(?:fee|balance|amount|charge|sum|invoice)\b/gi,
      /\b(?:customs|delivery|shipping|processing|redelivery) (?:fee|charge|cost)\b/gi,
    ],
  },
  {
    id: "greeting",
    category: "greeting",
    title: "Impersonal greeting",
    detail:
      "A generic salutation suggests a bulk send rather than a message from an organisation that knows you.",
    severity: "low",
    weight: 9,
    maxHits: 1,
    patterns: [
      /\bdear (?:customer|user|client|member|valued (?:customer|member)|account holder|sir or madam|sir\/madam|friend|beneficiary)\b/gi,
      /\b(?:hello|hi) dear\b/gi,
      /\battention:? (?:customer|user|account holder)\b/gi,
    ],
  },
  {
    id: "secrecy",
    category: "secrecy",
    title: "Pressure to move off-channel",
    detail:
      "You are asked to keep the exchange private or continue it somewhere unverifiable. This isolates you from people who could spot the scam.",
    severity: "medium",
    weight: 17,
    patterns: [
      /\b(?:do not (?:tell|share|inform|discuss)|keep this (?:confidential|between us|private|quiet)|don'?t tell anyone)\b/gi,
      /\b(?:text|whatsapp|telegram|message) me (?:on|at|back|directly)\b/gi,
      /\b(?:reply with your|send me your|share your)\b/gi,
      /\bi am (?:currently )?(?:in a meeting|unavailable|travelling)\b/gi,
    ],
  },
  {
    id: "callback",
    category: "secrecy",
    title: "Callback pressure",
    detail:
      "A phone number is pushed as the only way to resolve the issue, which leads to a live social-engineering call.",
    severity: "low",
    weight: 11,
    patterns: [
      /\bcall (?:us|me|this number|immediately|now|within)\b/gi,
      /\b(?:helpline|hotline|support line|toll[- ]free)\b/gi,
      /\b(?:\+\d{1,3}[\s-]?)?(?:\(?\d{3,5}\)?[\s-]?)\d{3}[\s-]?\d{3,4}\b/g,
    ],
  },
  {
    id: "attachment",
    category: "attachment",
    title: "Risky attachment reference",
    detail:
      "The message points you at an attachment or asks you to enable content, a common malware delivery route.",
    severity: "medium",
    weight: 15,
    patterns: [
      /\b(?:open|see|review|check|download) the attach(?:ed|ment)\b/gi,
      /\benable (?:macros|editing|content)\b/gi,
      /\.(?:exe|scr|zip|rar|iso|docm|xlsm|hta|apk)\b/gi,
      /\battached (?:invoice|document|receipt|statement|file|form|voicemail)\b/gi,
    ],
  },
  {
    id: "link-bait",
    category: "url",
    title: "Vague link prompt",
    detail:
      "The message hides its destination behind generic wording instead of naming where the link goes.",
    severity: "low",
    weight: 10,
    patterns: [
      /\b(?:click|tap|follow|use) (?:here|this link|the link below|below|the button)\b/gi,
      /\b(?:visit|go to) (?:the )?(?:link|site|portal) below\b/gi,
    ],
  },
];

/* ------------------------------------------------------------------ *
 * Rule execution
 * ------------------------------------------------------------------ */

function collectSpans(text: string, patterns: RegExp[]): Span[] {
  const spans: Span[] = [];
  for (const pattern of patterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
    for (const match of text.matchAll(re)) {
      const start = match.index ?? -1;
      if (start < 0 || !match[0].trim()) continue;
      spans.push({ start, end: start + match[0].length, text: match[0] });
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}

export function runLexicalRules(text: string, type: ScanType): Finding[] {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    if (rule.appliesTo && !rule.appliesTo.includes(type)) continue;
    const spans = collectSpans(text, rule.patterns);
    if (!spans.length) continue;

    const cap = rule.maxHits ?? 3;
    const hits = Math.min(spans.length, cap);
    const repeat = rule.repeatWeight ?? rule.weight / 3;
    const weight = rule.weight + (hits - 1) * repeat;

    findings.push({
      id: rule.id,
      category: rule.category,
      title: rule.title,
      detail: rule.detail,
      severity: rule.severity,
      weight,
      matches: spans.slice(0, 8),
      notes: [],
    });
  }
  return findings;
}

/* ------------------------------------------------------------------ *
 * Text manipulation heuristics
 * ------------------------------------------------------------------ */

const ZERO_WIDTH = /[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g;
const CYRILLIC_LOOKALIKE = /[\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u04bb\u0410\u0415\u041e\u0420\u0421]/g;

export function detectObfuscation(text: string): Finding | null {
  const notes: string[] = [];
  const matches: Span[] = [];
  let weight = 0;

  const zeroWidth = [...text.matchAll(ZERO_WIDTH)];
  if (zeroWidth.length) {
    weight += 24;
    notes.push(`${zeroWidth.length} invisible character(s) hidden inside the text.`);
  }

  const cyrillic = [...text.matchAll(CYRILLIC_LOOKALIKE)];
  if (cyrillic.length && /[a-z]/i.test(text)) {
    weight += 22;
    notes.push("Latin letters are mixed with look-alike Cyrillic characters.");
    for (const m of cyrillic.slice(0, 5)) {
      const start = m.index ?? 0;
      matches.push({ start, end: start + m[0].length, text: m[0] });
    }
  }

  const letters = text.replace(/[^a-z]/gi, "");
  const caps = text.replace(/[^A-Z]/g, "");
  if (letters.length > 40 && caps.length / letters.length > 0.45) {
    weight += 10;
    notes.push("Large portions of the text are written in capitals.");
  }

  const shouting = [...text.matchAll(/[!?]{2,}/g)];
  if (shouting.length >= 2) {
    weight += 6;
    notes.push("Repeated exclamation or question marks are used for emphasis.");
    for (const m of shouting.slice(0, 4)) {
      const start = m.index ?? 0;
      matches.push({ start, end: start + m[0].length, text: m[0] });
    }
  }

  if (!weight) return null;
  return {
    id: "obfuscation",
    category: "obfuscation",
    title: "Manipulated text",
    detail:
      "The content has been formatted to evade filters or to make a fake name look genuine.",
    severity: weight >= 20 ? "high" : "low",
    weight,
    matches,
    notes,
  };
}

/* ------------------------------------------------------------------ *
 * Email header analysis
 * ------------------------------------------------------------------ */

const FREE_MAIL = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "hotmail.com",
  "outlook.com",
  "live.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "mail.ru",
  "yandex.ru",
  "zoho.com",
  "inbox.lv",
]);

export interface EmailHeaders {
  displayName?: string;
  from?: string;
  fromDomain?: string;
  replyTo?: string;
  replyDomain?: string;
  returnPath?: string;
  subject?: string;
}

function headerValue(text: string, name: string): string | undefined {
  const re = new RegExp(`^[ \\t>]*${name}\\s*:\\s*(.+)$`, "im");
  return text.match(re)?.[1]?.trim();
}

function addressParts(value?: string): { display?: string; address?: string; domain?: string } {
  if (!value) return {};
  const angled = value.match(/^(.*?)<\s*([^>]+)\s*>$/);
  const display = angled?.[1]?.trim().replace(/^["']|["']$/g, "") || undefined;
  const address = (angled?.[2] ?? value).trim().replace(/^["']|["']$/g, "");
  const domain = address.includes("@") ? address.split("@").pop()?.toLowerCase() : undefined;
  return { display, address, domain };
}

export function parseEmailHeaders(text: string): EmailHeaders {
  const from = addressParts(headerValue(text, "from"));
  const reply = addressParts(headerValue(text, "reply-to"));
  const ret = addressParts(headerValue(text, "return-path"));
  return {
    displayName: from.display,
    from: from.address,
    fromDomain: from.domain,
    replyTo: reply.address,
    replyDomain: reply.domain,
    returnPath: ret.address,
    subject: headerValue(text, "subject"),
  };
}

export function analyzeSender(text: string, headers: EmailHeaders): Finding | null {
  const notes: string[] = [];
  let weight = 0;
  let severity: Severity = "low";

  const { fromDomain, replyDomain, displayName } = headers;

  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    weight += 26;
    severity = "high";
    notes.push(`Replies go to ${replyDomain}, not to the sending domain ${fromDomain}.`);
  }

  if (displayName && fromDomain) {
    const claimed = BRANDS.find((b) => displayName.toLowerCase().includes(b));
    if (claimed && !fromDomain.includes(claimed)) {
      weight += 28;
      severity = "high";
      notes.push(`The display name claims “${displayName}” but the mail comes from ${fromDomain}.`);
    }
  }

  if (fromDomain && FREE_MAIL.has(fromDomain)) {
    const brandMentioned = BRANDS.find((b) => new RegExp(`\\b${b}\\b`, "i").test(text));
    if (brandMentioned) {
      weight += 22;
      severity = "high";
      notes.push(
        `A free mailbox (${fromDomain}) is used while writing on behalf of ${brandMentioned}.`,
      );
    }
  }

  if (fromDomain) {
    const domainVerdict = analyzeUrl(fromDomain);
    const structural = domainVerdict.signals.filter((s) => s.weight >= 14);
    if (structural.length) {
      weight += Math.min(26, structural.reduce((t, s) => t + s.weight, 0) * 0.6);
      severity = "high";
      notes.push(...structural.map((s) => `${s.label}: ${s.detail}`));
    }
  }

  if (!weight) return null;

  return {
    id: "sender",
    category: "sender",
    title: "Sender does not add up",
    detail: "The sending identity is inconsistent with the organisation the email claims to be from.",
    severity,
    weight,
    matches: [],
    notes,
  };
}

/* ------------------------------------------------------------------ *
 * Brand impersonation (text + link cross-check)
 * ------------------------------------------------------------------ */

export function detectImpersonation(
  text: string,
  urls: UrlVerdict[],
  headers: EmailHeaders,
): Finding | null {
  const matches: Span[] = [];
  const mentioned: string[] = [];

  for (const brand of BRANDS) {
    const re = new RegExp(`\\b${brand}\\b`, "gi");
    for (const m of text.matchAll(re)) {
      const start = m.index ?? 0;
      matches.push({ start, end: start + m[0].length, text: m[0] });
      if (!mentioned.includes(brand)) mentioned.push(brand);
    }
  }
  if (!mentioned.length) return null;

  const notes: string[] = [];
  let weight = 7;
  let severity: Severity = "low";

  const mismatched = urls.filter(
    (u) => u.registrable && !mentioned.some((b) => u.registrable.includes(b)),
  );
  if (mismatched.length) {
    weight += 24;
    severity = "high";
    notes.push(
      `The message refers to ${mentioned[0]} but links to ${mismatched
        .slice(0, 2)
        .map((u) => u.registrable)
        .join(", ")}.`,
    );
  }

  if (headers.fromDomain && !mentioned.some((b) => headers.fromDomain!.includes(b))) {
    weight += 12;
    severity = "high";
    notes.push(`The email claims to represent ${mentioned[0]} but was sent from ${headers.fromDomain}.`);
  }

  const teamClaim = text.match(
    /\b(?:security|support|billing|account|service|fraud|customer care) (?:team|department|centre|center|services)\b/i,
  );
  if (teamClaim) {
    weight += 6;
    notes.push(`The sender presents itself as the “${teamClaim[0]}”.`);
  }

  if (!notes.length) {
    notes.push(`${mentioned.slice(0, 3).join(", ")} referenced without a matching verified link.`);
  }

  return {
    id: "impersonation",
    category: "impersonation",
    title: "Brand impersonation",
    detail: "A recognisable brand is invoked without any matching, verifiable destination.",
    severity,
    weight,
    matches: matches.slice(0, 8),
    notes,
  };
}
