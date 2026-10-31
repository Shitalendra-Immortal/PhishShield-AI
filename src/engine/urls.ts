import type { RiskLevel, UrlSignal, UrlVerdict } from "../types";

/* ------------------------------------------------------------------ *
 * Reference data
 * ------------------------------------------------------------------ */

/** Brands most frequently impersonated in phishing campaigns. */
export const BRANDS = [
  "paypal",
  "apple",
  "icloud",
  "microsoft",
  "office365",
  "outlook",
  "netflix",
  "amazon",
  "google",
  "gmail",
  "facebook",
  "instagram",
  "whatsapp",
  "linkedin",
  "dhl",
  "fedex",
  "ups",
  "usps",
  "dpd",
  "royalmail",
  "hmrc",
  "irs",
  "chase",
  "wellsfargo",
  "citibank",
  "barclays",
  "hsbc",
  "santander",
  "revolut",
  "monzo",
  "coinbase",
  "binance",
  "metamask",
  "blockchain",
  "steam",
  "adobe",
  "docusign",
  "dropbox",
  "booking",
  "airbnb",
  "spotify",
  "netflix",
  "bankofamerica",
];

/** Registrable domains we treat as legitimate when they appear verbatim. */
const TRUSTED_DOMAINS = new Set([
  "google.com",
  "youtube.com",
  "microsoft.com",
  "live.com",
  "office.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "paypal.com",
  "github.com",
  "gitlab.com",
  "stackoverflow.com",
  "wikipedia.org",
  "linkedin.com",
  "netflix.com",
  "spotify.com",
  "dropbox.com",
  "docusign.com",
  "adobe.com",
  "stripe.com",
  "cloudflare.com",
  "mozilla.org",
  "bbc.co.uk",
  "nytimes.com",
  "gov.uk",
]);

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rb.gy",
  "rebrand.ly",
  "shorturl.at",
  "tiny.cc",
  "s.id",
  "soo.gd",
  "clck.ru",
  "lnkd.in",
]);

/** TLDs with disproportionately high abuse rates. */
const RISKY_TLDS = new Set([
  "zip",
  "mov",
  "top",
  "xyz",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "work",
  "click",
  "link",
  "country",
  "support",
  "rest",
  "cam",
  "fit",
  "loan",
  "icu",
  "cyou",
  "sbs",
  "buzz",
  "monster",
  "quest",
  "ru",
  "su",
]);

const SENSITIVE_PATH_WORDS = [
  "login",
  "signin",
  "verify",
  "verification",
  "secure",
  "account",
  "update",
  "confirm",
  "webscr",
  "wallet",
  "recover",
  "unlock",
  "billing",
  "invoice",
  "password",
  "authenticate",
  "session",
];

const RISKY_FILE_EXT = /\.(exe|scr|apk|bat|cmd|jar|msi|vbs|iso|zip|rar|js|hta)(\?|$)/i;

const MULTI_PART_TLDS = new Set([
  "co.uk",
  "ac.uk",
  "gov.uk",
  "org.uk",
  "co.jp",
  "co.kr",
  "com.au",
  "net.au",
  "org.au",
  "com.br",
  "com.mx",
  "co.in",
  "co.za",
  "com.sg",
  "com.tr",
  "com.cn",
]);

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

export function registrableDomain(host: string): string {
  if (IPV4.test(host)) return host;
  const parts = host.toLowerCase().replace(/^www\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join(".");
  return lastTwo;
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length || !b.length) return Math.max(a.length, b.length);
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = cur;
  }
  return prev[b.length];
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Collapse common visual substitutions so "paypa1" ≈ "paypal". */
function deHomoglyph(value: string): string {
  return value
    .replace(/0/g, "o")
    .replace(/1|\||!/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/\$/g, "s")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w");
}

/* ------------------------------------------------------------------ *
 * Extraction
 * ------------------------------------------------------------------ */

const URL_PATTERN =
  /\b(?:(?:https?|ftp):\/\/|www\.)[^\s<>"'`]+|\b[a-z0-9][a-z0-9-]{1,}(?:\.[a-z0-9-]+)+(?:\/[^\s<>"'`]*)?/gi;

/** Pull every URL-looking token out of free text. */
export function extractUrls(text: string): string[] {
  const found = new Set<string>();
  const matches = text.match(URL_PATTERN) ?? [];
  for (const raw of matches) {
    const cleaned = raw.replace(/[.,;:!?)»\]]+$/g, "");
    if (!cleaned.includes(".")) continue;
    // Skip bare email addresses and version-looking tokens.
    if (/^\d+(\.\d+)+$/.test(cleaned)) continue;
    const hostPart = cleaned.replace(/^[a-z]+:\/\//i, "").split("/")[0];
    const tld = hostPart.split(".").pop() ?? "";
    if (!/^[a-z]{2,24}$/i.test(tld) && !IPV4.test(hostPart)) continue;
    found.add(cleaned);
  }
  return [...found];
}

export function parseHref(raw: string): URL | null {
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    return new URL(candidate);
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Classification
 * ------------------------------------------------------------------ */

export function urlLevel(score: number): RiskLevel {
  if (score >= 55) return "high";
  if (score >= 25) return "suspicious";
  return "low";
}

/**
 * Structural classification of a single URL.
 * Returns a weighted score plus the human-readable signals behind it.
 */
export function analyzeUrl(raw: string): UrlVerdict {
  const signals: UrlSignal[] = [];
  const add = (label: string, detail: string, weight: number) =>
    signals.push({ label, detail, weight });

  if (/^(javascript|data):/i.test(raw.trim())) {
    return {
      raw,
      href: raw,
      host: "",
      registrable: "",
      score: 92,
      level: "high",
      trusted: false,
      signals: [
        {
          label: "Executable scheme",
          detail: "The link uses a script or data scheme instead of a normal web address.",
          weight: 92,
        },
      ],
    };
  }

  const url = parseHref(raw);
  if (!url) {
    return {
      raw,
      href: raw,
      host: "",
      registrable: "",
      score: 30,
      level: "suspicious",
      trusted: false,
      signals: [
        { label: "Unparseable address", detail: "This link is malformed or obfuscated.", weight: 30 },
      ],
    };
  }

  const host = url.hostname.toLowerCase();
  const registrable = registrableDomain(host);
  const tld = host.split(".").pop() ?? "";
  const subdomains = host.replace(/^www\./, "").split(".").slice(0, -2);
  const path = `${url.pathname}${url.search}`.toLowerCase();
  const trusted = TRUSTED_DOMAINS.has(registrable);
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);

  if (url.username || url.password || /^[^/]*@/.test(raw.replace(/^[a-z]+:\/\//i, ""))) {
    add(
      "Embedded credentials",
      "Text before an “@” hides the real destination of the link.",
      32,
    );
  }

  if (IPV4.test(host)) {
    add("Raw IP address", "The link points at a numeric IP address rather than a domain.", 30);
  }

  if (host.includes("xn--")) {
    add(
      "Punycode domain",
      "The domain uses encoded international characters that can imitate familiar names.",
      30,
    );
  }

  if (SHORTENERS.has(registrable)) {
    add("Shortened link", "A link shortener hides the real destination until you open it.", 20);
  }

  if (RISKY_TLDS.has(tld)) {
    add(`High-abuse domain ending .${tld}`, "This extension is heavily used for throwaway phishing sites.", 16);
  }

  // Brand placed in a subdomain rather than the real domain.
  const brandInPrefix = BRANDS.find((b) => subdomains.some((s) => s.includes(b)));
  if (brandInPrefix && !registrable.startsWith(brandInPrefix)) {
    add(
      "Brand name outside the real domain",
      `“${brandInPrefix}” appears before the actual domain ${registrable}.`,
      28,
    );
  }

  // Typosquatting / homoglyph / composite-domain checks against the brand list.
  const rawLabel = registrable.split(".")[0];
  const label = deHomoglyph(rawLabel);
  const tokens = label.split(/[-_]/).filter(Boolean);
  if (!trusted) {
    for (const brand of BRANDS) {
      if (label === brand) {
        if (rawLabel !== brand) {
          add(
            "Character substitution in domain",
            `“${registrable}” replaces letters to read like “${brand}”.`,
            46,
          );
        }
        break;
      }
      if (tokens.length > 1 && tokens.includes(brand)) {
        add(
          "Brand name inside a composite domain",
          `“${registrable}” wraps the brand “${brand}” in a domain that brand does not own.`,
          28,
        );
        break;
      }
      const distance = levenshtein(label, brand);
      if (brand.length >= 5 && distance > 0 && distance <= (brand.length >= 8 ? 2 : 1)) {
        add(
          "Look-alike domain",
          `“${registrable}” closely imitates the legitimate brand “${brand}”.`,
          30,
        );
        break;
      }
    }
  }

  if (subdomains.length >= 3) {
    add("Deep subdomain chain", `${subdomains.length} subdomain levels are used to pad the address.`, 14);
  }

  const hyphens = (registrable.match(/-/g) ?? []).length;
  if (hyphens >= 2) {
    add("Hyphen-heavy domain", "Multiple hyphens are typical of disposable phishing domains.", 12);
  }

  if (/\d{3,}/.test(registrable.split(".")[0])) {
    add("Numeric domain padding", "Long digit sequences inside the domain name are unusual.", 10);
  }

  const sensitive = SENSITIVE_PATH_WORDS.filter((w) => path.includes(w));
  if (sensitive.length) {
    add(
      "Credential-themed path",
      `The address contains “${sensitive.slice(0, 3).join("”, “")}”, typical of fake sign-in pages.`,
      sensitive.length > 1 ? 16 : 12,
    );
  }

  if (RISKY_FILE_EXT.test(path)) {
    add("Executable download", "The link ends in a file type commonly used to deliver malware.", 26);
  }

  if (url.protocol === "http:" && hasScheme) {
    add("No encryption", "The link uses plain http, so anything you submit travels unprotected.", 12);
  }

  if (url.port && !["80", "443", ""].includes(url.port)) {
    add("Non-standard port", `Traffic is directed to port ${url.port} instead of the usual web port.`, 14);
  }

  if (raw.length > 95) {
    add("Unusually long address", "Excess length is often used to push the real domain out of view.", 8);
  }

  if ((raw.match(/%[0-9a-f]{2}/gi) ?? []).length >= 4) {
    add("Percent-encoded characters", "Parts of the address are encoded, obscuring what it really says.", 12);
  }

  if (/^\d+$/.test(host.replace(/\./g, "")) && !IPV4.test(host)) {
    add("Numeric host", "The host is entirely numeric.", 16);
  }

  let score = signals.reduce((total, s) => total + s.weight, 0);
  if (trusted) {
    score = Math.max(0, score - 45);
    if (!signals.length) {
      add("Recognised domain", `${registrable} is a well-known, legitimate destination.`, 0);
    }
  }
  score = Math.max(0, Math.min(100, Math.round(score)));

  return { raw, href: url.href, host, registrable, score, level: urlLevel(score), signals, trusted };
}
