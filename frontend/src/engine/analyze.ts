import type {
  Finding,
  Highlight,
  RiskLevel,
  ScanResult,
  ScanType,
  Sensitivity,
  Severity,
  UrlVerdict,
} from "../types";
import { analyzeUrl, extractUrls } from "./urls";
import {
  analyzeSender,
  detectImpersonation,
  detectObfuscation,
  parseEmailHeaders,
  runLexicalRules,
} from "./rules";

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 };

const THRESHOLDS: Record<Sensitivity, { high: number; suspicious: number }> = {
  balanced: { high: 68, suspicious: 35 },
  strict: { high: 55, suspicious: 24 },
};

/** Saturating normalisation so stacked signals converge towards 100 without ever hitting it. */
function normalise(raw: number): number {
  return Math.round(100 * (1 - Math.exp(-raw / 48)));
}

function mergeHighlights(findings: Finding[]): Highlight[] {
  const flat: Highlight[] = [];
  for (const f of findings) {
    for (const m of f.matches) {
      if (m.end <= m.start) continue;
      flat.push({
        start: m.start,
        end: m.end,
        category: f.category,
        severity: f.severity,
        label: f.title,
      });
    }
  }
  flat.sort((a, b) => a.start - b.start || b.end - a.end);

  const merged: Highlight[] = [];
  for (const h of flat) {
    const last = merged[merged.length - 1];
    if (last && h.start < last.end) {
      if (SEVERITY_RANK[h.severity] > SEVERITY_RANK[last.severity]) {
        last.severity = h.severity;
        last.label = h.label;
        last.category = h.category;
      }
      last.end = Math.max(last.end, h.end);
      continue;
    }
    merged.push({ ...h });
  }
  return merged;
}

function urlFinding(urls: UrlVerdict[]): Finding | null {
  const risky = urls.filter((u) => u.score > 0 && u.signals.some((s) => s.weight > 0));
  if (!risky.length) return null;

  const sorted = [...risky].sort((a, b) => b.score - a.score);
  const worst = sorted[0];
  const extra = sorted.slice(1).reduce((t, u) => t + u.score * 0.12, 0);
  const weight = Math.min(46, worst.score * 0.55 + extra);

  const notes = sorted
    .slice(0, 3)
    .flatMap((u) => u.signals.filter((s) => s.weight > 0).map((s) => `${u.registrable || u.raw} — ${s.detail}`))
    .slice(0, 6);

  return {
    id: "url-structure",
    category: "url",
    title: "Suspicious URL structure",
    detail: "At least one link is built to look familiar while pointing somewhere else.",
    severity: worst.score >= 55 ? "high" : worst.score >= 25 ? "medium" : "low",
    weight,
    matches: [],
    notes,
  };
}

function buildRecommendations(level: RiskLevel, findings: Finding[], urls: UrlVerdict[]): string[] {
  const has = (id: string) => findings.some((f) => f.id === id || f.category === id);
  const out: string[] = [];

  if (level === "high") {
    out.push("Do not reply, open links or download anything from this message.");
  } else if (level === "suspicious") {
    out.push("Pause before interacting. Treat this message as unverified until you confirm it.");
  } else {
    out.push("Nothing here matches known phishing patterns, but stay alert to unexpected requests.");
  }

  if (has("credentials")) {
    out.push(
      "Never enter passwords or one-time codes from a link. Open the official app or type the address yourself.",
    );
  }
  if (has("url") && urls.length) {
    out.push(
      `Check the destination before tapping. The link resolves to ${
        urls[0].registrable || "an unverified host"
      }, not necessarily the brand shown.`,
    );
  }
  if (has("impersonation") || has("sender")) {
    out.push(
      "Contact the organisation using a number or address you already trust — not the details in this message.",
    );
  }
  if (has("payment")) {
    out.push("Confirm any payment request by phone with a known contact before money moves.");
  }
  if (has("attachment")) {
    out.push("Leave the attachment unopened and never enable macros or editing to view content.");
  }
  if (has("urgency") || has("intimidation")) {
    out.push("Deadlines and threats are pressure tactics. Real providers allow you time to verify.");
  }
  if (has("reward")) {
    out.push("Legitimate prizes never require a fee, a code or your card details to release.");
  }
  if (level !== "low") {
    out.push("Report the message to your provider or security team, then delete and block the sender.");
  }

  return out.slice(0, 5);
}

function verdictFor(level: RiskLevel, type: ScanType): string {
  if (level === "high") return type === "url" ? "Malicious link indicators" : "Potential phishing detected";
  if (level === "suspicious") return "Suspicious signals found";
  return "No clear phishing signals";
}

function summaryFor(level: RiskLevel, findings: Finding[], urls: UrlVerdict[], type: ScanType): string {
  const n = findings.length;
  const linkPart = urls.length ? ` across ${urls.length} link${urls.length > 1 ? "s" : ""}` : "";
  if (!n) {
    return type === "url"
      ? "This address shows no structural indicators of a phishing site. Verify the destination is one you expected."
      : "No known phishing patterns were matched in this content. Treat unexpected requests with normal caution.";
  }
  if (level === "high") {
    return `${n} independent indicator${n > 1 ? "s" : ""}${linkPart} line up with phishing and social-engineering campaigns.`;
  }
  if (level === "suspicious") {
    return `${n} indicator${n > 1 ? "s" : ""}${linkPart} are consistent with phishing, but the evidence is not conclusive.`;
  }
  return `${n} minor indicator${n > 1 ? "s" : ""} were noted. None of them are strong on their own.`;
}

export interface AnalyzeOptions {
  sensitivity?: Sensitivity;
}

/**
 * Full static analysis of submitted content.
 * Everything here is deterministic: identical input always produces an identical report.
 */
export function analyze(rawInput: string, type: ScanType, options: AnalyzeOptions = {}): ScanResult {
  const input = rawInput.replace(/\r\n/g, "\n");
  const sensitivity = options.sensitivity ?? "balanced";
  const findings: Finding[] = [];

  const headers = type === "email" ? parseEmailHeaders(input) : {};
  // Mailbox addresses are handled by the sender checks; they must not be read as links.
  const linkSource = input.replace(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g, " ");
  const urlStrings = type === "url" ? [input.trim()] : extractUrls(linkSource);
  const urls = urlStrings.slice(0, 12).map(analyzeUrl);

  findings.push(...runLexicalRules(input, type));

  const impersonation = detectImpersonation(input, urls, headers);
  if (impersonation) findings.push(impersonation);

  if (type === "email") {
    const sender = analyzeSender(input, headers);
    if (sender) findings.push(sender);
  }

  const obfuscation = detectObfuscation(input);
  if (obfuscation) findings.push(obfuscation);

  const links = urlFinding(urls);
  if (links) findings.push(links);

  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.weight - a.weight,
  );

  const raw = findings.reduce((total, f) => total + f.weight, 0);
  let score = normalise(raw);

  // A single clearly malicious link should not be diluted by surrounding harmless prose.
  const worstUrl = urls.reduce((max, u) => Math.max(max, u.score), 0);
  if (type === "url") {
    // A link submitted on its own has no surrounding prose to dilute it.
    score = Math.max(score, Math.min(97, Math.round(worstUrl * 1.25)));
  } else if (worstUrl >= 55) {
    score = Math.max(score, Math.round(worstUrl * 0.8));
  }

  // Verbatim trusted destination with no other signals stays low.
  if (urls.length && urls.every((u) => u.trusted && u.score === 0) && findings.length <= 1) {
    score = Math.min(score, 18);
  }

  score = Math.max(0, Math.min(99, score));

  const limits = THRESHOLDS[sensitivity];
  const level: RiskLevel =
    score >= limits.high ? "high" : score >= limits.suspicious ? "suspicious" : "low";

  const density = Math.min(1, input.trim().length / 320);
  const confidence = Math.round(
    Math.max(38, Math.min(96, 46 + findings.length * 9 + density * 14 + (urls.length ? 6 : 0))),
  );

  return {
    id: `scan_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`,
    type,
    input,
    createdAt: Date.now(),
    score,
    level,
    verdict: verdictFor(level, type),
    summary: summaryFor(level, findings, urls, type),
    findings,
    urls,
    highlights: mergeHighlights(findings),
    recommendations: buildRecommendations(level, findings, urls),
    confidence,
  };
}

export const RISK_LABEL: Record<RiskLevel, string> = {
  low: "Low risk",
  suspicious: "Suspicious",
  high: "High risk",
};
