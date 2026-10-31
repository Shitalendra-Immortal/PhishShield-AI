/**
 * PhishShield — shared domain types.
 * These types are consumed by the detection engine, the history store and the UI.
 */

export type ScanType = "message" | "email" | "url";

export type RiskLevel = "low" | "suspicious" | "high";

export type Severity = "info" | "low" | "medium" | "high";

export type FindingCategory =
  | "urgency"
  | "credentials"
  | "impersonation"
  | "url"
  | "intimidation"
  | "reward"
  | "payment"
  | "sender"
  | "greeting"
  | "secrecy"
  | "attachment"
  | "obfuscation";

/** A character span inside the submitted content. */
export interface Span {
  start: number;
  end: number;
  text: string;
}

/** One triggered detection rule, aggregated across all of its matches. */
export interface Finding {
  id: string;
  category: FindingCategory;
  title: string;
  detail: string;
  severity: Severity;
  /** Contribution to the raw risk total before normalisation. */
  weight: number;
  matches: Span[];
  /** Non-textual evidence (hostnames, header values, …). */
  notes: string[];
}

export interface UrlSignal {
  label: string;
  detail: string;
  weight: number;
}

export interface UrlVerdict {
  raw: string;
  href: string;
  host: string;
  registrable: string;
  score: number;
  level: RiskLevel;
  signals: UrlSignal[];
  trusted: boolean;
}

/** Merged, de-overlapped span used to highlight the evidence panel. */
export interface Highlight {
  start: number;
  end: number;
  category: FindingCategory;
  severity: Severity;
  label: string;
}

export interface ScanResult {
  id: string;
  type: ScanType;
  input: string;
  createdAt: number;
  /** 0–100 normalised risk score. */
  score: number;
  level: RiskLevel;
  verdict: string;
  summary: string;
  findings: Finding[];
  urls: UrlVerdict[];
  highlights: Highlight[];
  recommendations: string[];
  /** Confidence in the assessment, derived from signal density. */
  confidence: number;
}

export type Sensitivity = "balanced" | "strict";

export interface Settings {
  sensitivity: Sensitivity;
  storeHistory: boolean;
}
