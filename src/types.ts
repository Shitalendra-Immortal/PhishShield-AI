/**
 * PhishShield — shared domain types.
 * These types are consumed by the API client, detection engine, history store, and UI.
 */

export type ScanType = "message" | "email" | "url";

export type RiskLevel = "safe" | "suspicious" | "phishing" | "low" | "high";

export type Severity = "info" | "low" | "medium" | "high";

export interface AnalyzeReason {
  label: string;
  detail: string;
  points: number;
}

export interface ThreatIntel {
  status: "listed" | "clean" | "unknown";
  threat: string | null;
}

export interface Span {
  start: number;
  end: number;
  text: string;
}

export interface Finding {
  id: string;
  category: string;
  title: string;
  detail: string;
  severity: Severity;
  weight: number;
  matches: Span[];
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

export interface Highlight {
  start: number;
  end: number;
  category: string;
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
  advice: string;
  reasons: AnalyzeReason[];
  host?: string;
  urls?: string[];
  note?: string | null;
  redirectChain?: string[];
  finalUrl?: string | null;
  threatIntel?: ThreatIntel;
  summary?: string;
  findings?: Finding[];
  highlights?: Highlight[];
  recommendations?: string[];
  confidence?: number;
}

export type Sensitivity = "balanced" | "strict";

export interface Settings {
  sensitivity: Sensitivity;
  storeHistory: boolean;
}
