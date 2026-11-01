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

export interface AiSignal {
  type: string;
  detail: string;
}

export interface AiSecondOpinion {
  available: boolean;
  assessment?: "safe" | "suspicious" | "phishing" | null;
  confidence?: "low" | "medium" | "high" | null;
  signals?: AiSignal[];
  explanation?: string | null;
  recommendedAction?: string | null;
  error?: string | null;
}

export interface AssessmentEvidence {
  source: "engine" | "ai";
  label: string;
  detail: string;
  points?: number;
}

/**
 * The dual-verdict aggregator's output, attached to every /api/analyze
 * response. finalVerdict is the headline: the highest justified severity,
 * never a combined score.
 */
export interface Assessment {
  finalVerdict: "safe" | "suspicious" | "phishing";
  backendVerdict: "safe" | "suspicious" | "phishing";
  aiVerdict: "safe" | "suspicious" | "phishing" | null;
  disagreement: boolean;
  aiJustified: boolean;
  combinedEvidence: AssessmentEvidence[];
  recommendation: string;
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
  ai?: AiSecondOpinion | null;
  aiOpinion?: AiSecondOpinion | null;
  assessment?: Assessment | null;
}

export type Sensitivity = "balanced" | "strict";

export type ThemeMode = "dark" | "light";

export interface Settings {
  sensitivity: Sensitivity;
  storeHistory: boolean;
  theme?: ThemeMode;
}
