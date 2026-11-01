import type { AiSecondOpinion, Assessment } from "../types";

export interface AnalyzeVerdict {
  level: "safe" | "suspicious" | "phishing";
  label: string;
  advice: string;
}

export interface AnalyzeReason {
  label: string;
  detail: string;
  points: number;
}

export interface ThreatIntel {
  status: "listed" | "clean" | "unknown";
  threat: string | null;
}

export interface AnalyzeResponse {
  kind: "url" | "message";
  score: number;
  verdict: AnalyzeVerdict;
  reasons: AnalyzeReason[];
  host?: string;
  urls?: string[];
  note?: string | null;
  redirectChain?: string[];
  finalUrl?: string | null;
  threatIntel?: ThreatIntel;
  ai?: AiSecondOpinion;
  assessment?: Assessment;
}

export interface SampleItem {
  id: string;
  label: string;
  input: string;
  expectedLevel: "safe" | "suspicious" | "phishing";
}

const DEFAULT_API_URL = "https://phishshield-ai-u284.onrender.com";

export function getApiBaseUrl(): string {
  const envUrl = import.meta.env.VITE_API_URL;
  return (envUrl && envUrl.trim() ? envUrl.trim() : DEFAULT_API_URL).replace(/\/+$/, "");
}

export async function analyzeInput(
  input: string,
  type?: "auto" | "url" | "message",
): Promise<AnalyzeResponse> {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input, type: type || "auto" }),
  });

  const data = await res.json().catch(() => null);

  if (!res.ok) {
    const message =
      data?.error?.message ||
      (res.status === 429
        ? "Rate limit exceeded (100 requests / 15 mins). Please retry shortly."
        : `Analysis failed (${res.status} ${res.statusText})`);
    throw new Error(message);
  }

  return data as AnalyzeResponse;
}

export async function fetchSamples(): Promise<SampleItem[]> {
  try {
    const baseUrl = getApiBaseUrl();
    const res = await fetch(`${baseUrl}/api/samples`);
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data?.samples) ? data.samples : [];
  } catch {
    return [];
  }
}
