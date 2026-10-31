import { useMemo, useState, type ReactNode } from "react";
import {
  ArrowLeft,
  Check,
  Copy,
  ExternalLink,
  Info,
  Route,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import type { Highlight, ScanResult, Severity } from "../types";
import {
  Button,
  Eyebrow,
  RISK_STYLES,
  RiskPill,
  TYPE_LABEL,
  formatDate,
  formatTime,
} from "../components/ui";
import { cn } from "../utils/cn";

const MARK_STYLE: Record<Severity, string> = {
  info: "bg-interactive text-cream",
  low: "bg-peach/15 text-peach decoration-peach/50",
  medium: "bg-warn/15 text-warn decoration-warn/50",
  high: "bg-danger/20 text-[#FF9B88] decoration-danger/60",
};

const AI_SIGNAL_TITLES: Record<string, string> = {
  false_authority: "False Authority",
  manufactured_urgency: "Manufactured Urgency",
  fake_deadline: "Fake Deadline",
  prize_lure: "Prize or Reward Lure",
  impersonation: "Brand Impersonation",
  credential_request: "Credential / PIN Request",
  suspicious_link: "Suspicious or Obfuscated Link",
  unverifiable_claim: "Unverifiable Claim",
  pressure_to_act: "Pressure & Intimidation",
  unusual_sender: "Unusual Sender Address",
};

function renderEvidence(input: string, highlights?: Highlight[]): ReactNode[] {
  if (!highlights || highlights.length === 0) {
    return [<span>{input}</span>];
  }
  const nodes: ReactNode[] = [];
  let cursor = 0;
  highlights.forEach((h, i) => {
    if (h.start > cursor) nodes.push(<span key={`t${i}`}>{input.slice(cursor, h.start)}</span>);
    nodes.push(
      <mark
        key={`h${i}`}
        title={h.label}
        className={cn(
          "rounded-[4px] px-[3px] py-[1px] underline decoration-dotted underline-offset-[3px]",
          MARK_STYLE[h.severity],
        )}
      >
        {input.slice(h.start, h.end)}
      </mark>,
    );
    cursor = Math.max(cursor, h.end);
  });
  if (cursor < input.length) nodes.push(<span key="tail">{input.slice(cursor)}</span>);
  return nodes;
}

function reportText(scan: ScanResult): string {
  const lines = [
    `==============================================`,
    `PHISHSHIELD SECURITY ASSESSMENT REPORT`,
    `==============================================`,
    `Verdict: ${scan.verdict}`,
    `Risk Score: ${scan.score}/100 (${RISK_STYLES[scan.level]?.label || scan.level})`,
    `Type: ${TYPE_LABEL[scan.type]} · Date: ${formatDate(scan.createdAt)} ${formatTime(scan.createdAt)}`,
    "",
  ];

  if (scan.host) {
    lines.push(`Analyzed Host: ${scan.host}`);
  }
  if (scan.finalUrl) {
    lines.push(`Final Destination URL: ${scan.finalUrl}`);
  }
  if (scan.note) {
    lines.push(`Security Note: ${scan.note}`);
  }

  if (scan.threatIntel && scan.threatIntel.status !== "unknown") {
    lines.push(
      `Threat Intelligence (URLhaus): ${scan.threatIntel.status}${
        scan.threatIntel.threat ? ` (${scan.threatIntel.threat})` : ""
      }`,
    );
  }

  lines.push("", "--- DETECTED INDICATORS ---");
  if (scan.reasons && scan.reasons.length > 0) {
    scan.reasons.forEach((r) => {
      const pts = r.points > 0 ? `+${r.points} pts` : r.points < 0 ? `${r.points} pts` : "Informational";
      lines.push(`• [${pts}] ${r.label}`);
      lines.push(`  ${r.detail}`);
    });
  } else if (scan.findings && scan.findings.length > 0) {
    scan.findings.forEach((f) => {
      lines.push(`• ${f.title}: ${f.detail}`);
    });
  } else {
    lines.push("• No suspicious phishing signals detected.");
  }

  const ai = scan.ai || scan.aiOpinion;
  if (ai && ai.available) {
    lines.push("", "--- AI SECOND OPINION ---");
    lines.push(`Assessment: ${ai.assessment || "N/A"}`);
    lines.push(`Confidence: ${ai.confidence || "N/A"}`);
    if (ai.explanation) {
      lines.push(`Explanation: ${ai.explanation}`);
    }
    if (ai.signals && ai.signals.length > 0) {
      lines.push("Social-engineering signals:");
      ai.signals.forEach((s) => {
        lines.push(`  - ${AI_SIGNAL_TITLES[s.type] || s.type}: ${s.detail}`);
      });
    }
    if (ai.recommendedAction) {
      lines.push(`AI Action: ${ai.recommendedAction}`);
    }
  }

  lines.push("", "--- RECOMMENDED ACTION ---");
  if (scan.advice) {
    lines.push(scan.advice);
  } else if (scan.recommendations && scan.recommendations.length > 0) {
    scan.recommendations.forEach((r, i) => lines.push(`${i + 1}. ${r}`));
  } else {
    lines.push("Standard security precautions apply.");
  }

  lines.push("", "--- SUBMITTED CONTENT ---");
  lines.push(scan.input);
  lines.push("==============================================");

  return lines.join("\n");
}

export function Result({
  scan,
  onNewScan,
  onDelete,
}: {
  scan: ScanResult;
  onNewScan: () => void;
  onDelete: (id: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  const [copiedInput, setCopiedInput] = useState(false);
  const evidence = useMemo(() => renderEvidence(scan.input, scan.highlights), [scan]);
  const style = RISK_STYLES[scan.level] || RISK_STYLES.safe;
  const ai = scan.ai || scan.aiOpinion;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(reportText(scan));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const copyInputText = async () => {
    try {
      await navigator.clipboard.writeText(scan.input);
      setCopiedInput(true);
      window.setTimeout(() => setCopiedInput(false), 2000);
    } catch {
      setCopiedInput(false);
    }
  };

  const hasReasons = scan.reasons && scan.reasons.length > 0;
  const hasLegacyFindings = scan.findings && scan.findings.length > 0;

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 animate-rise">
      {/* Top action header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={onNewScan}
          className="inline-flex items-center gap-2 rounded-[12px] border border-line bg-surface px-4 py-2 font-sans text-[0.84rem] font-medium text-cream transition-colors hover:bg-interactive hover:border-line focus-visible:focus-ring"
        >
          <ArrowLeft className="h-4 w-4 text-flame" />
          Back to Scanner
        </button>

        <div className="flex items-center gap-2.5">
          <Button variant="ghost" onClick={copy} size="md">
            {copied ? <Check className="h-4 w-4 text-safe" /> : <Copy className="h-4 w-4" />}
            {copied ? "Report Copied" : "Copy Report"}
          </Button>
          <Button onClick={onNewScan} size="md">
            Scan Another Message
          </Button>
        </div>
      </div>

      {/* Main Verdict Card: 16px radius, solid tonal surface */}
      <section className="relative overflow-hidden rounded-[16px] border border-line bg-surface px-6 py-8 sm:px-10 sm:py-9">
        <div className="relative flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-xl">
            <div className="flex flex-wrap items-center gap-2.5">
              <Eyebrow>Security assessment</Eyebrow>
              <span className="h-1 w-1 rounded-full bg-muted/60" />
              <span className="font-sans text-[0.8rem] font-semibold uppercase tracking-[0.14em] text-cream/90">
                {TYPE_LABEL[scan.type]}
              </span>
              {scan.host && (
                <>
                  <span className="h-1 w-1 rounded-full bg-muted/60" />
                  <span className="font-mono text-[0.82rem] text-cream/90">{scan.host}</span>
                </>
              )}
            </div>

            <h1 className="mt-3.5 font-display text-[2.2rem] font-semibold leading-[1.08] tracking-[-0.035em] text-cream sm:text-[2.8rem]">
              {scan.verdict}
            </h1>

            {scan.summary && (
              <p className="mt-3 font-sans text-[0.98rem] leading-[1.7] text-cream/90">{scan.summary}</p>
            )}

            {/* Official domain / note badge */}
            {scan.note && (
              <div className="mt-4 flex items-start gap-3 rounded-[10px] border border-peach/30 bg-peach/10 p-3.5 font-sans text-[0.9rem] text-peach">
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-peach" />
                <div>
                  <span className="font-semibold text-cream">Security Note: </span>
                  <span className="text-cream/95">{scan.note}</span>
                </div>
              </div>
            )}

            {/* Threat Intel Alert Card */}
            {scan.threatIntel && (
              <div className="mt-3">
                {scan.threatIntel.status === "listed" && (
                  <div className="flex items-center gap-2.5 rounded-[10px] border border-danger/35 bg-danger/12 px-4 py-2.5 font-sans text-[0.88rem] text-[#FFB0A0]">
                    <ShieldAlert className="h-4 w-4 shrink-0 text-danger" />
                    <span>
                      <strong className="text-cream">URLhaus Alert:</strong> Listed in malicious URL database
                      {scan.threatIntel.threat ? ` (${scan.threatIntel.threat})` : ""}.
                    </span>
                  </div>
                )}
                {scan.threatIntel.status === "clean" && (
                  <div className="flex items-center gap-2.5 rounded-[10px] border border-safe/30 bg-safe/10 px-4 py-2.5 font-sans text-[0.88rem] text-safe">
                    <ShieldCheck className="h-4 w-4 shrink-0 text-safe" />
                    <span>
                      <strong className="text-cream">Threat Intel:</strong> Verified against abuse.ch URLhaus (clean).
                    </span>
                  </div>
                )}
              </div>
            )}

            <div className="mt-6 flex flex-wrap items-center gap-3 font-sans text-[0.84rem] text-muted">
              <RiskPill level={scan.level} />
              <span className="font-mono text-[0.8rem]">
                {formatDate(scan.createdAt)} · {formatTime(scan.createdAt)}
              </span>
            </div>
          </div>

          {/* Normalized Risk Score & Scale: 12px container, IBM Plex Mono typography */}
          <div className="w-full rounded-[12px] border border-line bg-elevated p-5 lg:w-[22rem]">
            <div className="flex items-end justify-between">
              <p className="font-sans text-[0.8rem] font-semibold uppercase tracking-[0.16em] text-muted">
                Risk Score
              </p>
              <p className={cn("font-mono text-[0.84rem] font-semibold tracking-wide", style.text)}>
                {style.label}
              </p>
            </div>

            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-mono text-[4.4rem] font-semibold leading-none tracking-tight text-gradient tabular-nums sm:text-[5rem]">
                {scan.score}
              </span>
              <span className="font-mono text-[1.4rem] leading-none text-muted font-medium">
                / 100
              </span>
            </div>

            {/* Progress Bar (6px radius) */}
            <div className="relative mt-4 h-2.5 w-full overflow-hidden rounded-[6px] border border-line bg-interactive p-0.5">
              <div
                className={cn("h-full rounded-[6px] bg-gradient-to-r transition-all duration-500", style.bar)}
                style={{ width: `${Math.max(5, scan.score)}%` }}
              />
            </div>

            {/* Scale with High Contrast */}
            <div className="mt-3 grid grid-cols-3 text-center font-mono text-[0.76rem] font-medium">
              <span className={cn(scan.score < 30 ? "text-safe font-bold" : "text-safe/80")}>
                Safe (0–29)
              </span>
              <span className={cn(scan.score >= 30 && scan.score < 60 ? "text-warn font-bold" : "text-warn/80")}>
                Suspicious (30–59)
              </span>
              <span className={cn(scan.score >= 60 ? "text-danger font-bold" : "text-danger/80")}>
                Phishing (60–100)
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* AI Second Opinion: Shown only when ai exists and ai.available is true */}
      {ai && ai.available && (
        <section className="relative overflow-hidden rounded-[16px] border border-line bg-surface animate-rise">
          <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-line-soft sm:px-8">
            <div className="flex items-center gap-2.5">
              <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-flame/10 text-flame">
                <Sparkles className="h-4 w-4" />
              </span>
              <div>
                <h2 className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
                  AI second opinion
                </h2>
                <p className="font-sans text-[0.78rem] text-muted">
                  The engine verdict above is final.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {ai.assessment && (
                <span
                  className={cn(
                    "rounded-[6px] px-2.5 py-0.5 font-mono text-[0.74rem] font-semibold uppercase tracking-wider border",
                    ai.assessment === "phishing" && "bg-danger/15 text-[#FFB0A0] border-danger/35",
                    ai.assessment === "suspicious" && "bg-warn/15 text-warn border-warn/35",
                    ai.assessment === "safe" && "bg-safe/15 text-safe border-safe/35",
                  )}
                >
                  AI: {ai.assessment}
                </span>
              )}
              {ai.confidence && (
                <span className="rounded-[6px] bg-elevated border border-line px-2.5 py-0.5 font-mono text-[0.74rem] font-medium text-muted">
                  Confidence: <span className="capitalize text-cream font-semibold">{ai.confidence}</span>
                </span>
              )}
            </div>
          </header>

          <div className="p-6 sm:p-8 space-y-4">
            {ai.explanation && (
              <div>
                <p className="font-sans text-[0.78rem] font-semibold uppercase tracking-[0.14em] text-muted">
                  Explanation
                </p>
                <p className="mt-1 font-sans text-[0.94rem] leading-relaxed text-cream/90">
                  {ai.explanation}
                </p>
              </div>
            )}

            {ai.signals && ai.signals.length > 0 && (
              <div className="pt-1">
                <p className="font-sans text-[0.78rem] font-semibold uppercase tracking-[0.14em] text-muted">
                  Detected Signals ({ai.signals.length})
                </p>
                <div className="mt-2.5 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  {ai.signals.map((sig, i) => (
                    <div
                      key={i}
                      className="rounded-[10px] border border-line-soft bg-elevated p-3 text-[0.88rem]"
                    >
                      <p className="font-display font-semibold text-flame text-[0.92rem]">
                        {AI_SIGNAL_TITLES[sig.type] || sig.type.replace(/_/g, " ")}
                      </p>
                      <p className="mt-1 font-sans text-[0.84rem] text-muted leading-relaxed">{sig.detail}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {ai.recommendedAction && (
              <div className="pt-2 border-t border-line-soft">
                <p className="font-sans text-[0.78rem] font-semibold uppercase tracking-[0.14em] text-muted">
                  Recommended Action
                </p>
                <p className="mt-1 font-sans text-[0.92rem] font-medium text-cream">
                  {ai.recommendedAction}
                </p>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Redirect Chain & Final Destination: 16px radius card */}
      {scan.redirectChain && scan.redirectChain.length > 0 && (
        <section className="overflow-hidden rounded-[16px] border border-line bg-surface">
          <header className="flex items-center gap-2.5 px-6 py-4 border-b border-line-soft sm:px-8">
            <Route className="h-4 w-4 text-flame" />
            <h2 className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
              Redirect Analysis &amp; Destination
            </h2>
          </header>
          <div className="p-6 sm:p-8 space-y-3.5">
            <p className="font-sans text-[0.92rem] text-cream/90 leading-relaxed">
              Link shorteners conceal where links go. PhishShield traced the full redirection chain:
            </p>
            <ol className="space-y-2.5 font-mono text-[0.86rem]">
              {scan.redirectChain.map((url, i) => (
                <li
                  key={i}
                  className="flex items-start gap-3 rounded-[10px] border border-line-soft bg-elevated p-3 text-cream/95 break-all"
                >
                  <span className="rounded-[6px] bg-interactive border border-line px-2 py-0.5 text-[0.74rem] font-medium text-muted shrink-0">
                    {i === 0 ? "Short URL" : `Hop ${i}`}
                  </span>
                  <span>{url}</span>
                </li>
              ))}
              {scan.finalUrl && (
                <li className="flex items-start gap-3 rounded-[10px] border border-flame/30 bg-flame/10 p-3.5 text-cream break-all font-semibold">
                  <span className="rounded-[6px] bg-flame-gradient px-2 py-0.5 text-[0.74rem] text-[#1B1011] shrink-0 font-sans font-bold">
                    Destination
                  </span>
                  <span className="flex-1 font-mono">{scan.finalUrl}</span>
                </li>
              )}
            </ol>
          </div>
        </section>
      )}

      {/* What We Detected (Signals & Indicators): 16px radius card */}
      <section className="overflow-hidden rounded-[16px] border border-line bg-surface">
        <header className="flex items-baseline justify-between gap-4 px-6 py-4 border-b border-line-soft sm:px-8">
          <h2 className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
            What we detected
          </h2>
          <span className="font-mono text-[0.82rem] font-medium text-muted">
            {hasReasons
              ? `${scan.reasons.length} signal${scan.reasons.length === 1 ? "" : "s"}`
              : hasLegacyFindings
              ? `${scan.findings!.length} signal${scan.findings!.length === 1 ? "" : "s"}`
              : "0 signals"}
          </span>
        </header>

        {!hasReasons && !hasLegacyFindings ? (
          <p className="border-t border-line-soft px-6 py-8 font-sans text-[0.94rem] leading-relaxed text-muted sm:px-8">
            No phishing signals found. While this content shows no recognized threats, always verify
            sensitive financial requests or password prompts directly with the provider.
          </p>
        ) : (
          <ul className="border-t border-line-soft">
            {hasReasons
              ? scan.reasons.map((r, i) => {
                  const isPositive = r.points > 0;
                  const isNegative = r.points < 0;
                  const isZero = r.points === 0;

                  return (
                    <li
                      key={i}
                      className="flex items-start justify-between gap-4 border-b border-line-soft px-6 py-4 last:border-b-0 hover:bg-interactive/30 transition-colors sm:px-8"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="font-display text-[0.98rem] font-semibold tracking-[-0.015em] text-cream">
                          {r.label}
                        </p>
                        <p className="mt-1 font-sans text-[0.9rem] leading-relaxed text-muted">
                          {r.detail}
                        </p>
                      </div>

                      {/* Points badge: 6px radius, IBM Plex Mono */}
                      <span
                        className={cn(
                          "shrink-0 font-mono text-[0.8rem] font-medium px-2.5 py-0.5 rounded-[6px] border",
                          isPositive && "bg-danger/15 text-[#FFB0A0] border-danger/35",
                          isNegative && "bg-safe/15 text-safe border-safe/35",
                          isZero && "bg-interactive text-muted border-line",
                        )}
                      >
                        {isPositive ? `+${r.points} pts` : isNegative ? `${r.points} pts` : "Notice"}
                      </span>
                    </li>
                  );
                })
              : scan.findings!.map((f) => (
                  <li
                    key={f.id}
                    className="flex gap-4 border-b border-line-soft px-6 py-4 last:border-b-0 hover:bg-interactive/30 transition-colors sm:px-8"
                  >
                    <div className="min-w-0">
                      <p className="font-display text-[0.98rem] font-semibold tracking-[-0.015em] text-cream">
                        {f.title}
                      </p>
                      <p className="mt-1 font-sans text-[0.9rem] leading-relaxed text-muted">{f.detail}</p>
                    </div>
                  </li>
                ))}
          </ul>
        )}
      </section>

      {/* Recommended Action: 16px radius card */}
      <section className="relative overflow-hidden rounded-[16px] border border-line bg-surface">
        <header className="px-6 py-4 border-b border-line-soft sm:px-8">
          <h2 className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
            Recommended Action
          </h2>
        </header>
        <div className="px-6 py-5 sm:px-8">
          <p className="font-sans text-[0.98rem] leading-relaxed text-cream font-medium">
            {scan.advice || "No specific action required. Continue to follow standard security practices."}
          </p>
        </div>
      </section>

      {/* Submitted Content Display: 16px radius card */}
      <section className="overflow-hidden rounded-[16px] border border-line bg-surface">
        <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-line-soft sm:px-8">
          <div className="flex items-center gap-3">
            <h2 className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
              Submitted Content
            </h2>
            <span className="font-mono text-[0.78rem] text-muted">
              {scan.input.length} characters
            </span>
          </div>

          <div className="flex items-center gap-2">
            {scan.type === "url" && (
              <span className="font-sans text-[0.8rem] text-muted flex items-center gap-1">
                <ExternalLink className="h-3 w-3" /> Exact URL inspected
              </span>
            )}
            <button
              type="button"
              onClick={copyInputText}
              className="inline-flex items-center gap-1 rounded-[8px] border border-line bg-elevated px-3 py-1 font-sans text-[0.78rem] text-muted transition-colors hover:text-cream hover:bg-interactive focus-visible:focus-ring"
            >
              {copiedInput ? <Check className="h-3 w-3 text-safe" /> : <Copy className="h-3 w-3" />}
              {copiedInput ? "Copied" : "Copy Content"}
            </button>
          </div>
        </header>

        <div className="px-6 py-5 sm:px-8">
          <div
            className={cn(
              "max-h-[22rem] overflow-y-auto whitespace-pre-wrap break-words break-all rounded-[10px] border border-line-soft bg-elevated p-4 leading-[1.8] text-cream",
              scan.type === "url" ? "font-mono text-[0.92rem]" : "font-sans text-[0.94rem]",
            )}
          >
            {evidence}
          </div>

          {scan.urls && scan.urls.length > 0 && (
            <div className="mt-5">
              <p className="font-sans text-[0.78rem] font-semibold uppercase tracking-[0.16em] text-muted">
                Links found in content ({scan.urls.length})
              </p>
              <ul className="mt-2.5 space-y-2 font-mono text-[0.86rem]">
                {scan.urls.map((u, i) => {
                  const urlText = typeof u === "string" ? u : (u as { raw: string }).raw;
                  return (
                    <li
                      key={i}
                      className="flex items-center justify-between gap-3 rounded-[10px] border border-line-soft bg-elevated px-3.5 py-2.5 break-all"
                    >
                      <span className="truncate text-cream/90">{urlText}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </div>
      </section>

      {/* Bottom Action Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2 pb-4">
        <div className="flex flex-wrap items-center gap-3">
          <Button size="lg" onClick={onNewScan}>
            Scan Another Message
          </Button>
          <Button size="lg" variant="ghost" onClick={copy}>
            {copied ? <Check className="h-4 w-4 text-safe" /> : <Copy className="h-4 w-4" />}
            {copied ? "Report Copied" : "Copy Report"}
          </Button>
        </div>

        <Button size="lg" variant="quiet" onClick={() => onDelete(scan.id)}>
          <Trash2 className="h-4 w-4 text-danger/80" />
          Delete scan
        </Button>
      </div>
    </div>
  );
}
