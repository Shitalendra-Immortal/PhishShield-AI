import { useMemo, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCircle2,
  Copy,
  Info,
  Lightbulb,
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
  high: "bg-danger/20 text-danger font-semibold decoration-danger/60",
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

function getAssessmentComparison(scan: ScanResult, ai: NonNullable<ScanResult["ai"]>) {
  const normBackend =
    scan.level === "high" ? "phishing" : scan.level === "low" ? "safe" : scan.level;
  const normAi = ai.assessment?.toLowerCase();

  if (!normAi) return null;

  const agrees = normBackend === normAi;
  if (agrees) {
    return {
      agrees: true,
      normBackend,
      normAi,
      explanation: null,
    };
  }

  // Extract actual signal names from AI
  const aiSignalNames = (ai.signals || [])
    .map((s) => AI_SIGNAL_TITLES[s.type] || s.type.replace(/_/g, " "))
    .filter(Boolean);
  const aiSignalList =
    aiSignalNames.length > 0
      ? aiSignalNames.slice(0, 2).map((s) => s.toLowerCase()).join(" and ")
      : null;

  // Extract actual backend reasons
  const engineReasons = (scan.reasons || [])
    .filter((r) => r.points > 0)
    .map((r) => r.label.toLowerCase())
    .slice(0, 2);
  const engineReasonList = engineReasons.length > 0 ? engineReasons.join(" and ") : null;

  let explanation = "";

  if (normBackend === "safe" && normAi === "suspicious") {
    explanation = aiSignalList
      ? `The primary engine classified this message as Safe based on structural rules, but the AI identified contextual warning signs, such as ${aiSignalList}, leading it to suggest caution.`
      : `The primary detection engine classified the message as Safe, but the AI identified contextual warning signs not sufficiently captured by the primary engine.`;
  } else if (normBackend === "suspicious" && normAi === "phishing") {
    explanation = aiSignalList
      ? `The primary detection engine identified suspicious indicators (${scan.score}/100) and classified the message as Suspicious. The AI identified additional contextual warning signs, such as ${aiSignalList}, leading it to assess the message as Phishing.`
      : `The primary detection engine scored the message as Suspicious (${scan.score}/100). The AI identified stronger phishing indicators, leading it to assess the message as Phishing.`;
  } else if (normBackend === "phishing" && normAi === "safe") {
    explanation = engineReasonList
      ? `The primary engine detected strong phishing indicators (${engineReasonList}), but the AI did not identify sufficient contextual evidence in the text. Always follow the primary engine verdict for security.`
      : `The primary engine detected strong phishing indicators, but the AI did not identify sufficient contextual evidence. Always follow the primary engine verdict for security.`;
  } else if (normBackend === "suspicious" && normAi === "safe") {
    explanation = engineReasonList
      ? `The primary engine flagged suspicious indicators (${engineReasonList}), but the AI assessed the text context as benign. The primary engine's suspicious verdict remains authoritative.`
      : `The primary engine detected suspicious indicators (${scan.score}/100), but the AI assessed the phrasing as benign. The primary engine verdict remains authoritative.`;
  } else if (normBackend === "safe" && normAi === "phishing") {
    explanation = aiSignalList
      ? `The primary engine detected no rule-based threats, but the AI identified critical contextual phishing signs (${aiSignalList}). Exercise heightened caution.`
      : `The primary engine detected no rule-based threats, but the AI identified strong phishing indicators. Exercise caution.`;
  } else if (normBackend === "phishing" && normAi === "suspicious") {
    explanation = engineReasonList
      ? `The primary engine detected strong phishing indicators (${engineReasonList}), whereas the AI assessed the severity as Suspicious. The primary engine's phishing verdict is final.`
      : `The primary engine detected high-confidence phishing indicators. The AI assessed the threat as Suspicious, but the primary engine verdict remains final.`;
  } else {
    explanation = `The assessments differ because the primary engine analyzes technical signatures and structural rules, while the AI evaluates language semantics and social-engineering patterns. The primary engine verdict remains final.`;
  }

  return {
    agrees: false,
    normBackend,
    normAi,
    explanation,
  };
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

    const comp = getAssessmentComparison(scan, ai);
    if (comp && !comp.agrees && comp.explanation) {
      lines.push("", "--- WHY ASSESSMENTS DIFFER ---");
      lines.push(comp.explanation);
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
  const aiComparison = useMemo(
    () => (ai && ai.available ? getAssessmentComparison(scan, ai) : null),
    [scan, ai],
  );

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
    <div className="mx-auto w-full max-w-5xl space-y-3.5 sm:space-y-4 animate-rise">
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
      <section className="relative overflow-hidden rounded-[16px] border border-line bg-surface p-6 sm:p-7 lg:p-8">
        <div className="relative flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
          <div className="max-w-xl">
            <div className="flex flex-wrap items-center gap-2.5 mb-3.5 sm:mb-4">
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

            <h1 className="font-display text-[2.2rem] font-semibold leading-[1.08] tracking-[-0.035em] text-cream sm:text-[2.8rem]">
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
                  <div className="flex items-center gap-2.5 rounded-[10px] border border-danger/45 bg-danger/15 px-4 py-2.5 font-sans text-[0.88rem] text-danger font-semibold">
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

            {/* Scale with Spectrum Values Below Text */}
            <div className="mt-3 grid grid-cols-3 text-center font-mono text-[0.76rem]">
              <div className={cn("flex flex-col items-center leading-tight", scan.score < 30 ? "text-safe font-bold" : "text-safe/80 font-medium")}>
                <span>Safe</span>
                <span className="text-[0.7rem] opacity-90 font-mono">(0–29)</span>
              </div>
              <div className={cn("flex flex-col items-center leading-tight", scan.score >= 30 && scan.score < 60 ? "text-warn font-bold" : "text-warn/80 font-medium")}>
                <span>Suspicious</span>
                <span className="text-[0.7rem] opacity-90 font-mono">(30–59)</span>
              </div>
              <div className={cn("flex flex-col items-center leading-tight", scan.score >= 60 ? "text-danger font-bold" : "text-danger/80 font-medium")}>
                <span>Phishing</span>
                <span className="text-[0.7rem] opacity-90 font-mono">(60–100)</span>
              </div>
            </div>
          </div>
        </div>
      </section>

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

      {/* AI Second Opinion: Shown only when ai exists and ai.available is true */}
      {ai && ai.available && (
        <section className="relative overflow-hidden rounded-[16px] border border-line bg-gradient-to-br from-elevated/50 via-surface to-elevated/30 animate-rise">
          <header className="flex flex-wrap items-center justify-between gap-3 px-6 py-3.5 border-b border-line-soft sm:px-8 bg-elevated/30">
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

            <div className="flex flex-wrap items-center gap-2">
              {aiComparison?.agrees && (
                <span className="inline-flex items-center gap-1.5 rounded-[6px] bg-safe/15 border border-safe/35 px-2.5 py-0.5 font-mono text-[0.74rem] font-medium text-safe">
                  <CheckCircle2 className="h-3 w-3 text-safe" />
                  Agrees with engine
                </span>
              )}
              {ai.assessment && (
                <span
                  className={cn(
                    "rounded-[6px] px-2.5 py-0.5 font-mono text-[0.74rem] font-bold uppercase tracking-wider border",
                    ai.assessment === "phishing" && "bg-danger/15 text-danger border-danger/45",
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

          <div className="p-4.5 sm:p-6 space-y-3">
            {ai.explanation && (
              <p className="font-sans text-[0.92rem] leading-relaxed text-cream/90">
                {ai.explanation}
              </p>
            )}

            {ai.signals && ai.signals.length > 0 && (
              <div className="pt-1">
                <p className="font-sans text-[0.74rem] font-semibold uppercase tracking-[0.14em] text-muted">
                  Detected Signals ({ai.signals.length})
                </p>
                <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {ai.signals.map((sig, i) => (
                    <div
                      key={i}
                      className="rounded-[8px] border border-line-soft bg-elevated px-3 py-2 text-[0.84rem]"
                    >
                      <p className="font-display font-semibold text-danger text-[0.88rem]">
                        {AI_SIGNAL_TITLES[sig.type] || sig.type.replace(/_/g, " ")}
                      </p>
                      <p className="mt-0.5 font-sans text-[0.82rem] text-muted leading-relaxed">{sig.detail}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Why Do the Assessments Differ? Notice (only shown when assessments diverge) */}
      {ai && ai.available && aiComparison && !aiComparison.agrees && (
        <section className="relative overflow-hidden rounded-[16px] border border-warn/35 bg-warn/10 p-5 sm:p-6 animate-rise">
            <div className="flex items-start gap-3.5">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[8px] bg-warn/20 text-warn">
                <AlertTriangle className="h-4.5 w-4.5" />
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="font-display text-[1.05rem] font-semibold text-cream flex items-center gap-2">
                    Why do the assessments differ?
                  </h3>
                  <span className="font-mono text-[0.74rem] font-semibold uppercase tracking-wider text-warn/90 rounded-[6px] border border-warn/30 bg-warn/15 px-2 py-0.5">
                    Notice
                  </span>
                </div>

                {/* Compact Comparison Summary */}
                <div className="mt-3 flex flex-wrap items-center gap-3 font-mono text-[0.8rem] text-muted border-y border-warn/20 py-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted/80">Backend verdict:</span>
                    <span className="font-semibold text-cream capitalize">
                      {scan.level} ({scan.score}/100)
                    </span>
                  </div>
                  <span className="text-warn/60">·</span>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted/80">AI second opinion:</span>
                    <span className="font-semibold text-cream capitalize">
                      {ai.assessment}
                      {ai.confidence ? ` (${ai.confidence} confidence)` : ""}
                    </span>
                  </div>
                </div>

                {/* Grounded Explanation */}
                <p className="mt-3 font-sans text-[0.92rem] leading-relaxed text-cream/95">
                  {aiComparison.explanation}
                </p>

                <p className="mt-2 text-[0.76rem] font-sans font-medium text-muted">
                  The engine verdict above is final and remains authoritative.
                </p>
              </div>
            </div>
          </section>
      )}

      {/* What We Detected (Signals & Indicators): 16px radius card */}
      <section className="overflow-hidden rounded-[16px] border border-line bg-surface">
        <header className="flex items-baseline justify-between gap-4 px-6 py-3 border-b border-line-soft sm:px-8">
          <h2 className="font-display text-[1.08rem] font-semibold tracking-[-0.02em] text-cream">
            What we detected
          </h2>
          <span className="font-mono text-[0.8rem] font-medium text-muted">
            {hasReasons
              ? `${scan.reasons.length} signal${scan.reasons.length === 1 ? "" : "s"}`
              : hasLegacyFindings
              ? `${scan.findings!.length} signal${scan.findings!.length === 1 ? "" : "s"}`
              : "0 signals"}
          </span>
        </header>

        {!hasReasons && !hasLegacyFindings ? (
          <div className="border-t border-line-soft px-6 py-3.5 sm:px-8 flex items-center gap-2.5 text-muted font-sans text-[0.88rem]">
            <CheckCircle2 className="h-4 w-4 text-safe shrink-0" />
            <span>No threat signals detected. Checks completed cleanly.</span>
          </div>
        ) : (
          <ul className="border-t border-line-soft divide-y divide-line-soft">
            {hasReasons
              ? scan.reasons.map((r, i) => {
                  const isPositive = r.points > 0;
                  const isNegative = r.points < 0;
                  const isZero = r.points === 0;

                  return (
                    <li
                      key={i}
                      className="flex items-start justify-between gap-4 px-6 py-3.5 hover:bg-interactive/30 transition-colors sm:px-8"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="font-display text-[0.95rem] font-semibold tracking-[-0.015em] text-cream">
                          {r.label}
                        </p>
                        <p className="mt-0.5 font-sans text-[0.86rem] leading-relaxed text-muted">
                          {r.detail}
                        </p>
                      </div>

                      {/* Points badge: 6px radius, IBM Plex Mono */}
                      <span
                        className={cn(
                          "shrink-0 font-mono text-[0.78rem] font-medium px-2 py-0.5 rounded-[6px] border",
                          isPositive && "bg-danger/20 text-danger border-danger/50 font-bold",
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
                    className="flex gap-4 px-6 py-3.5 hover:bg-interactive/30 transition-colors sm:px-8"
                  >
                    <div className="min-w-0">
                      <p className="font-display text-[0.95rem] font-semibold tracking-[-0.015em] text-cream">
                        {f.title}
                      </p>
                      <p className="mt-0.5 font-sans text-[0.86rem] leading-relaxed text-muted">{f.detail}</p>
                    </div>
                  </li>
                ))}
          </ul>
        )}
      </section>

      {/* Recommended Action */}
      <section className="relative overflow-hidden rounded-[16px] border border-flame/40 bg-gradient-to-br from-flame/[0.04] via-surface to-ember/[0.02] dark:from-flame/[0.06] dark:via-surface dark:to-transparent">
        <header className="flex items-center gap-2 px-6 py-3 border-b border-flame/15 sm:px-8 bg-flame/[0.03]">
          <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-[5px] bg-flame/12 text-flame">
            <Lightbulb className="h-3 w-3" />
          </span>
          <h2 className="font-display text-[1.05rem] font-semibold tracking-[-0.02em] text-cream">
            Recommended Action
          </h2>
        </header>
        <div className="px-6 py-3.5 sm:px-8">
          <p className="font-sans text-[0.94rem] leading-relaxed text-cream font-medium">
            {scan.advice || "No specific action required. Continue to follow standard security practices."}
          </p>
        </div>
      </section>

      {/* Submitted Content Display */}
      <section className="overflow-hidden rounded-[16px] border border-line bg-surface">
        <header className="flex items-center justify-between px-6 py-2.5 border-b border-line-soft sm:px-8">
          <h2 className="font-display text-[1.02rem] font-semibold text-cream">
            Submitted Content
          </h2>

          <button
            type="button"
            onClick={copyInputText}
            className="inline-flex items-center gap-1.5 rounded-[6px] px-2.5 py-1 font-sans text-[0.78rem] text-muted hover:text-cream hover:bg-interactive transition-colors"
          >
            {copiedInput ? <Check className="h-3.5 w-3.5 text-safe" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copiedInput ? "Copied" : "Copy"}</span>
          </button>
        </header>

        <div className="px-6 py-3.5 sm:px-8">
          <div
            className={cn(
              "max-h-[16rem] overflow-y-auto whitespace-pre-wrap break-words rounded-[8px] bg-elevated/70 p-3 leading-relaxed text-cream/90 select-text",
              scan.type === "url" ? "font-mono text-[0.88rem]" : "font-sans text-[0.9rem]",
            )}
          >
            {evidence}
          </div>

          {scan.urls && scan.urls.length > 0 && scan.type !== "url" && (
            <div className="mt-4">
              <p className="font-sans text-[0.76rem] font-semibold uppercase tracking-[0.14em] text-muted">
                Links found ({scan.urls.length})
              </p>
              <ul className="mt-2 space-y-1.5 font-mono text-[0.82rem]">
                {scan.urls.map((u, i) => {
                  const urlText = typeof u === "string" ? u : (u as { raw: string }).raw;
                  return (
                    <li
                      key={i}
                      className="rounded-[6px] bg-elevated/70 px-3 py-2 text-cream/90 break-all"
                    >
                      {urlText}
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

        <Button
          size="lg"
          variant="quiet"
          onClick={() => onDelete(scan.id)}
          className="text-muted hover:text-danger hover:bg-danger/10 transition-colors"
        >
          <Trash2 className="h-4 w-4 text-danger/80" />
          Delete scan
        </Button>
      </div>
    </div>
  );
}
