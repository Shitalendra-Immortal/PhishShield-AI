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

const GLOW: Record<ScanResult["level"], string> = {
  safe: "rgba(127,185,138,0.18)",
  low: "rgba(127,185,138,0.18)",
  suspicious: "rgba(240,162,75,0.26)",
  phishing: "rgba(232,80,60,0.34)",
  high: "rgba(232,80,60,0.34)",
};

const MARK_STYLE: Record<Severity, string> = {
  info: "bg-white/[0.08] text-cream",
  low: "bg-peach/15 text-peach decoration-peach/50",
  medium: "bg-warn/15 text-warn decoration-warn/50",
  high: "bg-danger/18 text-[#FF9B88] decoration-danger/60",
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
    `PhishShield assessment — ${scan.verdict}`,
    `Risk score: ${scan.score}/100 (${RISK_STYLES[scan.level]?.label || scan.level})`,
    `Type: ${TYPE_LABEL[scan.type]} · ${formatDate(scan.createdAt)} ${formatTime(scan.createdAt)}`,
    "",
  ];

  if (scan.note) {
    lines.push(`Note: ${scan.note}`, "");
  }

  if (scan.finalUrl) {
    lines.push(`Final Destination: ${scan.finalUrl}`, "");
  }

  if (scan.threatIntel && scan.threatIntel.status !== "unknown") {
    lines.push(
      `Threat Intel (URLhaus): ${scan.threatIntel.status}${
        scan.threatIntel.threat ? ` (${scan.threatIntel.threat})` : ""
      }`,
      "",
    );
  }

  lines.push("What we detected:");
  if (scan.reasons && scan.reasons.length > 0) {
    scan.reasons.forEach((r) => {
      const pts = r.points > 0 ? `+${r.points}` : `${r.points}`;
      lines.push(`- ${r.label} (${pts} pts): ${r.detail}`);
    });
  } else if (scan.findings && scan.findings.length > 0) {
    scan.findings.forEach((f) => {
      lines.push(`- ${f.title}: ${f.detail}`);
    });
  } else {
    lines.push("- No phishing signals detected.");
  }

  lines.push("", "Recommended action:");
  if (scan.advice) {
    lines.push(scan.advice);
  } else if (scan.recommendations && scan.recommendations.length > 0) {
    scan.recommendations.forEach((r, i) => lines.push(`${i + 1}. ${r}`));
  }

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
  const evidence = useMemo(() => renderEvidence(scan.input, scan.highlights), [scan]);
  const style = RISK_STYLES[scan.level] || RISK_STYLES.safe;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(reportText(scan));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const hasReasons = scan.reasons && scan.reasons.length > 0;
  const hasLegacyFindings = scan.findings && scan.findings.length > 0;

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 animate-rise">
      <button
        type="button"
        onClick={onNewScan}
        className="inline-flex items-center gap-2 text-[0.86rem] text-muted transition-colors hover:text-cream"
      >
        <ArrowLeft className="h-4 w-4" />
        New scan
      </button>

      {/* Verdict */}
      <section className="relative overflow-hidden rounded-[32px] border border-line bg-card/70 px-6 py-10 backdrop-blur-xl sm:rounded-[40px] sm:px-12 sm:py-14">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-28 -top-40 h-[30rem] w-[30rem] rounded-full blur-[110px]"
          style={{ background: `radial-gradient(circle, ${GLOW[scan.level] || GLOW.safe}, transparent 68%)` }}
        />
        <div className="absolute inset-x-0 top-0 h-px hairline-top" />

        <div className="relative flex flex-col gap-10 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-xl">
            <div className="flex flex-wrap items-center gap-3">
              <Eyebrow>Security assessment</Eyebrow>
              <span className="h-1 w-1 rounded-full bg-muted/50" />
              <span className="text-[0.76rem] uppercase tracking-[0.2em] text-muted">
                {TYPE_LABEL[scan.type]}
              </span>
              {scan.host && (
                <>
                  <span className="h-1 w-1 rounded-full bg-muted/50" />
                  <span className="font-mono text-[0.76rem] text-muted">{scan.host}</span>
                </>
              )}
            </div>

            <h1 className="mt-5 font-display text-[2.1rem] font-semibold leading-[1.02] tracking-[-0.04em] text-cream sm:text-[3rem]">
              {scan.verdict}
            </h1>

            {scan.summary && (
              <p className="mt-4 text-[1rem] leading-[1.75] text-muted">{scan.summary}</p>
            )}

            {/* Note badge / card */}
            {scan.note && (
              <div className="mt-5 flex items-start gap-3 rounded-2xl border border-peach/25 bg-peach/10 p-4 text-[0.92rem] text-peach">
                <Info className="mt-0.5 h-4 w-4 shrink-0" />
                <div>
                  <span className="font-medium text-cream">Note: </span>
                  {scan.note}
                </div>
              </div>
            )}

            {/* Threat Intel Pill / Card */}
            {scan.threatIntel && (
              <div className="mt-4">
                {scan.threatIntel.status === "listed" && (
                  <div className="flex items-center gap-2.5 rounded-xl border border-danger/35 bg-danger/15 px-3.5 py-2 text-[0.84rem] text-[#FF9B88]">
                    <ShieldAlert className="h-4 w-4 shrink-0 text-danger" />
                    <span>
                      <strong>URLhaus Alert:</strong> Listed in malicious URL database
                      {scan.threatIntel.threat ? ` (${scan.threatIntel.threat})` : ""}.
                    </span>
                  </div>
                )}
                {scan.threatIntel.status === "clean" && (
                  <div className="flex items-center gap-2.5 rounded-xl border border-safe/30 bg-safe/10 px-3.5 py-2 text-[0.84rem] text-safe">
                    <ShieldCheck className="h-4 w-4 shrink-0" />
                    <span>
                      <strong>Threat Intel:</strong> Checked against abuse.ch URLhaus (clean).
                    </span>
                  </div>
                )}
              </div>
            )}

            <div className="mt-7 flex flex-wrap items-center gap-3 text-[0.8rem] text-muted">
              <RiskPill level={scan.level} />
              <span>
                {formatDate(scan.createdAt)} · {formatTime(scan.createdAt)}
              </span>
            </div>
          </div>

          {/* Score */}
          <div className="w-full lg:w-[20rem]">
            <div className="flex items-end justify-between">
              <p className="text-[0.8rem] uppercase tracking-[0.2em] text-muted">Risk score</p>
              <p className={cn("text-[0.8rem] font-medium", style.text)}>{style.label}</p>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-display text-[5.2rem] font-semibold leading-none tracking-[-0.06em] text-gradient tabular-nums sm:text-[6rem]">
                {scan.score}
              </span>
              <span className="font-display text-[1.6rem] leading-none tracking-[-0.03em] text-muted/70">
                /100
              </span>
            </div>
            <div className="relative mt-6 h-[6px] w-full overflow-hidden rounded-full bg-white/[0.08]">
              <div
                className={cn("h-full rounded-full bg-gradient-to-r transition-all duration-700", style.bar)}
                style={{ width: `${Math.max(4, scan.score)}%` }}
              />
            </div>
            <div className="mt-2.5 flex justify-between font-mono text-[0.68rem] uppercase tracking-[0.14em] text-muted/70">
              <span>Safe (0–29)</span>
              <span>Suspicious (30–59)</span>
              <span>Phishing (60–100)</span>
            </div>
          </div>
        </div>
      </section>

      {/* Redirect Chain & Final Destination (when present) */}
      {scan.redirectChain && scan.redirectChain.length > 0 && (
        <section className="overflow-hidden rounded-[28px] border border-line bg-ink-2/60 backdrop-blur-xl">
          <header className="flex items-center gap-2.5 px-6 py-4 border-b border-line-soft sm:px-8">
            <Route className="h-4 w-4 text-peach" />
            <h2 className="font-display text-[1.1rem] tracking-[-0.02em] text-cream">
              Redirect Analysis &amp; Destination
            </h2>
          </header>
          <div className="p-6 sm:p-8 space-y-4">
            <p className="text-[0.88rem] text-muted leading-relaxed">
              Link shorteners conceal where links go. PhishShield followed the redirection chain:
            </p>
            <ol className="space-y-3 font-mono text-[0.84rem]">
              {scan.redirectChain.map((url, i) => (
                <li
                  key={i}
                  className="flex items-start gap-3 rounded-xl border border-line-soft bg-white/[0.02] p-3 text-cream/90 break-all"
                >
                  <span className="rounded bg-white/10 px-2 py-0.5 text-[0.74rem] text-muted shrink-0">
                    {i === 0 ? "Short URL" : `Hop ${i}`}
                  </span>
                  <span>{url}</span>
                </li>
              ))}
              {scan.finalUrl && (
                <li className="flex items-start gap-3 rounded-xl border border-peach/30 bg-peach/10 p-3.5 text-cream break-all font-semibold">
                  <span className="rounded bg-flame-gradient px-2 py-0.5 text-[0.74rem] text-[#1B1011] shrink-0 font-sans font-bold">
                    Destination
                  </span>
                  <span className="flex-1">{scan.finalUrl}</span>
                </li>
              )}
            </ol>
          </div>
        </section>
      )}

      {/* What we detected / Analysis reasons */}
      <section className="overflow-hidden rounded-[28px] border border-line bg-ink-2/50 backdrop-blur-xl">
        <header className="flex items-baseline justify-between gap-4 px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">
            What we detected
          </h2>
          <span className="font-mono text-[0.76rem] text-muted">
            {hasReasons
              ? `${scan.reasons.length} signal${scan.reasons.length === 1 ? "" : "s"}`
              : hasLegacyFindings
              ? `${scan.findings!.length} signal${scan.findings!.length === 1 ? "" : "s"}`
              : "0 signals"}
          </span>
        </header>

        {!hasReasons && !hasLegacyFindings ? (
          <p className="border-t border-line-soft px-6 py-8 text-[0.95rem] leading-relaxed text-muted sm:px-8">
            No phishing signals found. That is not a guarantee of absolute safety — always verify
            sensitive requests before entering passwords or approving transactions.
          </p>
        ) : (
          <ul className="border-t border-line-soft">
            {hasReasons
              ? scan.reasons.map((r, i) => {
                  const isPositive = r.points > 0;
                  const isNegative = r.points < 0;
                  return (
                    <li
                      key={i}
                      className="flex items-start justify-between gap-4 border-b border-line-soft px-6 py-5 last:border-b-0 sm:px-8"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <p className="font-display text-[1rem] tracking-[-0.015em] text-cream">
                            {r.label}
                          </p>
                        </div>
                        <p className="mt-1.5 text-[0.92rem] leading-relaxed text-muted">
                          {r.detail}
                        </p>
                      </div>
                      <span
                        className={cn(
                          "shrink-0 font-mono text-[0.82rem] font-semibold px-2.5 py-1 rounded-full",
                          isPositive && "bg-danger/15 text-danger border border-danger/30",
                          isNegative && "bg-safe/15 text-safe border border-safe/30",
                          !isPositive && !isNegative && "bg-white/10 text-muted border border-white/10",
                        )}
                      >
                        {isPositive ? `+${r.points} pts` : isNegative ? `${r.points} pts` : "info"}
                      </span>
                    </li>
                  );
                })
              : scan.findings!.map((f) => (
                  <li
                    key={f.id}
                    className="flex gap-4 border-b border-line-soft px-6 py-5 last:border-b-0 sm:px-8"
                  >
                    <div className="min-w-0">
                      <p className="font-display text-[1rem] tracking-[-0.015em] text-cream">{f.title}</p>
                      <p className="mt-1.5 text-[0.92rem] leading-relaxed text-muted">{f.detail}</p>
                    </div>
                  </li>
                ))}
          </ul>
        )}
      </section>

      {/* Evidence / Content inspected */}
      <section className="overflow-hidden rounded-[28px] border border-line bg-card/50 backdrop-blur-xl">
        <header className="flex items-baseline justify-between gap-4 px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">Submitted Content</h2>
          {scan.type === "url" && (
            <span className="text-[0.78rem] text-muted flex items-center gap-1">
              <ExternalLink className="h-3 w-3" /> Exact URL inspected
            </span>
          )}
        </header>

        <div className="border-t border-line-soft px-6 py-6 sm:px-8">
          <div
            className={cn(
              "max-h-[26rem] overflow-y-auto whitespace-pre-wrap break-words rounded-2xl border border-line-soft bg-ink/60 p-5 leading-[1.85] text-cream/90",
              scan.type === "url" ? "font-mono text-[0.9rem]" : "text-[0.95rem]",
            )}
          >
            {evidence}
          </div>

          {scan.urls && scan.urls.length > 0 && (
            <div className="mt-6">
              <p className="text-[0.8rem] uppercase tracking-[0.2em] text-muted">Links found in content</p>
              <ul className="mt-3 space-y-2 font-mono text-[0.84rem]">
                {scan.urls.map((u, i) => {
                  const urlText = typeof u === "string" ? u : u.raw;
                  return (
                    <li
                      key={i}
                      className="flex items-center justify-between gap-3 rounded-2xl border border-line-soft bg-white/[0.02] px-4 py-3"
                    >
                      <span className="truncate text-cream/85">{urlText}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </div>
      </section>

      {/* Recommended action (verbatim advice from backend) */}
      <section className="relative overflow-hidden rounded-[28px] border border-line bg-ink-2/60 backdrop-blur-xl">
        <div
          aria-hidden
          className="pointer-events-none absolute -bottom-32 -left-20 h-72 w-72 rounded-full bg-ember/12 blur-[90px]"
        />
        <header className="relative px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">
            Recommended Action
          </h2>
        </header>
        <div className="relative border-t border-line-soft px-6 py-6 sm:px-8">
          <p className="text-[1.02rem] leading-relaxed text-cream/90">
            {scan.advice || "No specific action required. Continue to follow standard security practices."}
          </p>
        </div>
      </section>

      <div className="flex flex-wrap items-center gap-3 pb-2">
        <Button size="lg" onClick={onNewScan}>
          Scan something else
        </Button>
        <Button size="lg" variant="ghost" onClick={copy}>
          {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          {copied ? "Copied" : "Copy report"}
        </Button>
        <Button size="lg" variant="quiet" onClick={() => onDelete(scan.id)}>
          <Trash2 className="h-4 w-4" />
          Delete scan
        </Button>
      </div>
    </div>
  );
}
