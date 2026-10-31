import { useMemo, useState, type ReactNode } from "react";
import { ArrowLeft, Check, Copy, Trash2 } from "lucide-react";
import type { Highlight, ScanResult, Severity } from "../types";
import {
  Button,
  Eyebrow,
  RISK_STYLES,
  RiskPill,
  SEVERITY_COLOR,
  TYPE_LABEL,
  formatDate,
  formatTime,
} from "../components/ui";
import { cn } from "../utils/cn";

const GLOW: Record<ScanResult["level"], string> = {
  high: "rgba(232,80,60,0.34)",
  suspicious: "rgba(240,162,75,0.26)",
  low: "rgba(127,185,138,0.18)",
};

const MARK_STYLE: Record<Severity, string> = {
  info: "bg-white/[0.08] text-cream",
  low: "bg-peach/15 text-peach decoration-peach/50",
  medium: "bg-warn/15 text-warn decoration-warn/50",
  high: "bg-danger/18 text-[#FF9B88] decoration-danger/60",
};

function renderEvidence(input: string, highlights: Highlight[]): ReactNode[] {
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
    `Risk score: ${scan.score}/100 (${RISK_STYLES[scan.level].label})`,
    `Type: ${TYPE_LABEL[scan.type]} · ${formatDate(scan.createdAt)} ${formatTime(scan.createdAt)}`,
    "",
    "What we detected:",
    ...(scan.findings.length
      ? scan.findings.map((f) => `- ${f.title}: ${f.detail}`)
      : ["- No phishing patterns matched."]),
    "",
    "Recommended action:",
    ...scan.recommendations.map((r, i) => `${i + 1}. ${r}`),
  ];
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
  const style = RISK_STYLES[scan.level];

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(reportText(scan));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

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
          style={{ background: `radial-gradient(circle, ${GLOW[scan.level]}, transparent 68%)` }}
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
            </div>
            <h1 className="mt-5 font-display text-[2.1rem] font-semibold leading-[1.02] tracking-[-0.04em] text-cream sm:text-[3rem]">
              {scan.verdict}
            </h1>
            <p className="mt-5 text-[1rem] leading-[1.75] text-muted">{scan.summary}</p>
            <div className="mt-7 flex flex-wrap items-center gap-3 text-[0.8rem] text-muted">
              <RiskPill level={scan.level} />
              <span>
                {formatDate(scan.createdAt)} · {formatTime(scan.createdAt)}
              </span>
              <span className="h-1 w-1 rounded-full bg-muted/50" />
              <span>Confidence {scan.confidence}%</span>
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
              <span>Low</span>
              <span>Suspicious</span>
              <span>High</span>
            </div>
          </div>
        </div>
      </section>

      {/* A — What we detected */}
      <section className="overflow-hidden rounded-[28px] border border-line bg-ink-2/50 backdrop-blur-xl">
        <header className="flex items-baseline justify-between gap-4 px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">
            What we detected
          </h2>
          <span className="font-mono text-[0.76rem] text-muted">
            {scan.findings.length} signal{scan.findings.length === 1 ? "" : "s"}
          </span>
        </header>

        {scan.findings.length === 0 ? (
          <p className="border-t border-line-soft px-6 py-8 text-[0.95rem] leading-relaxed text-muted sm:px-8">
            No rule in the detection set matched this content. That is not a guarantee of safety —
            verify unexpected requests through a channel you already trust.
          </p>
        ) : (
          <ul className="border-t border-line-soft">
            {scan.findings.map((f) => (
              <li
                key={f.id}
                className="flex gap-4 border-b border-line-soft px-6 py-5 last:border-b-0 sm:px-8"
              >
                <span
                  className={cn("mt-[0.55rem] h-2 w-2 shrink-0 rounded-full", SEVERITY_COLOR[f.severity])}
                />
                <div className="min-w-0">
                  <p className="font-display text-[1rem] tracking-[-0.015em] text-cream">{f.title}</p>
                  <p className="mt-1.5 text-[0.92rem] leading-relaxed text-muted">{f.detail}</p>
                  {f.notes.length > 0 && (
                    <ul className="mt-2.5 space-y-1">
                      {f.notes.slice(0, 4).map((note, i) => (
                        <li key={i} className="text-[0.84rem] leading-relaxed text-muted/85">
                          <span className="mr-2 text-peach/70">—</span>
                          {note}
                        </li>
                      ))}
                    </ul>
                  )}
                  {f.matches.length > 0 && (
                    <p className="mt-2.5 font-mono text-[0.78rem] leading-relaxed text-peach/80">
                      {f.matches
                        .slice(0, 3)
                        .map((m) => `“${m.text.trim()}”`)
                        .join("  ")}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* B — Evidence */}
      <section className="overflow-hidden rounded-[28px] border border-line bg-card/50 backdrop-blur-xl">
        <header className="flex items-baseline justify-between gap-4 px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">Evidence</h2>
          {scan.highlights.length > 0 && (
            <span className="text-[0.78rem] text-muted">Highlighted phrases triggered a rule</span>
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

          {scan.urls.length > 0 && (
            <div className="mt-6">
              <p className="text-[0.8rem] uppercase tracking-[0.2em] text-muted">Links found</p>
              <ul className="mt-3 space-y-2">
                {scan.urls.map((u, i) => (
                  <li
                    key={`${u.raw}-${i}`}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line-soft bg-white/[0.02] px-4 py-3"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-[0.84rem] text-cream/85">
                        {u.raw}
                      </span>
                      <span className="mt-1 block text-[0.78rem] text-muted">
                        Resolves to {u.registrable || u.host || "an unknown host"}
                        {u.signals.filter((s) => s.weight > 0).length > 0 &&
                          ` · ${u.signals.filter((s) => s.weight > 0).length} structural flag(s)`}
                      </span>
                    </span>
                    <RiskPill level={u.level} />
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>

      {/* C — Recommended action */}
      <section className="relative overflow-hidden rounded-[28px] border border-line bg-ink-2/60 backdrop-blur-xl">
        <div
          aria-hidden
          className="pointer-events-none absolute -bottom-32 -left-20 h-72 w-72 rounded-full bg-ember/12 blur-[90px]"
        />
        <header className="relative px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">
            Recommended action
          </h2>
        </header>
        <ol className="relative border-t border-line-soft">
          {scan.recommendations.map((rec, i) => (
            <li
              key={i}
              className="flex gap-5 border-b border-line-soft px-6 py-5 last:border-b-0 sm:px-8"
            >
              <span className="font-mono text-[0.8rem] text-peach/80 tabular-nums">
                {String(i + 1).padStart(2, "0")}
              </span>
              <p className="text-[0.95rem] leading-relaxed text-cream/85">{rec}</p>
            </li>
          ))}
        </ol>
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
