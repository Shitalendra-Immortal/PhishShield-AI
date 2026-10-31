import { ArrowRight, ArrowUpRight } from "lucide-react";
import type { ScanResult } from "../types";
import { Button, Eyebrow, RiskPill, TYPE_LABEL, formatDate, preview } from "../components/ui";

function HeroComposition() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-y-0 right-0 hidden w-[46%] lg:block">
      <div className="absolute right-[-18%] top-1/2 h-[34rem] w-[34rem] -translate-y-1/2">
        <div className="absolute inset-0 rounded-full bg-[radial-gradient(circle_at_35%_30%,rgba(255,193,138,0.95),rgba(241,91,59,0.75)_42%,rgba(232,75,53,0.1)_70%,transparent_75%)] blur-[2px]" />
        <div className="absolute inset-[18%] rounded-full bg-ink-2/80 backdrop-blur-xl" />
        <div className="absolute inset-[18%] rounded-full bg-[radial-gradient(circle_at_70%_80%,rgba(241,91,59,0.35),transparent_60%)]" />
        <div className="absolute inset-[6%] rounded-full border border-white/10" />
        <div className="absolute inset-[-8%] rounded-full border border-white/[0.06]" />
        <div className="absolute inset-[-22%] rounded-full border border-white/[0.04]" />
        <div className="absolute left-1/2 top-[30%] h-[1px] w-[70%] -translate-x-1/2 bg-gradient-to-r from-transparent via-peach/50 to-transparent" />
        <div className="absolute left-1/2 top-[62%] h-[1px] w-[52%] -translate-x-1/2 bg-gradient-to-r from-transparent via-cream/25 to-transparent" />
      </div>
      <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(38,36,39,0.92)_0%,rgba(38,36,39,0.45)_26%,transparent_52%)]" />
    </div>
  );
}

function Stat({ value, label }: { value: number; label: string }) {
  return (
    <div className="px-6 py-7 sm:px-8 sm:py-9">
      <p className="font-display text-[2.6rem] leading-none tracking-[-0.045em] text-cream tabular-nums sm:text-[3.2rem]">
        {value.toString().padStart(2, "0")}
      </p>
      <p className="mt-3 text-[0.88rem] text-muted">{label}</p>
    </div>
  );
}

export function Overview({
  history,
  onNavigate,
  onOpenScan,
}: {
  history: ScanResult[];
  onNavigate: (v: "scan" | "history") => void;
  onOpenScan: (scan: ScanResult) => void;
}) {
  const total = history.length;
  const threats = history.filter((s) => s.level === "high").length;
  const safe = history.filter((s) => s.level === "low").length;
  const recent = history.slice(0, 5);

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* Hero */}
      <section className="relative overflow-hidden rounded-[32px] border border-line bg-card/70 backdrop-blur-xl sm:rounded-[40px] animate-rise">
        <div
          aria-hidden
          className="absolute -right-24 -top-40 h-[32rem] w-[32rem] rounded-full bg-flame/20 blur-[110px] lg:hidden"
        />
        <HeroComposition />
        <div className="absolute inset-x-0 top-0 h-px hairline-top" />

        <div className="relative px-6 py-14 sm:px-12 sm:py-20 lg:w-[62%] lg:py-28 lg:pl-16">
          <Eyebrow>PhishShield</Eyebrow>
          <h1 className="mt-6 font-display text-[2.6rem] font-semibold leading-[0.96] tracking-[-0.045em] text-cream sm:text-[3.7rem] lg:text-[4.4rem]">
            Stay ahead of
            <br />
            <span className="text-gradient">digital threats.</span>
          </h1>
          <p className="mt-7 max-w-lg text-[1.02rem] leading-[1.75] text-muted sm:text-[1.1rem]">
            Analyse suspicious messages, emails and links before you interact with them.
          </p>
          <div className="mt-10 flex flex-wrap items-center gap-3">
            <Button size="lg" onClick={() => onNavigate("scan")}>
              Start a Scan
              <ArrowRight className="h-4 w-4" />
            </Button>
            <Button size="lg" variant="ghost" onClick={() => onNavigate("history")}>
              View history
            </Button>
          </div>

          <div className="mt-12 max-w-lg border-t border-line-soft pt-5 text-[0.82rem] leading-relaxed text-muted">
            Language signals · Link forensics · Sender consistency —{" "}
            <span className="text-cream/70">analysed entirely on your device.</span>
          </div>
        </div>
      </section>

      {/* Statistics */}
      <section className="grid grid-cols-1 divide-y divide-white/[0.07] overflow-hidden rounded-[28px] border border-line bg-ink-2/50 backdrop-blur-xl sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        <Stat value={total} label="Total scans" />
        <Stat value={threats} label="Threats detected" />
        <Stat value={safe} label="Low-risk messages" />
      </section>

      {/* Recent activity */}
      <section className="overflow-hidden rounded-[28px] border border-line bg-card/50 backdrop-blur-xl">
        <div className="flex items-center justify-between gap-4 px-6 py-5 sm:px-8">
          <h2 className="font-display text-[1.15rem] tracking-[-0.02em] text-cream">
            Recent activity
          </h2>
          {total > 0 && (
            <button
              type="button"
              onClick={() => onNavigate("history")}
              className="inline-flex items-center gap-1 text-[0.85rem] text-muted transition-colors hover:text-cream"
            >
              All scans
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {recent.length === 0 ? (
          <div className="border-t border-line-soft px-6 py-14 text-center sm:px-8">
            <p className="font-display text-[1.3rem] tracking-[-0.02em] text-cream">
              Nothing analysed yet.
            </p>
            <p className="mx-auto mt-3 max-w-sm text-[0.92rem] leading-relaxed text-muted">
              Paste a message, email or link and PhishShield will tell you what it finds.
            </p>
            <Button className="mt-7" onClick={() => onNavigate("scan")}>
              Start a Scan
            </Button>
          </div>
        ) : (
          <ul className="border-t border-line-soft">
            {recent.map((scan) => (
              <li key={scan.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(scan)}
                  className="group flex w-full items-center gap-4 border-b border-line-soft px-6 py-4 text-left transition-colors last:border-b-0 hover:bg-white/[0.03] sm:px-8"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[0.95rem] text-cream/90 group-hover:text-cream">
                      {preview(scan.input, 90)}
                    </span>
                    <span className="mt-1 block text-[0.78rem] text-muted">
                      {TYPE_LABEL[scan.type]} · {formatDate(scan.createdAt)}
                    </span>
                  </span>
                  <RiskPill level={scan.level} className="hidden sm:inline-flex" />
                  <span className="w-12 shrink-0 text-right font-mono text-[0.9rem] text-cream tabular-nums">
                    {scan.score}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
