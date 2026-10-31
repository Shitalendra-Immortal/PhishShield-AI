import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { motion } from "motion/react";
import type { ScanResult } from "../types";
import { Button, Eyebrow, RiskPill, TYPE_LABEL, formatDate, preview } from "../components/ui";
import { cn } from "../utils/cn";

type Filter = "all" | "phishing" | "suspicious" | "safe";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "phishing", label: "Phishing" },
  { id: "suspicious", label: "Suspicious" },
  { id: "safe", label: "Safe" },
];

/* ── Animate UI Motion Tokens ─────────────────────────────────── */
const SPRING_SELECTION = {
  type: "spring" as const,
  stiffness: 340,
  damping: 30,
};

const SPRING_PRESS = {
  type: "spring" as const,
  stiffness: 550,
  damping: 30,
};

export function History({
  history,
  onOpenScan,
  onNewScan,
  onClear,
}: {
  history: ScanResult[];
  onOpenScan: (scan: ScanResult) => void;
  onNewScan: () => void;
  onClear: () => void;
}) {
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return history.filter((s) => {
      const matchesLevel =
        filter === "all" ||
        (filter === "phishing" && (s.level === "phishing" || s.level === "high")) ||
        (filter === "suspicious" && s.level === "suspicious") ||
        (filter === "safe" && (s.level === "safe" || s.level === "low"));
      return matchesLevel && (!q || s.input.toLowerCase().includes(q));
    });
  }, [history, filter, query]);

  return (
    <div className="mx-auto w-full max-w-5xl animate-rise">
      <header className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <Eyebrow>Archive</Eyebrow>
          <h1 className="mt-4 font-display text-[2.2rem] font-semibold leading-[1.08] tracking-[-0.035em] text-cream sm:text-[2.8rem]">
            Scan history.
          </h1>
          <p className="mt-2.5 max-w-md font-sans text-[0.96rem] leading-[1.7] text-muted">
            Every security assessment you have run, stored on this device only.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button onClick={onNewScan}>New scan</Button>
          {history.length > 0 && (
            <Button variant="quiet" onClick={onClear}>
              Clear
            </Button>
          )}
        </div>
      </header>

      {/* Filters (16px container) & Search Input (10px input field) */}
      <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex flex-wrap gap-1 rounded-[16px] border border-line bg-surface p-1 shadow-sm">
          {FILTERS.map((f) => {
            const isActive = filter === f.id;
            return (
              <motion.button
                key={f.id}
                type="button"
                onClick={() => setFilter(f.id)}
                whileTap={{ scale: 0.97 }}
                transition={SPRING_PRESS}
                className={cn(
                  "relative rounded-[10px] px-3.5 py-1.5 text-[0.84rem] font-sans font-medium outline-none transition-colors duration-200 focus-visible:focus-ring",
                  isActive
                    ? "font-semibold text-[#1B1011]"
                    : "text-muted hover:text-cream hover:bg-interactive/40",
                )}
              >
                {isActive && (
                  <motion.span
                    layoutId="history-filter-active"
                    className="absolute inset-0 rounded-[10px] bg-flame-gradient shadow-sm"
                    transition={SPRING_SELECTION}
                  />
                )}
                <span className="relative z-10">{f.label}</span>
              </motion.button>
            );
          })}
        </div>

        {/* Input field: 10px radius */}
        <div className="flex items-center gap-2.5 rounded-[10px] border border-line bg-elevated px-3.5 py-2 sm:w-64 transition-colors focus-within:border-flame focus-within:ring-1 focus-within:ring-flame/50">
          <Search className="h-4 w-4 shrink-0 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search content"
            className="w-full border-none bg-transparent font-sans text-[0.88rem] text-cream outline-none placeholder:text-muted/60"
          />
        </div>
      </div>

      {/* Table / List: 16px radius main card */}
      <section className="mt-6 overflow-hidden rounded-[16px] border border-line bg-surface">
        <div className="hidden grid-cols-[minmax(0,1fr)_7rem_8rem_8.5rem_4.5rem] items-center gap-4 border-b border-line-soft px-8 py-3.5 font-sans text-[0.76rem] font-semibold uppercase tracking-[0.14em] text-muted md:grid">
          <span>Submitted content</span>
          <span>Type</span>
          <span>Date</span>
          <span>Risk level</span>
          <span className="text-right">Score</span>
        </div>

        {rows.length === 0 ? (
          <div className="px-6 py-12 text-center sm:px-8 sm:py-14">
            <p className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
              {history.length === 0 ? "No scans stored yet." : "Nothing matches that filter."}
            </p>
            <p className="mx-auto mt-2 max-w-sm font-sans text-[0.88rem] leading-relaxed text-muted">
              {history.length === 0
                ? "Run your first analysis and it will be archived here locally."
                : "Try a different risk level filter or clear the search query."}
            </p>
            {history.length === 0 && (
              <Button className="mt-6" onClick={onNewScan}>
                Start a Scan
              </Button>
            )}
          </div>
        ) : (
          <ul>
            {rows.map((scan) => (
              <li key={scan.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(scan)}
                  className="group grid w-full grid-cols-[minmax(0,1fr)_4rem] items-center gap-4 border-b border-line-soft px-6 py-3.5 text-left transition-colors last:border-b-0 hover:bg-interactive/40 sm:px-8 md:grid-cols-[minmax(0,1fr)_7rem_8rem_8.5rem_4.5rem] focus-visible:focus-ring"
                >
                  <span className="min-w-0">
                    <span className="block truncate font-sans text-[0.92rem] text-cream/90 group-hover:text-cream">
                      {preview(scan.input, 85)}
                    </span>
                    <span className="mt-0.5 block font-sans text-[0.78rem] text-muted md:hidden">
                      {TYPE_LABEL[scan.type]} · {formatDate(scan.createdAt)}
                    </span>
                  </span>
                  <span className="hidden font-sans text-[0.86rem] text-muted md:block">
                    {TYPE_LABEL[scan.type]}
                  </span>
                  <span className="hidden font-mono text-[0.82rem] text-muted md:block">
                    {formatDate(scan.createdAt)}
                  </span>
                  <span className="hidden md:block">
                    <RiskPill level={scan.level} />
                  </span>
                  <span className="text-right font-mono text-[0.92rem] font-semibold text-cream tabular-nums">
                    {scan.score}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {rows.length > 0 && (
        <p className="mt-4 font-sans text-[0.84rem] text-muted">
          Showing {rows.length} of {history.length} scan{history.length === 1 ? "" : "s"}.
        </p>
      )}
    </div>
  );
}
