import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import type { RiskLevel, ScanResult } from "../types";
import { Button, Eyebrow, RiskPill, TYPE_LABEL, formatDate, preview } from "../components/ui";
import { cn } from "../utils/cn";

type Filter = "all" | RiskLevel;

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "high", label: "High risk" },
  { id: "suspicious", label: "Suspicious" },
  { id: "low", label: "Low risk" },
];

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
    return history.filter(
      (s) =>
        (filter === "all" || s.level === filter) && (!q || s.input.toLowerCase().includes(q)),
    );
  }, [history, filter, query]);

  return (
    <div className="mx-auto w-full max-w-5xl animate-rise">
      <header className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <Eyebrow>Archive</Eyebrow>
          <h1 className="mt-5 font-display text-[2.4rem] font-semibold leading-[1] tracking-[-0.045em] text-cream sm:text-[3.2rem]">
            Scan history.
          </h1>
          <p className="mt-4 max-w-md text-[0.98rem] leading-[1.7] text-muted">
            Every assessment you have run, kept on this device only.
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

      {/* Filters */}
      <div className="mt-10 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap gap-2">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setFilter(f.id)}
              className={cn(
                "rounded-full border px-4 py-2 text-[0.84rem] transition-all duration-300",
                filter === f.id
                  ? "border-transparent bg-flame-gradient font-medium text-[#1B1011]"
                  : "border-line text-muted hover:border-white/20 hover:text-cream",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2.5 rounded-full border border-line bg-white/[0.03] px-4 py-2.5 sm:w-64">
          <Search className="h-4 w-4 shrink-0 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search content"
            className="w-full border-none bg-transparent text-[0.88rem] text-cream outline-none"
          />
        </div>
      </div>

      {/* Table */}
      <section className="mt-6 overflow-hidden rounded-[28px] border border-line bg-card/50 backdrop-blur-xl">
        <div className="hidden grid-cols-[minmax(0,1fr)_7rem_8rem_8.5rem_4rem] items-center gap-4 border-b border-line-soft px-8 py-4 text-[0.74rem] uppercase tracking-[0.18em] text-muted md:grid">
          <span>Submitted content</span>
          <span>Type</span>
          <span>Date</span>
          <span>Risk level</span>
          <span className="text-right">Score</span>
        </div>

        {rows.length === 0 ? (
          <div className="px-6 py-16 text-center sm:px-8">
            <p className="font-display text-[1.3rem] tracking-[-0.02em] text-cream">
              {history.length === 0 ? "No scans stored yet." : "Nothing matches that filter."}
            </p>
            <p className="mx-auto mt-3 max-w-sm text-[0.92rem] leading-relaxed text-muted">
              {history.length === 0
                ? "Run your first analysis and it will appear here."
                : "Try a different risk level or clear the search."}
            </p>
            {history.length === 0 && (
              <Button className="mt-7" onClick={onNewScan}>
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
                  className="group grid w-full grid-cols-[minmax(0,1fr)_4rem] items-center gap-4 border-b border-line-soft px-6 py-4 text-left transition-colors last:border-b-0 hover:bg-white/[0.03] sm:px-8 md:grid-cols-[minmax(0,1fr)_7rem_8rem_8.5rem_4rem]">
                  <span className="min-w-0">
                    <span className="block truncate text-[0.95rem] text-cream/90 group-hover:text-cream">
                      {preview(scan.input, 80)}
                    </span>
                    <span className="mt-1 block text-[0.78rem] text-muted md:hidden">
                      {TYPE_LABEL[scan.type]} · {formatDate(scan.createdAt)}
                    </span>
                  </span>
                  <span className="hidden text-[0.86rem] text-muted md:block">
                    {TYPE_LABEL[scan.type]}
                  </span>
                  <span className="hidden text-[0.86rem] text-muted md:block">
                    {formatDate(scan.createdAt)}
                  </span>
                  <span className="hidden md:block">
                    <RiskPill level={scan.level} />
                  </span>
                  <span className="text-right font-mono text-[0.9rem] text-cream tabular-nums">
                    {scan.score}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      {rows.length > 0 && (
        <p className="mt-5 text-[0.82rem] text-muted">
          Showing {rows.length} of {history.length} scan{history.length === 1 ? "" : "s"}.
        </p>
      )}
    </div>
  );
}
