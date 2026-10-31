import { useEffect, useState, type ReactNode } from "react";
import { X } from "lucide-react";
import type { Settings } from "../types";
import { cn } from "../utils/cn";
import { Button, Eyebrow, Wordmark } from "./ui";

export type View = "overview" | "scan" | "history" | "result";

const NAV: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "scan", label: "Scan" },
  { id: "history", label: "History" },
];

/* ── Ambient background ───────────────────────────────────────── */

function Atmosphere() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-ink">
      <div className="absolute inset-0 ambient-field" />
      <div className="absolute -right-[12%] -top-[22%] h-[46rem] w-[46rem] rounded-full bg-[radial-gradient(circle,rgba(241,91,59,0.26),transparent_62%)] blur-[40px] animate-breathe" />
      <div className="absolute -bottom-[26%] -left-[14%] h-[40rem] w-[40rem] rounded-full bg-[radial-gradient(circle,rgba(255,135,76,0.13),transparent_60%)] blur-[50px]" />
      <div className="absolute inset-0 grain opacity-[0.035] mix-blend-overlay" />
      <div className="absolute inset-x-0 top-0 h-px hairline-top opacity-60" />
    </div>
  );
}

/* ── Navigation ───────────────────────────────────────────────── */

function NavPill({
  view,
  onNavigate,
  className,
  fill,
}: {
  view: View;
  onNavigate: (v: View) => void;
  className?: string;
  fill?: boolean;
}) {
  const active: View = view === "result" ? "scan" : view;
  return (
    <nav
      className={cn(
        "flex items-center gap-1 rounded-full border border-line bg-ink-2/70 p-1 backdrop-blur-xl",
        className,
      )}
    >
      {NAV.map((item) => {
        const isActive = active === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onNavigate(item.id)}
            aria-current={isActive ? "page" : undefined}
            className={cn(
              "relative rounded-full px-4 py-2 text-[0.86rem] font-medium transition-all duration-300 outline-none focus-visible:focus-ring sm:px-5",
              fill && "flex-1",
              isActive
                ? "bg-flame-gradient text-[#1B1011] shadow-[0_10px_26px_-14px_rgba(241,91,59,0.9)]"
                : "text-muted hover:text-cream",
            )}
          >
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}

/* ── Methodology + settings drawer ────────────────────────────── */

function Drawer({
  open,
  onClose,
  settings,
  onUpdate,
  onClearHistory,
  historyCount,
}: {
  open: boolean;
  onClose: () => void;
  settings: Settings;
  onUpdate: (patch: Partial<Settings>) => void;
  onClearHistory: () => void;
  historyCount: number;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    if (open) document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose, open]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="absolute inset-0 bg-ink/70 backdrop-blur-sm animate-fade"
        onClick={onClose}
        aria-hidden
      />
      <aside className="relative h-full w-full max-w-md overflow-y-auto border-l border-line bg-ink-2/95 px-6 py-7 backdrop-blur-2xl animate-rise sm:px-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <Eyebrow>Methodology</Eyebrow>
            <h2 className="mt-2 font-display text-2xl text-cream">How the analysis works</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-full border border-line p-2 text-muted transition-colors hover:text-cream"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-7 space-y-6 text-[0.93rem] leading-relaxed text-muted">
          <p>
            Submissions are analyzed in memory by the PhishShield AI API. Inputs are never stored,
            persisted, or shared.
          </p>
          <div className="space-y-4">
            {[
              {
                t: "Language signals",
                d: "A curated rule set matches the persuasion patterns used in phishing: urgency, intimidation, credential requests, payment lures and secrecy.",
              },
              {
                t: "Link forensics",
                d: "Each link is decomposed into host, registrable domain, path and scheme, then checked for look-alike spelling, punycode, raw IPs, abusive extensions and credential-themed paths.",
              },
              {
                t: "Sender consistency",
                d: "For emails, the display name, sending domain and reply-to address are cross-checked against the brand the message claims to represent.",
              },
              {
                t: "Risk scoring",
                d: "Matched signals are weighted and combined with diminishing returns, producing a 0–100 score. Thresholds translate that score into low, suspicious or high risk.",
              },
            ].map((item) => (
              <div key={item.t} className="rounded-2xl border border-line-soft bg-white/[0.02] p-4">
                <p className="font-display text-[0.98rem] text-cream">{item.t}</p>
                <p className="mt-1.5 text-[0.88rem] leading-relaxed">{item.d}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-10">
          <Eyebrow>Settings</Eyebrow>

          <div className="mt-5 space-y-6">
            <div>
              <p className="text-[0.95rem] text-cream">Detection sensitivity</p>
              <p className="mt-1 text-[0.85rem] text-muted">
                Strict lowers the thresholds so borderline content is flagged sooner.
              </p>
              <div className="mt-3 flex gap-1 rounded-full border border-line bg-white/[0.03] p-1">
                {(["balanced", "strict"] as const).map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => onUpdate({ sensitivity: s })}
                    className={cn(
                      "flex-1 rounded-full px-4 py-2 text-[0.85rem] font-medium capitalize transition-all",
                      settings.sensitivity === s
                        ? "bg-flame-gradient text-[#1B1011]"
                        : "text-muted hover:text-cream",
                    )}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between gap-6">
              <div>
                <p className="text-[0.95rem] text-cream">Keep scan history</p>
                <p className="mt-1 text-[0.85rem] text-muted">Stored locally on this device only.</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={settings.storeHistory}
                onClick={() => onUpdate({ storeHistory: !settings.storeHistory })}
                className={cn(
                  "relative h-7 w-12 shrink-0 rounded-full border transition-colors",
                  settings.storeHistory
                    ? "border-transparent bg-flame-gradient"
                    : "border-line bg-white/[0.06]",
                )}
              >
                <span
                  className={cn(
                    "absolute top-1/2 h-5 w-5 -translate-y-1/2 rounded-full bg-cream transition-all duration-300",
                    settings.storeHistory ? "left-6" : "left-1",
                  )}
                />
              </button>
            </div>

            <div className="flex items-center justify-between gap-6 border-t border-line-soft pt-6">
              <div>
                <p className="text-[0.95rem] text-cream">Stored scans</p>
                <p className="mt-1 text-[0.85rem] text-muted">{historyCount} on this device</p>
              </div>
              <Button variant="ghost" onClick={onClearHistory} disabled={!historyCount}>
                Clear all
              </Button>
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}

/* ── Shell ────────────────────────────────────────────────────── */

export function AppShell({
  view,
  onNavigate,
  settings,
  onUpdateSettings,
  onClearHistory,
  historyCount,
  children,
}: {
  view: View;
  onNavigate: (v: View) => void;
  settings: Settings;
  onUpdateSettings: (patch: Partial<Settings>) => void;
  onClearHistory: () => void;
  historyCount: number;
  children: ReactNode;
}) {
  const [drawer, setDrawer] = useState(false);

  return (
    <div className="relative min-h-screen">
      <Atmosphere />

      <header className="sticky top-0 z-40 border-b border-line-soft bg-ink/55 backdrop-blur-xl">
        <div className="mx-auto flex h-[4.5rem] w-full max-w-[82rem] items-center justify-between gap-4 px-5 sm:px-8">
          <Wordmark onClick={() => onNavigate("overview")} />
          <NavPill view={view} onNavigate={onNavigate} className="hidden md:flex" />
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setDrawer(true)}
              className="rounded-full border border-line px-4 py-2 text-[0.84rem] text-muted transition-colors hover:border-white/20 hover:text-cream"
            >
              Methodology
            </button>
            {view !== "scan" && (
              <Button className="hidden sm:inline-flex" onClick={() => onNavigate("scan")}>
                Start a Scan
              </Button>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[82rem] px-5 pb-36 pt-10 sm:px-8 sm:pt-14 md:pb-24">
        {children}
      </main>

      <footer className="mx-auto w-full max-w-[82rem] px-5 pb-28 sm:px-8 md:pb-12">
        <div className="flex flex-col gap-4 border-t border-line-soft pt-8 text-[0.84rem] text-muted sm:flex-row sm:items-center sm:justify-between">
          <p className="font-display tracking-[-0.02em] text-cream/80">PhishShield</p>
          <p className="max-w-md leading-relaxed">
            Analysis is processed securely in memory by PhishShield AI API. Nothing you paste is stored on a server.
          </p>
          <button
            type="button"
            onClick={() => setDrawer(true)}
            className="self-start text-left transition-colors hover:text-cream sm:self-auto"
          >
            Methodology &amp; settings
          </button>
        </div>
      </footer>

      <div
        className="fixed inset-x-0 bottom-0 z-40 flex justify-center px-5 pb-5 md:hidden"
        style={{ paddingBottom: "calc(1.25rem + env(safe-area-inset-bottom))" }}
      >
        <NavPill
          view={view}
          onNavigate={onNavigate}
          fill
          className="w-full max-w-sm bg-ink-2/90 shadow-[0_18px_50px_-20px_rgba(0,0,0,0.9)]"
        />
      </div>

      <Drawer
        open={drawer}
        onClose={() => setDrawer(false)}
        settings={settings}
        onUpdate={onUpdateSettings}
        onClearHistory={onClearHistory}
        historyCount={historyCount}
      />
    </div>
  );
}
