import { useEffect, useState, type ReactNode } from "react";
import { HelpCircle, Moon, Sun, X } from "lucide-react";
import { AnimatePresence, LayoutGroup, motion } from "motion/react";
import type { Settings } from "../types";
import { cn } from "../utils/cn";
import { Button, Eyebrow, ThreatIcon, Wordmark } from "./ui";

export type View = "overview" | "scan" | "history" | "result";

const NAV: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "scan", label: "Scan" },
  { id: "history", label: "History" },
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

/* ── Theme Toggle Component (Solid Tonal, no glowing border) ─── */

function ThemeToggle({
  theme,
  onToggle,
}: {
  theme: "dark" | "light";
  onToggle: () => void;
}) {
  const isDark = theme === "dark";

  return (
    <motion.button
      type="button"
      onClick={onToggle}
      whileTap={{ scale: 0.92 }}
      transition={SPRING_PRESS}
      className="relative flex h-8.5 w-8.5 items-center justify-center rounded-[10px] border border-line bg-elevated text-muted transition-colors hover:bg-interactive hover:text-cream outline-none focus:outline-none overflow-hidden"
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      title={isDark ? "Switch to light mode" : "Switch to dark mode"}
    >
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span
          key={theme}
          className="inline-flex items-center justify-center"
          initial={{ opacity: 0, rotate: -90, scale: 0.6 }}
          animate={{ opacity: 1, rotate: 0, scale: 1 }}
          exit={{ opacity: 0, rotate: 90, scale: 0.6 }}
          transition={{ duration: 0.22, ease: "easeOut" }}
        >
          {isDark ? (
            <Sun className="h-4 w-4 text-peach" />
          ) : (
            <Moon className="h-4 w-4 text-cream/90" />
          )}
        </motion.span>
      </AnimatePresence>
    </motion.button>
  );
}

/* ── Methodology / Help Button (Animated Question Mark Icon) ──── */

function HelpButton({ onClick }: { onClick: () => void }) {
  const [hovered, setHovered] = useState(false);

  return (
    <motion.button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      whileTap={{ scale: 0.92 }}
      transition={SPRING_PRESS}
      className="relative hidden sm:flex h-8.5 w-8.5 items-center justify-center rounded-[10px] border border-line bg-elevated text-muted transition-colors hover:bg-interactive hover:text-cream outline-none focus:outline-none overflow-hidden"
      aria-label="Settings"
      title="Settings"
    >
      <motion.span
        className="inline-flex items-center justify-center"
        animate={hovered ? { rotate: [0, -14, 12, -6, 0] } : { rotate: 0 }}
        transition={{ duration: 0.45, ease: "easeInOut" }}
      >
        <HelpCircle className="h-4 w-4" />
      </motion.span>
    </motion.button>
  );
}

/* ── Solid Tonal Background (Global gradients removed) ────────── */

function Atmosphere() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 -z-10 bg-ink"
    />
  );
}

/* ── Navigation (16px container radius, 10px item radius) ─────── */

function NavPill({
  view,
  onNavigate,
  className,
}: {
  view: View;
  onNavigate: (v: View) => void;
  className?: string;
}) {
  const active: View = view === "result" ? "scan" : view;

  return (
    <LayoutGroup id="nav-pill-group">
      <nav
        className={cn(
          "relative flex items-center gap-1 rounded-[16px] border border-line bg-surface p-1 shadow-sm",
          className,
        )}
      >
        {NAV.map((item) => {
          const isActive = active === item.id;
          return (
            <motion.button
              key={item.id}
              type="button"
              onClick={() => onNavigate(item.id)}
              whileTap={{ scale: 0.97 }}
              transition={SPRING_PRESS}
              aria-current={isActive ? "page" : undefined}
              className={cn(
                "relative rounded-[10px] px-3.5 py-1.5 text-[0.84rem] font-sans font-medium outline-none transition-colors duration-200 focus-visible:focus-ring sm:px-4 sm:py-1.5",
                isActive
                  ? "font-semibold text-[#faf8f5]"
                  : "text-muted hover:text-cream hover:bg-interactive/40",
              )}
            >
              {isActive && (
                <motion.span
                  layoutId="nav-pill-active"
                  className="absolute inset-0 rounded-[10px] bg-flame-gradient shadow-sm"
                  transition={SPRING_SELECTION}
                />
              )}
              <span className="relative z-10">{item.label}</span>
            </motion.button>
          );
        })}
      </nav>
    </LayoutGroup>
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
        className="absolute inset-0 bg-black/60 animate-fade"
        onClick={onClose}
        aria-hidden
      />
      <aside className="relative h-full w-full max-w-md overflow-y-auto border-l border-line bg-surface px-6 py-7 shadow-2xl animate-rise sm:px-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="font-display text-xl text-cream font-semibold">How It Works</h2>
            <p className="mt-1 text-[0.82rem] text-muted">
              Scanned securely in memory. Nothing is ever saved or shared.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-[10px] border border-line bg-elevated p-2 text-muted transition-colors hover:bg-interactive hover:text-cream focus-visible:focus-ring"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-5 space-y-2.5">
          {[
            {
              t: "Text Analysis",
              d: "Spots urgency, threats, fake deadlines, and password traps.",
            },
            {
              t: "Link Safety",
              d: "Detects hidden redirects, spoofed domains, and unsafe web addresses.",
            },
            {
              t: "Sender Check",
              d: "Checks whether sender email details match the real company.",
            },
            {
              t: "Risk Score",
              d: "Calculates an instant 0–100 score: Safe, Suspicious, or Phishing.",
            },
          ].map((item) => (
            <div key={item.t} className="rounded-[12px] border border-line-soft bg-elevated/70 px-3.5 py-2.5">
              <p className="font-sans text-[0.88rem] font-semibold text-cream">{item.t}</p>
              <p className="mt-0.5 text-[0.82rem] leading-snug text-muted">{item.d}</p>
            </div>
          ))}
        </div>

        <div className="mt-8 border-t border-line-soft pt-5">
          <p className="font-display text-[1.05rem] font-semibold text-cream">Settings</p>

          <div className="mt-4 space-y-4.5">
            {/* Theme switcher */}
            <div>
              <p className="font-sans text-[0.92rem] font-medium text-cream">Appearance</p>
              <p className="mt-0.5 text-[0.84rem] text-muted">
                Toggle between dark and light workspace theme.
              </p>
              <div className="mt-3 flex gap-1 rounded-[12px] border border-line bg-elevated p-1">
                {(["dark", "light"] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => onUpdate({ theme: t })}
                    className={cn(
                      "flex-1 rounded-[8px] px-3.5 py-1.5 text-[0.84rem] font-sans font-medium capitalize transition-all",
                      (settings.theme || "light") === t
                        ? "bg-flame-gradient font-semibold text-[#1B1011] shadow-sm"
                        : "text-muted hover:text-cream hover:bg-interactive/50",
                    )}
                  >
                    {t === "dark" ? "Dark Mode" : "Light Mode"}
                  </button>
                ))}
              </div>
            </div>

            {/* Sensitivity */}
            <div>
              <p className="font-sans text-[0.92rem] font-medium text-cream">Detection sensitivity</p>
              <p className="mt-0.5 text-[0.84rem] text-muted">
                Strict lowers the thresholds so borderline content is flagged sooner.
              </p>
              <div className="mt-3 flex gap-1 rounded-[12px] border border-line bg-elevated p-1">
                {(["balanced", "strict"] as const).map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => onUpdate({ sensitivity: s })}
                    className={cn(
                      "flex-1 rounded-[8px] px-3.5 py-1.5 text-[0.84rem] font-sans font-medium capitalize transition-all",
                      settings.sensitivity === s
                        ? "bg-flame-gradient font-semibold text-[#1B1011] shadow-sm"
                        : "text-muted hover:text-cream hover:bg-interactive/50",
                    )}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {/* History Toggle */}
            <div className="flex items-center justify-between gap-6">
              <div>
                <p className="font-sans text-[0.92rem] font-medium text-cream">Keep scan history</p>
                <p className="mt-0.5 text-[0.84rem] text-muted">Stored locally on this device only.</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={settings.storeHistory}
                onClick={() => onUpdate({ storeHistory: !settings.storeHistory })}
                className={cn(
                  "relative h-6.5 w-11 shrink-0 rounded-[10px] border transition-colors",
                  settings.storeHistory
                    ? "border-flame bg-flame-gradient"
                    : "border-line bg-interactive",
                )}
              >
                <span
                  className={cn(
                    "absolute top-1/2 h-4.5 w-4.5 -translate-y-1/2 rounded-[7px] bg-cream shadow-sm transition-all duration-200",
                    settings.storeHistory ? "left-5.5" : "left-1",
                  )}
                />
              </button>
            </div>

            <div className="flex items-center justify-between gap-6 border-t border-line-soft pt-6">
              <div>
                <p className="font-sans text-[0.92rem] font-medium text-cream">Stored scans</p>
                <p className="mt-0.5 text-[0.84rem] text-muted">{historyCount} on this device</p>
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
  const currentTheme = settings.theme || "light";

  const toggleTheme = () => {
    onUpdateSettings({ theme: currentTheme === "dark" ? "light" : "dark" });
  };

  return (
    <div className="relative min-h-screen bg-ink text-cream">
      <Atmosphere />

      {/* Top Navigation Bar with Frosted Glass Blur */}
      <header className="sticky top-0 z-40 border-b border-line bg-surface/80 backdrop-blur-md">
        <div className="relative mx-auto flex h-16 w-full max-w-[92rem] items-center justify-between px-4 sm:px-8">
          {/* Logo on the left */}
          <div className="flex items-center justify-start shrink-0 z-10 sm:w-48">
            <Wordmark onClick={() => onNavigate("overview")} />
          </div>

          {/* Primary Nav pinned strictly in the centre of the top bar */}
          <div className="absolute left-1/2 -translate-x-1/2 flex items-center justify-center">
            <NavPill view={view} onNavigate={onNavigate} />
          </div>

          {/* Secondary actions on the right */}
          <div className="flex items-center justify-end gap-2 shrink-0 z-10 sm:w-48">
            {/* Theme Toggle Button (Clean solid tonal, no glowing border) */}
            <ThemeToggle theme={currentTheme} onToggle={toggleTheme} />

            {/* Methodology & Help Button (Animated Question Mark Icon using Animate UI tokens) */}
            <HelpButton onClick={() => setDrawer(true)} />
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="mx-auto w-full max-w-[92rem] px-4 pt-6 pb-10 sm:px-8 sm:pt-8 sm:pb-12">
        {children}
      </main>

      {/* Footer */}
      <footer className="mx-auto w-full max-w-[92rem] px-4 pb-8 sm:px-8 sm:pb-10">
        <div className="flex flex-col gap-4 border-t border-line-soft pt-6 text-[0.84rem] text-muted sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <ThreatIcon className="h-5 w-5 shrink-0" />
            <p className="font-brand font-semibold tracking-[-0.02em] text-cream">PhishShield</p>
          </div>
          <p className="max-w-md leading-relaxed text-muted">
            Analysis is processed securely in memory via the PhishShield API. Submissions are never stored or logged.
          </p>
          <button
            type="button"
            onClick={() => setDrawer(true)}
            className="self-start text-left font-sans text-muted transition-colors hover:text-cream sm:self-auto outline-none focus-visible:underline"
          >
            Settings
          </button>
        </div>
      </footer>

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
