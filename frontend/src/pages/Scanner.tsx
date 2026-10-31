import { useEffect, useRef, useState } from "react";
import { AlertCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { motion } from "motion/react";
import type { ScanType } from "../types";
import { PLACEHOLDERS } from "../lib/samples";
import { Button, Eyebrow } from "../components/ui";
import { cn } from "../utils/cn";

const TABS: { id: ScanType; label: string }[] = [
  { id: "message", label: "Message" },
  { id: "email", label: "Email" },
  { id: "url", label: "URL" },
];

const STAGES = [
  "Connecting to PhishShield API…",
  "Evaluating threat intelligence & forensics…",
  "Calculating normalized risk score…",
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

export function Scanner({
  onAnalyse,
  initialType = "message",
}: {
  onAnalyse: (input: string, type: ScanType) => Promise<void> | void;
  initialType?: ScanType;
}) {
  const [type, setType] = useState<ScanType>(initialType);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState(0);
  const timers = useRef<number[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const submit = async () => {
    const input = value.trim();
    if (!input) {
      setError(`Please paste or enter ${type === "url" ? "a link" : "the content"} you want to inspect.`);
      return;
    }
    if (input.length > 5000) {
      setError("Input is too long (maximum 5,000 characters).");
      return;
    }
    if (type === "url" && !/\.[a-z]{2,}/i.test(input) && !/^(https?|data|javascript):/i.test(input)) {
      setError("That does not look like a valid web address. Include the full URL (e.g. https://example.com).");
      return;
    }

    setError(null);
    setBusy(true);
    setStage(0);

    const t1 = window.setTimeout(() => setStage(1), 350);
    const t2 = window.setTimeout(() => setStage(2), 700);
    timers.current = [t1, t2];

    try {
      await onAnalyse(input, type);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      const isNetworkError =
        msg.includes("Failed to fetch") ||
        msg.includes("network") ||
        msg.includes("Failed to connect") ||
        msg.includes("NetworkError");

      const userMessage = isNetworkError
        ? "Unable to reach PhishShield analysis service. The backend server may be waking up or temporarily unavailable. Please click Retry below."
        : msg;
      setError(userMessage);
    } finally {
      timers.current.forEach(clearTimeout);
      setBusy(false);
    }
  };

  const switchTab = (next: ScanType) => {
    setType(next);
    setError(null);
  };

  return (
    <div className="mx-auto w-full max-w-3xl animate-rise">
      <div className="text-center">
        <Eyebrow>Threat inspection</Eyebrow>
        <h1 className="mx-auto mt-4 max-w-2xl font-display text-[2.4rem] font-semibold leading-[1.08] tracking-[-0.035em] text-cream sm:text-[3.2rem]">
          Check before <span className="text-gradient">you click.</span>
        </h1>
        <p className="mx-auto mt-3 max-w-xl font-sans text-[0.96rem] leading-[1.7] text-muted sm:text-[1.02rem]">
          Paste a suspicious message, email or URL to inspect potential threats with live threat intelligence.
        </p>
      </div>

      {/* Tabs: 16px container radius, 10px tab item radius */}
      <div className="mt-8 flex justify-center">
        <div className="relative flex w-full max-w-sm items-center gap-1 rounded-[16px] border border-line bg-surface p-1 shadow-sm">
          {TABS.map((tab) => {
            const isActive = type === tab.id;
            return (
              <motion.button
                key={tab.id}
                type="button"
                onClick={() => switchTab(tab.id)}
                whileTap={{ scale: 0.97 }}
                transition={SPRING_PRESS}
                className={cn(
                  "relative flex-1 rounded-[10px] px-4 py-2 text-[0.84rem] font-sans font-medium outline-none transition-colors duration-200 focus-visible:focus-ring",
                  isActive
                    ? "font-semibold text-[#1B1011]"
                    : "text-muted hover:text-cream hover:bg-interactive/40",
                )}
              >
                {isActive && (
                  <motion.span
                    layoutId="scanner-tab-active"
                    className="absolute inset-0 rounded-[10px] bg-flame-gradient shadow-sm"
                    transition={SPRING_SELECTION}
                  />
                )}
                <span className="relative z-10">{tab.label}</span>
              </motion.button>
            );
          })}
        </div>
      </div>

      {/* Input panel: 16px radius main card, solid tonal surface */}
      <section
        className={cn(
          "relative mt-6 overflow-hidden rounded-[16px] border bg-surface p-6 transition-all sm:p-8",
          error ? "border-danger/40" : "border-line",
        )}
      >
        <div className="relative">
          {/* Input field: 10px radius */}
          {type === "url" ? (
            <div className="rounded-[10px] border border-line-soft bg-elevated/40 p-3 transition-colors focus-within:border-flame/70 focus-within:ring-1 focus-within:ring-flame/50">
              <input
                value={value}
                onChange={(e) => {
                  setValue(e.target.value);
                  if (error) setError(null);
                }}
                onKeyDown={(e) => e.key === "Enter" && submit()}
                placeholder={PLACEHOLDERS.url}
                aria-label="URL to analyse"
                spellCheck={false}
                autoComplete="off"
                disabled={busy}
                className="w-full border-none bg-transparent font-mono text-[0.98rem] text-cream outline-none placeholder:text-muted/60"
              />
            </div>
          ) : (
            <div className="rounded-[10px] border border-line-soft bg-elevated/40 p-3.5 transition-colors focus-within:border-flame/70 focus-within:ring-1 focus-within:ring-flame/50">
              <textarea
                value={value}
                onChange={(e) => {
                  setValue(e.target.value);
                  if (error) setError(null);
                }}
                placeholder={PLACEHOLDERS[type]}
                aria-label={type === "email" ? "Email content to analyse" : "Message to analyse"}
                spellCheck={false}
                rows={8}
                disabled={busy}
                className="w-full resize-none border-none bg-transparent font-sans text-[0.96rem] leading-[1.8] text-cream outline-none placeholder:text-muted/60"
              />
            </div>
          )}

          <div className="mt-6 flex flex-col gap-4 border-t border-line-soft pt-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-4 text-[0.84rem] text-muted">
              {value.length > 0 && (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      setValue("");
                      setError(null);
                    }}
                    className="font-sans transition-colors hover:text-cream focus-visible:focus-ring rounded-[6px]"
                  >
                    Clear
                  </button>
                  <span className="h-3 w-px bg-line" />
                  <span className="font-mono text-[0.8rem] text-muted">
                    {value.length} / 5000 chars
                  </span>
                </>
              )}
            </div>

            <Button size="lg" onClick={submit} disabled={busy} className="w-full sm:w-auto">
              {busy ? (
                <span className="flex items-center gap-2">
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  Analysing Threat…
                </span>
              ) : (
                "Analyse Threat"
              )}
            </Button>
          </div>

          {/* Error notification with Retry action */}
          {error && (
            <div className="mt-5 rounded-[10px] border border-danger/30 bg-danger/10 p-4 text-[0.88rem] text-[#FFB0A0] animate-fade">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
                  <div className="font-sans leading-relaxed text-cream/90">{error}</div>
                </div>
                <button
                  type="button"
                  onClick={submit}
                  disabled={busy}
                  className="shrink-0 inline-flex items-center gap-1.5 rounded-[8px] border border-danger/40 bg-danger/20 px-3 py-1 font-sans text-[0.8rem] font-semibold text-cream transition-colors hover:bg-danger/30 focus-visible:focus-ring"
                >
                  <RefreshCw className="h-3 w-3" />
                  Retry
                </button>
              </div>
            </div>
          )}

          {/* Scanning Progress & Animated Status */}
          {busy && (
            <div className="mt-6 rounded-[12px] border border-line-soft bg-elevated p-4 animate-fade">
              <div className="relative h-2 w-full overflow-hidden rounded-[6px] bg-interactive border border-line">
                <span className="absolute inset-y-0 w-2/5 rounded-[6px] bg-flame-gradient animate-sweep" />
              </div>
              <div className="mt-3 flex items-center justify-between">
                <p className="font-mono text-[0.8rem] uppercase tracking-[0.14em] text-cream flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-flame animate-pulse" />
                  {STAGES[stage]}
                </p>
                <span className="font-mono text-[0.76rem] text-muted">Step {stage + 1} of 3</span>
              </div>
            </div>
          )}
        </div>
      </section>

      <p className="mt-6 flex items-start justify-center gap-2.5 text-center font-sans text-[0.86rem] leading-relaxed text-muted">
        <ShieldCheck className="mt-[2px] h-4 w-4 shrink-0 text-peach" />
        <span>
          Analyzed in memory via PhishShield API. Inputs are never stored or logged.
        </span>
      </p>
    </div>
  );
}
