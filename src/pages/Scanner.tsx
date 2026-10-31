import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import type { ScanType } from "../types";
import { PLACEHOLDERS, SAMPLES } from "../lib/samples";
import { Button, Eyebrow } from "../components/ui";
import { cn } from "../utils/cn";

const TABS: { id: ScanType; label: string }[] = [
  { id: "message", label: "Message" },
  { id: "email", label: "Email" },
  { id: "url", label: "URL" },
];

const STAGES = ["Reading language patterns", "Decomposing links", "Weighing risk signals"];

export function Scanner({
  onAnalyse,
  initialType = "message",
}: {
  onAnalyse: (input: string, type: ScanType) => void;
  initialType?: ScanType;
}) {
  const [type, setType] = useState<ScanType>(initialType);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState(0);
  const timers = useRef<number[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const submit = () => {
    const input = value.trim();
    if (!input) {
      setError(`Paste ${type === "url" ? "a link" : "the content"} you want to inspect.`);
      return;
    }
    if (type === "url" && !/\.[a-z]{2,}/i.test(input) && !/^(https?|data|javascript):/i.test(input)) {
      setError("That does not look like a web address. Include the full link.");
      return;
    }
    setError(null);
    setBusy(true);
    setStage(0);
    timers.current = [
      window.setTimeout(() => setStage(1), 320),
      window.setTimeout(() => setStage(2), 640),
      window.setTimeout(() => {
        setBusy(false);
        onAnalyse(input, type);
      }, 950),
    ];
  };

  const switchTab = (next: ScanType) => {
    setType(next);
    setError(null);
  };

  return (
    <div className="mx-auto w-full max-w-3xl animate-rise">
      <div className="text-center">
        <Eyebrow>Threat inspection</Eyebrow>
        <h1 className="mx-auto mt-6 max-w-2xl font-display text-[2.5rem] font-semibold leading-[0.98] tracking-[-0.045em] text-cream sm:text-[3.6rem]">
          Check before <span className="text-gradient">you click.</span>
        </h1>
        <p className="mx-auto mt-6 max-w-xl text-[1rem] leading-[1.75] text-muted sm:text-[1.05rem]">
          Paste a suspicious message, email or URL to inspect potential threats.
        </p>
      </div>

      {/* Tabs */}
      <div className="mt-10 flex justify-center">
        <div className="flex w-full max-w-sm items-center gap-1 rounded-full border border-line bg-ink-2/70 p-1 backdrop-blur-xl">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => switchTab(tab.id)}
              className={cn(
                "flex-1 rounded-full px-4 py-2.5 text-[0.88rem] font-medium transition-all duration-300 outline-none focus-visible:focus-ring",
                type === tab.id
                  ? "bg-flame-gradient text-[#1B1011] shadow-[0_10px_26px_-14px_rgba(241,91,59,0.9)]"
                  : "text-muted hover:text-cream",
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input panel */}
      <section className="relative mt-8 overflow-hidden rounded-[30px] border border-line bg-card/70 p-6 backdrop-blur-xl sm:p-8">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-20 -top-28 h-64 w-64 rounded-full bg-flame/20 blur-[90px]"
        />
        <div className="absolute inset-x-0 top-0 h-px hairline-top opacity-70" />

        <div className="relative">
          {type === "url" ? (
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
              placeholder={PLACEHOLDERS.url}
              aria-label="URL to analyse"
              spellCheck={false}
              autoComplete="off"
              className="w-full border-none bg-transparent py-6 font-mono text-[0.98rem] text-cream outline-none placeholder:text-muted/60 sm:text-[1.05rem]"
            />
          ) : (
            <textarea
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={PLACEHOLDERS[type]}
              aria-label={type === "email" ? "Email content to analyse" : "Message to analyse"}
              spellCheck={false}
              rows={9}
              className="w-full resize-none border-none bg-transparent text-[1rem] leading-[1.8] text-cream outline-none placeholder:text-muted/60"
            />
          )}

          <div className="mt-6 flex flex-col gap-4 border-t border-line-soft pt-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-4 text-[0.82rem] text-muted">
              <button
                type="button"
                onClick={() => {
                  setValue(SAMPLES[type]);
                  setError(null);
                }}
                className="transition-colors hover:text-cream"
              >
                Load an example
              </button>
              {value.length > 0 && (
                <>
                  <span className="h-3 w-px bg-white/15" />
                  <button
                    type="button"
                    onClick={() => setValue("")}
                    className="transition-colors hover:text-cream"
                  >
                    Clear
                  </button>
                  <span className="hidden font-mono text-[0.76rem] text-muted/70 sm:inline">
                    {value.length} chars
                  </span>
                </>
              )}
            </div>

            <Button size="lg" onClick={submit} disabled={busy} className="w-full sm:w-auto">
              {busy ? "Analysing…" : "Analyse Threat"}
            </Button>
          </div>

          {error && <p className="mt-4 text-[0.86rem] text-danger">{error}</p>}

          {busy && (
            <div className="mt-6 animate-fade">
              <div className="relative h-[3px] w-full overflow-hidden rounded-full bg-white/[0.07]">
                <span className="absolute inset-y-0 w-1/3 rounded-full bg-flame-gradient animate-sweep" />
              </div>
              <p className="mt-3 font-mono text-[0.76rem] uppercase tracking-[0.18em] text-muted">
                {STAGES[stage]}
              </p>
            </div>
          )}
        </div>
      </section>

      <p className="mt-6 flex items-start justify-center gap-2.5 text-center text-[0.84rem] leading-relaxed text-muted">
        <ShieldCheck className="mt-[2px] h-4 w-4 shrink-0 text-peach/70" />
        <span>
          Everything is analysed locally in your browser. Your content is never uploaded or shared.
        </span>
      </p>
    </div>
  );
}
