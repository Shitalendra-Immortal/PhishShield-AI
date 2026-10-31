import { useEffect, useState } from "react";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import type { ScanResult } from "../types";
import { Button, RiskPill, TYPE_LABEL, formatDate, preview } from "../components/ui";
import { LiquidButton } from "../components/LiquidButton";
import { useShouldReduceMotion } from "@animate-ui/react/utils/motion";

const TRANSLATIONS = ["Scams.", "धोखों\u200A", "ਠੱਗੀਆਂ\u200A"] as const;

function TypewriterWord() {
  const reduce = useShouldReduceMotion();
  const [wordIdx, setWordIdx] = useState(0);

  useEffect(() => {
    if (reduce) return;
    const interval = setInterval(() => {
      setWordIdx((prev) => (prev + 1) % TRANSLATIONS.length);
    }, 3200);
    return () => clearInterval(interval);
  }, [reduce]);

  if (reduce) {
    return (
        <span className="inline-block pt-[0.2em] pb-[0.3em] pr-[0.35em] -mt-[0.2em] -mb-[0.3em] align-baseline text-gradient leading-none">
          {TRANSLATIONS[0]}
        </span>
        );
  }

        const currentWord = TRANSLATIONS[wordIdx];

        return (
        <span
          className="relative inline-grid items-baseline align-baseline overflow-visible leading-none pr-1"
          style={{
            fontFamily:
              'var(--font-display), "Mukta", "Nirmala UI", "Noto Sans Devanagari", "Noto Sans Gurmukhi", sans-serif',
          }}
        >
          {/* Invisible reserve words for 0 layout shift */}
          {TRANSLATIONS.map((w) => (
            <span
              key={w}
              aria-hidden="true"
              className="invisible select-none [grid-area:1/1] inline-block pt-[0.2em] pb-[0.3em] pr-[0.35em] -mt-[0.2em] -mb-[0.3em] align-baseline text-gradient leading-none"
            >
              {w}
            </span>
          ))}
            <span className="[grid-area:1/1] inline-grid items-baseline overflow-visible leading-none">
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={currentWord}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{
                    opacity: 1,
                    y: 0,
                    transition: { duration: 0.45, ease: [0.16, 1, 0.3, 1] },
                  }}
                  exit={{
                    opacity: 0,
                    y: -10,
                    transition: { duration: 0.3, ease: [0.16, 1, 0.3, 1] },
                  }}
                  style={{ willChange: "transform, opacity" }}
                  className="[grid-area:1/1] inline-block pt-[0.2em] pb-[0.3em] pr-[0.35em] -mt-[0.2em] -mb-[0.3em] align-baseline text-gradient overflow-visible leading-none"
                >
                  {currentWord}
                </motion.span>
              </AnimatePresence>
            </span>
          </span>
          );
}

          /* ── Purposeful Cybersecurity Visual (Clean geometric, no excessive glow) ── */

          function HeroComposition() {
  return (
          <div
            aria-hidden
            className="pointer-events-none flex items-center justify-center select-none"
          >
            <svg
              className="relative h-[22rem] w-[22rem] lg:h-[26rem] lg:w-[26rem] xl:h-[30rem] xl:w-[30rem] select-none text-cream"
              viewBox="0 0 360 360"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <defs>
                {/* Torch light blur filter - soft ethereal glow */}
                <filter id="torchGlow" x="-30%" y="-30%" width="160%" height="160%">
                  <feGaussianBlur stdDeviation="4.5" result="blur" />
                </filter>

                {/* Torch radial gradient: very soft, light, translucent falloff */}
                <radialGradient
                  id="torchGrad"
                  cx="180"
                  cy="180"
                  r="145"
                  gradientUnits="userSpaceOnUse"
                >
                  <stop offset="0%" stopColor="var(--hero-torch-beam)" stopOpacity="0.22" />
                  <stop offset="45%" stopColor="var(--hero-torch-beam)" stopOpacity="0.08" />
                  <stop offset="100%" stopColor="var(--hero-torch-beam)" stopOpacity="0" />
                </radialGradient>

                <linearGradient id="shieldGrad" x1="180" y1="110" x2="180" y2="250" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="var(--hero-shield-stroke-1)" stopOpacity="0.9" />
                  <stop offset="60%" stopColor="var(--hero-shield-stroke-2)" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="var(--hero-shield-stroke-1)" stopOpacity="0.25" />
                </linearGradient>
                <linearGradient id="shieldFill" x1="180" y1="110" x2="180" y2="250" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="var(--hero-shield-fill-1)" />
                  <stop offset="100%" stopColor="var(--hero-shield-fill-2)" />
                </linearGradient>
              </defs>

              {/* Concentric scanning rings */}
              <circle cx="180" cy="180" r="160" stroke="var(--hero-ring-subtle)" strokeWidth="1" strokeDasharray="3 9" />
              <circle cx="180" cy="180" r="130" stroke="var(--hero-ring-mid)" strokeWidth="1" />
              <circle cx="180" cy="180" r="95" stroke="var(--hero-ring-brand)" strokeWidth="1" strokeDasharray="5 5" />
              <circle cx="180" cy="180" r="62" stroke="var(--hero-ring-inner)" strokeWidth="1" />

              {/* Reticle / coordinate axis markers */}
              <line x1="180" y1="14" x2="180" y2="26" stroke="var(--hero-reticle)" strokeWidth="1.5" />
              <line x1="180" y1="334" x2="180" y2="346" stroke="var(--hero-reticle)" strokeWidth="1.5" />
              <line x1="14" y1="180" x2="26" y2="180" stroke="var(--hero-reticle)" strokeWidth="1.5" />
              <line x1="334" y1="180" x2="346" y2="180" stroke="var(--hero-reticle)" strokeWidth="1.5" />

              {/* Torch light beam: seamless, soft, volumetric light cone with no hard edges or dark lines */}
              <g
                style={{ transformOrigin: "180px 180px" }}
                className="animate-[spin_14s_linear_infinite]"
              >
                {/* Soft blurred volumetric torch haze */}
                <path
                  d="M 180 180 L 140 40.6 A 145 145 0 0 1 220 40.6 Z"
                  fill="url(#torchGrad)"
                  filter="url(#torchGlow)"
                />

                {/* Very light inner cone fill */}
                <path
                  d="M 180 180 L 140 40.6 A 145 145 0 0 1 220 40.6 Z"
                  fill="url(#torchGrad)"
                  opacity="0.6"
                />
              </g>

              {/* Outer subtle shield contour */}
              <path
                d="M180 114 L224 132 V182 C224 212 205 236 180 246 C155 236 136 212 136 182 V132 Z"
                fill="url(#shieldFill)"
                stroke="url(#shieldGrad)"
                strokeWidth="1.75"
              />

              {/* Inner shield geometry */}
              <path
                d="M180 128 L212 142 V181 C212 203 198 221 180 229 C162 221 148 203 148 181 V142 Z"
                stroke="var(--hero-shield-inner)"
                strokeWidth="1"
                strokeDasharray="2 3"
              />

              {/* Central security node with concentric radar echo */}
              <circle cx="180" cy="180" r="3.5" fill="var(--hero-node-core)" />
              <circle cx="180" cy="180" r="10" stroke="var(--hero-node-ring)" strokeWidth="1" />
              <circle cx="180" cy="180" r="18" stroke="var(--hero-node-ring)" strokeWidth="0.75" strokeDasharray="2 3" opacity="0.6" />
            </svg>
          </div>
          );
}

          /* ── Metrics ─────────────────────────────────────────────────── */

          function Stat({value, label}: {value: number; label: string }) {
  return (
          <div className="px-6 py-6 sm:px-8 sm:py-7 lg:px-10 lg:py-8">
            <p className="font-mono text-[2.4rem] font-semibold leading-none tracking-tight text-cream tabular-nums sm:text-[3rem] lg:text-[3.4rem]">
              {value}
            </p>
            <p className="mt-2.5 font-sans text-[0.88rem] font-medium text-muted sm:text-[0.94rem]">{label}</p>
          </div>
          );
}

          /* ── Overview Dashboard ───────────────────────────────────────── */

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
  const threats = history.filter((s) => s.level === "phishing" || s.level === "high").length;
  const safe = history.filter((s) => s.level === "safe" || s.level === "low").length;
          const recent = history.slice(0, 5);

          return (
          <div className="space-y-8 sm:space-y-10">
            {/* Hero Section: 20px radius hero container, solid tonal surface */}
            <section className="relative overflow-hidden rounded-[20px] border border-line bg-surface animate-rise">
              <div className="grid grid-cols-1 items-center gap-10 px-8 py-14 sm:px-12 sm:py-18 lg:grid-cols-12 lg:gap-12 lg:px-16 lg:py-24 xl:py-28">
                <div className="flex flex-col justify-center lg:col-span-7 xl:col-span-7 z-10">
                  <h1 className="font-display text-[2.6rem] font-semibold leading-[1.12] tracking-[-0.035em] text-cream sm:text-[3.4rem] lg:text-[4rem] xl:text-[4.4rem]">
                    Stay ahead of
                    <br />
                    <span className="inline-flex items-baseline whitespace-nowrap">
                      <span className="text-gradient mr-[0.26em]">digital</span>
                      <TypewriterWord />
                    </span>
                  </h1>
                  <p className="mt-5 max-w-xl font-sans text-[1.04rem] leading-[1.7] text-muted sm:text-[1.16rem] lg:text-[1.24rem] text-balance">
                    Analyse suspicious messages, emails and links
                    <br className="hidden sm:inline" />
                    {" "}before you interact with them.
                  </p>
                  <div className="mt-9 flex flex-wrap items-center gap-3">
                    <LiquidButton size="lg" onClick={() => onNavigate("scan")}>
                      Start a Scan
                      <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                    </LiquidButton>
                  </div>
                </div>

                <div className="hidden lg:flex lg:col-span-5 xl:col-span-5 items-center justify-center">
                  <HeroComposition />
                </div>
              </div>
            </section>

            {/* Statistics Section: 16px radius main card, solid tonal surface */}
            <section className="grid grid-cols-1 divide-y divide-line-soft overflow-hidden rounded-[16px] border border-line bg-surface sm:grid-cols-3 sm:divide-x sm:divide-y-0">
              <Stat value={total} label="Total scans" />
              <Stat value={threats} label="Threats detected" />
              <Stat value={safe} label="Low-risk messages" />
            </section>

            {/* Recent Activity Section: 16px radius main card, solid tonal surface */}
            <section className="overflow-hidden rounded-[16px] border border-line bg-surface">
              <div className="flex items-center justify-between gap-4 px-6 py-4 sm:px-8 border-b border-line-soft">
                <h2 className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
                  Recent activity
                </h2>
                {total > 0 && (
                  <button
                    type="button"
                    onClick={() => onNavigate("history")}
                    className="inline-flex items-center gap-1 font-sans text-[0.84rem] text-muted transition-colors hover:text-cream focus-visible:focus-ring rounded-[6px]"
                  >
                    All scans
                    <ArrowUpRight className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>

              {recent.length === 0 ? (
                <div className="px-6 py-8 text-center sm:px-8 sm:py-10">
                  <p className="font-display text-[1.12rem] font-semibold tracking-[-0.02em] text-cream">
                    Nothing analysed yet.
                  </p>
                  <p className="mx-auto mt-2 max-w-sm font-sans text-[0.88rem] leading-relaxed text-muted">
                    Paste a message, email or link and PhishShield will tell you what it finds.
                  </p>
                  <Button className="mt-5" onClick={() => onNavigate("scan")}>
                    Start a Scan
                  </Button>
                </div>
              ) : (
                <ul>
                  {recent.map((scan) => (
                    <li key={scan.id}>
                      <button
                        type="button"
                        onClick={() => onOpenScan(scan)}
                        className="group flex w-full items-center gap-4 border-b border-line-soft px-6 py-3.5 text-left transition-colors last:border-b-0 hover:bg-interactive/40 sm:px-8 focus-visible:focus-ring"
                      >
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-sans text-[0.92rem] text-cream/90 group-hover:text-cream">
                            {preview(scan.input, 90)}
                          </span>
                          <span className="mt-0.5 block font-sans text-[0.76rem] text-muted">
                            {TYPE_LABEL[scan.type]} · {formatDate(scan.createdAt)}
                          </span>
                        </span>
                        <RiskPill level={scan.level} className="hidden sm:inline-flex" />
                        <span className="w-12 shrink-0 text-right font-mono text-[0.88rem] text-cream tabular-nums font-semibold">
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
