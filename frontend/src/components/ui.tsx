import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { RiskLevel, ScanType, Severity } from "../types";
import { cn } from "../utils/cn";
import { ThreatIcon } from "./ThreatIcon";

export { ThreatIcon };

/* ── Brand wordmark ───────────────────────────────────────────── */

export function Wordmark({
  className,
  onClick,
}: {
  className?: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "group flex items-center gap-2 rounded-[10px] outline-none transition-opacity hover:opacity-85 focus-visible:focus-ring",
        className,
      )}
      aria-label="PhishShield home"
    >
      <ThreatIcon className="h-7 w-7 shrink-0 transition-transform group-hover:scale-105" />
      <span className="font-brand text-[1.14rem] font-semibold tracking-[-0.02em] text-cream hidden sm:inline">
        PhishShield
      </span>
    </button>
  );
}

/* ── Eyebrow label ────────────────────────────────────────────── */

export function Eyebrow({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <p
      className={cn(
        "font-sans text-[0.7rem] font-semibold uppercase tracking-[0.22em] text-muted",
        className,
      )}
    >
      {children}
    </p>
  );
}

/* ── Button ───────────────────────────────────────────────────── */

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "quiet";
  size?: "md" | "lg";
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      className={cn(
        "relative inline-flex items-center justify-center gap-2 rounded-[12px] font-sans font-medium outline-none transition-all duration-200 focus-visible:focus-ring disabled:cursor-not-allowed disabled:opacity-40",
        size === "lg" ? "px-5 py-2.5 text-[0.92rem]" : "px-4 py-2 text-[0.85rem]",
        variant === "primary" &&
          "bg-flame-gradient font-semibold text-[#1B1011] shadow-sm hover:brightness-[1.05] active:scale-[0.985]",
        variant === "ghost" &&
          "border border-line bg-elevated text-cream hover:bg-interactive hover:border-line",
        variant === "quiet" && "text-muted hover:text-cream hover:bg-interactive/50",
        className,
      )}
    >
      {children}
    </button>
  );
}

/* ── Surfaces ─────────────────────────────────────────────────── */

export function Panel({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
  glow?: boolean;
}) {
  return (
    <section
      className={cn(
        "relative overflow-hidden rounded-[16px] border border-line bg-card",
        className,
      )}
    >
      <div className="relative">{children}</div>
    </section>
  );
}

/* ── Risk semantics ───────────────────────────────────────────── */

export const RISK_STYLES: Record<
  RiskLevel,
  { label: string; text: string; bg: string; border: string; dot: string; bar: string }
> = {
  safe: {
    label: "Looks Safe",
    text: "text-safe",
    bg: "bg-safe/12",
    border: "border-safe/30",
    dot: "bg-safe",
    bar: "from-safe to-safe",
  },
  low: {
    label: "Looks Safe",
    text: "text-safe",
    bg: "bg-safe/12",
    border: "border-safe/30",
    dot: "bg-safe",
    bar: "from-safe to-safe",
  },
  suspicious: {
    label: "Suspicious",
    text: "text-warn",
    bg: "bg-warn/12",
    border: "border-warn/30",
    dot: "bg-warn",
    bar: "from-warn to-peach",
  },
  phishing: {
    label: "Likely Phishing",
    text: "text-danger",
    bg: "bg-danger/12",
    border: "border-danger/35",
    dot: "bg-danger",
    bar: "from-danger to-ember",
  },
  high: {
    label: "Likely Phishing",
    text: "text-danger",
    bg: "bg-danger/12",
    border: "border-danger/35",
    dot: "bg-danger",
    bar: "from-danger to-ember",
  },
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  info: "bg-muted",
  low: "bg-peach",
  medium: "bg-warn",
  high: "bg-danger",
};

export function RiskPill({ level, className }: { level: RiskLevel; className?: string }) {
  const s = RISK_STYLES[level] || RISK_STYLES.safe;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-[6px] border px-2.5 py-0.5 font-mono text-[0.72rem] font-medium tracking-wide",
        s.bg,
        s.border,
        s.text,
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", s.dot)} />
      {s.label}
    </span>
  );
}

/* ── Misc ─────────────────────────────────────────────────────── */

export const TYPE_LABEL: Record<ScanType, string> = {
  message: "Message",
  email: "Email",
  url: "URL",
};

export function formatDate(ts: number): string {
  return new Date(ts).toLocaleDateString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

export function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function preview(input: string, length = 72): string {
  const flat = input.replace(/\s+/g, " ").trim();
  return flat.length > length ? `${flat.slice(0, length)}…` : flat;
}
