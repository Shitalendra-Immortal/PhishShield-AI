import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { RiskLevel, ScanType, Severity } from "../types";
import { cn } from "../utils/cn";

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
        "group flex items-center gap-2.5 rounded-full outline-none transition-opacity hover:opacity-85 focus-visible:focus-ring",
        className,
      )}
      aria-label="PhishShield home"
    >
      <span className="relative flex h-7 w-7 items-center justify-center">
        <span className="absolute inset-0 rounded-[10px] bg-flame-gradient opacity-90 blur-[6px]" />
        <span className="absolute inset-0 rounded-[10px] bg-flame-gradient" />
        <span className="absolute inset-[6px] rounded-[4px] bg-ink/85" />
      </span>
      <span className="font-display text-[1.06rem] font-semibold tracking-[-0.035em] text-cream">
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
        "font-sans text-[0.68rem] font-medium uppercase tracking-[0.3em] text-muted",
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
        "relative inline-flex items-center justify-center gap-2 rounded-full font-sans font-medium outline-none transition-all duration-300 focus-visible:focus-ring disabled:cursor-not-allowed disabled:opacity-45",
        size === "lg" ? "px-7 py-3.5 text-[0.98rem]" : "px-5 py-2.5 text-[0.9rem]",
        variant === "primary" &&
          "bg-flame-gradient text-[#1B1011] shadow-[0_16px_38px_-18px_rgba(241,91,59,0.95)] hover:shadow-[0_22px_50px_-18px_rgba(241,91,59,1)] hover:brightness-[1.06] active:scale-[0.985]",
        variant === "ghost" &&
          "border border-line bg-white/[0.03] text-cream hover:border-white/20 hover:bg-white/[0.07]",
        variant === "quiet" && "text-muted hover:text-cream",
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
  glow,
}: {
  children: ReactNode;
  className?: string;
  glow?: boolean;
}) {
  return (
    <section
      className={cn(
        "relative overflow-hidden rounded-[28px] border border-line bg-card/60 backdrop-blur-xl",
        className,
      )}
    >
      {glow && (
        <div
          aria-hidden
          className="pointer-events-none absolute -right-24 -top-32 h-72 w-72 rounded-full bg-flame/25 blur-[90px]"
        />
      )}
      <div className="relative">{children}</div>
    </section>
  );
}

/* ── Risk semantics ───────────────────────────────────────────── */

export const RISK_STYLES: Record<
  RiskLevel,
  { label: string; text: string; bg: string; border: string; dot: string; bar: string }
> = {
  low: {
    label: "Low risk",
    text: "text-safe",
    bg: "bg-safe/10",
    border: "border-safe/25",
    dot: "bg-safe",
    bar: "from-safe/80 to-safe/40",
  },
  suspicious: {
    label: "Suspicious",
    text: "text-warn",
    bg: "bg-warn/10",
    border: "border-warn/25",
    dot: "bg-warn",
    bar: "from-warn to-peach",
  },
  high: {
    label: "High risk",
    text: "text-danger",
    bg: "bg-danger/12",
    border: "border-danger/30",
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
  const s = RISK_STYLES[level];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[0.72rem] font-medium tracking-wide",
        s.bg,
        s.border,
        s.text,
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} />
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
