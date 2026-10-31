"use client";

import * as React from "react";
import { motion, type HTMLMotionProps, type Transition } from "motion/react";

import { Slot, type WithAsChild } from "@animate-ui/react/primitives/slot";
import {
  motionTokens,
  ReducedMotionConfig,
  useShouldReduceMotion,
  useTempoTransition,
} from "@animate-ui/react/utils/motion";
import { cn } from "../utils/cn";

const HOVER_TRANSITION: Transition = {
  transform: { duration: 0.3, ease: "easeOut" },
  "--liquid-button-fill-width": { duration: 0 },
  "--liquid-button-fill-height": { duration: 0 },
  "--liquid-button-delay": { duration: 0 },
};

const DEFAULT_TRANSITION: Transition = {
  transform: motionTokens.spring.press,
  default: { duration: 0.3, ease: [0.25, 0.1, 0.35, 1] },
};

type LiquidButtonProps = WithAsChild<
  HTMLMotionProps<"button"> & {
    delay?: string;
    fillHeight?: string;
    hoverScale?: number;
    tapScale?: number;
    variant?: "primary" | "flame" | "dark" | "default";
    size?: "md" | "lg";
  }
>;

function LiquidButton(props: LiquidButtonProps) {
  return (
    <ReducedMotionConfig>
      <LiquidButtonContent {...props} />
    </ReducedMotionConfig>
  );
}

const variantStyles: Record<string, string> = {
  primary:
    "[--liquid-button-bg:linear-gradient(135deg,#f15b3b_0%,#ff874c_100%)] [--liquid-button-color:#d94420] text-[#faf8f5] hover:text-white shadow-sm font-semibold",
  flame:
    "[--liquid-button-bg:linear-gradient(135deg,#f15b3b_0%,#ff874c_100%)] [--liquid-button-color:#b9300e] text-[#faf8f5] hover:text-white shadow-sm font-semibold",
  dark:
    "[--liquid-button-background-color:#181615] [--liquid-button-color:#ff7550] text-[#faf8f5] hover:text-[#141211] border border-line font-medium",
  default:
    "[--liquid-button-background-color:var(--color-elevated)] [--liquid-button-color:var(--color-flame)] text-cream hover:text-[#141211] border border-line font-medium",
};

function LiquidButtonContent({
  delay = "0.3s",
  fillHeight = "3px",
  hoverScale = 1,
  tapScale = motionTokens.scale.press,
  asChild = false,
  variant = "primary",
  size = "md",
  transition,
  style,
  className,
  children,
  ...props
}: LiquidButtonProps) {
  const reduce = useShouldReduceMotion();
  const hoverTransition = useTempoTransition(HOVER_TRANSITION);
  const defaultTransition = useTempoTransition(DEFAULT_TRANSITION);
  const Component = asChild ? Slot : motion.button;

  return (
    <Component
      initial={reduce ? undefined : { transform: "scale(1)" }}
      whileTap={reduce ? undefined : { transform: `scale(${tapScale})` }}
      whileHover={{
        ...(reduce || hoverScale === 1
          ? null
          : { transform: `scale(${hoverScale})` }),
        "--liquid-button-fill-width": "100%",
        "--liquid-button-fill-height": "100%",
        "--liquid-button-delay": delay,
        transition: hoverTransition,
      }}
      transition={transition ?? defaultTransition}
      data-slot="liquid-button"
      className={cn(
        "group relative inline-flex items-center justify-center gap-2 overflow-hidden rounded-[12px] font-sans outline-none cursor-pointer select-none transition-colors duration-200 focus-visible:focus-ring disabled:pointer-events-none disabled:opacity-50",
        size === "lg" ? "px-5 py-2.5 text-[0.92rem]" : "px-4 py-2 text-[0.85rem]",
        variantStyles[variant],
        className
      )}
      style={
        {
          "--liquid-button-fill-width": "-1%",
          "--liquid-button-fill-height": fillHeight,
          "--liquid-button-delay": "0s",
          background:
            "linear-gradient(var(--liquid-button-color) 0 0) no-repeat calc(200% - var(--liquid-button-fill-width, -1%)) 100% / 200% var(--liquid-button-fill-height, 0.2em), var(--liquid-button-bg, var(--liquid-button-background-color))",
          backgroundColor: "var(--liquid-button-background-color, transparent)",
          transition: `background ${delay} var(--liquid-button-delay, 0s), color ${delay} ${delay}, background-position ${delay} calc(${delay} - var(--liquid-button-delay, 0s))`,
          ...style,
        } as React.CSSProperties
      }
      {...props}
    >
      {children}
    </Component>
  );
}

export { LiquidButton, type LiquidButtonProps };

