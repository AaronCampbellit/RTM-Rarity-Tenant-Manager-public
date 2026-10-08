import * as React from "react";
import { cn } from "@/lib/utils";
import type { StatusTone } from "@/types";

/** Tone → text color + tint background, from the design token table. */
const TONE: Record<StatusTone, { color: string; bg: string }> = {
  success: { color: "#56d364", bg: "rgba(63,185,80,.13)" },
  danger: { color: "#f7868a", bg: "rgba(229,72,77,.15)" },
  warning: { color: "#e3b341", bg: "rgba(210,161,6,.15)" },
  info: { color: "#79a8ff", bg: "rgba(91,141,239,.15)" },
  neutral: { color: "#a2a2ab", bg: "rgba(255,255,255,.07)" },
};

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: StatusTone;
  /** Show a leading status dot (default true). */
  dot?: boolean;
}

/** Status pill: colored dot + label on a tinted background (radius 5px). */
export function Badge({
  tone = "neutral",
  dot = true,
  className,
  children,
  ...props
}: BadgeProps) {
  const t = TONE[tone];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-[5px] px-2 py-[3px] text-[11.5px] font-semibold leading-none whitespace-nowrap",
        className,
      )}
      style={{ color: t.color, background: t.bg }}
      {...props}
    >
      {dot && (
        <span
          className="size-[6px] rounded-full"
          style={{ background: t.color }}
        />
      )}
      {children}
    </span>
  );
}

export { TONE };
