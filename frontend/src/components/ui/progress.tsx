import { cn } from "@/lib/utils";

export interface ProgressProps {
  value: number;
  /** Override fill color (e.g. amber ≥85%, red ≥98% for license utilization). */
  color?: string;
  className?: string;
}

export function Progress({ value, color, className }: ProgressProps) {
  return (
    <div
      className={cn(
        "h-[6px] w-full overflow-hidden rounded-full bg-[#2b2b32]",
        className,
      )}
    >
      <div
        className="h-full rounded-full transition-[width]"
        style={{
          width: `${Math.min(100, Math.max(0, value))}%`,
          background: color ?? "var(--ac)",
        }}
      />
    </div>
  );
}

/** Utilization fill color thresholds, shared by Licensing + Jobs. */
export function utilColor(pct: number) {
  return pct >= 98 ? "#f7868a" : pct >= 85 ? "#e3b341" : "#56d364";
}
