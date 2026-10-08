import { Check, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

export interface CheckboxProps {
  checked: boolean;
  /** Indeterminate visual (header "some selected" state). */
  indeterminate?: boolean;
  onChange: () => void;
  className?: string;
  "aria-label"?: string;
}

export function Checkbox({
  checked,
  indeterminate,
  onChange,
  className,
  ...props
}: CheckboxProps) {
  const on = checked || indeterminate;
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? "mixed" : checked}
      onClick={(e) => {
        e.stopPropagation();
        onChange();
      }}
      className={cn(
        "grid size-[16px] place-items-center rounded-[4px] border transition-colors",
        on
          ? "border-[var(--ac)] bg-[var(--ac)] text-white"
          : "border-[var(--border-strong)] bg-control hover:border-white/25",
        className,
      )}
      {...props}
    >
      {indeterminate ? (
        <Minus className="size-3" strokeWidth={3} />
      ) : checked ? (
        <Check className="size-3" strokeWidth={3} />
      ) : null}
    </button>
  );
}
