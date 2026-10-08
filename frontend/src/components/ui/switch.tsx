import { cn } from "@/lib/utils";

export interface SwitchProps {
  checked: boolean;
  onChange?: () => void;
  disabled?: boolean;
  className?: string;
  ariaLabel?: string;
}

/** Toggle switch — accent track when on, grey when off (Admin App Settings). */
export function Switch({ checked, onChange, disabled, className, ariaLabel }: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={onChange}
      className={cn(
        "relative inline-flex h-[22px] w-[40px] shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-70",
        checked ? "bg-[var(--ac)]" : "bg-[#3a3a42]",
        className,
      )}
    >
      <span
        className={cn(
          "inline-block size-[16px] rounded-full bg-white shadow transition-transform",
          checked ? "translate-x-[21px]" : "translate-x-[3px]",
        )}
      />
    </button>
  );
}
