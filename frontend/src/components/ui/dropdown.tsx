import * as React from "react";
import { cn } from "@/lib/utils";

/** Lightweight click-dropdown: a trigger that toggles a `pop` menu below it. */
export function Dropdown({
  trigger,
  children,
  align = "start",
  side = "bottom",
  menuClassName,
}: {
  trigger: (props: { open: boolean; toggle: () => void }) => React.ReactNode;
  children: (close: () => void) => React.ReactNode;
  align?: "start" | "end";
  side?: "bottom" | "top";
  menuClassName?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      {trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open && (
        <div
          className={cn(
            "animate-pop absolute z-40 min-w-[200px] overflow-hidden rounded-[10px] border border-[var(--border-strong)] bg-raised p-1 shadow-[0_14px_40px_rgba(0,0,0,.55)]",
            side === "top" ? "bottom-full mb-1.5" : "mt-1.5",
            align === "end" ? "right-0" : "left-0",
            menuClassName,
          )}
        >
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}

export function DropdownItem({
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        "flex w-full items-center gap-2.5 rounded-[7px] px-2.5 py-2 text-left text-[13px] text-body transition-colors hover:bg-white/5 hover:text-fg",
        className,
      )}
      {...props}
    />
  );
}
