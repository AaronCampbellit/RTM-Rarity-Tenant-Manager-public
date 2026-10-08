import * as React from "react";
import { Search } from "lucide-react";
import { cn } from "@/lib/utils";

export const Input = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement>
>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn(
      "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg placeholder:text-muted outline-none transition-colors focus:border-[var(--ac)]/50 focus:ring-1 focus:ring-[var(--ac)]/30",
      className,
    )}
    {...props}
  />
));
Input.displayName = "Input";

/** Input with a leading search icon (used across toolbars). */
export const SearchInput = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement>
>(({ className, ...props }, ref) => (
  <div className={cn("relative", className)}>
    <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
    <input
      ref={ref}
      className="h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control pl-9 pr-3 text-[13px] text-fg placeholder:text-muted outline-none transition-colors focus:border-[var(--ac)]/50 focus:ring-1 focus:ring-[var(--ac)]/30"
      {...props}
    />
  </div>
));
SearchInput.displayName = "SearchInput";

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(
      "w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 py-2 text-[13px] text-fg placeholder:text-muted outline-none transition-colors focus:border-[var(--ac)]/50 focus:ring-1 focus:ring-[var(--ac)]/30",
      className,
    )}
    {...props}
  />
));
Textarea.displayName = "Textarea";
