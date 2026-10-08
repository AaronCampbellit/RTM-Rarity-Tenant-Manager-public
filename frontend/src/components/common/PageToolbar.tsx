import * as React from "react";
import { cn } from "@/lib/utils";

/** Row above a table: a count/label on the left, controls on the right. */
export function PageToolbar({
  count,
  children,
  className,
}: {
  count?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "mb-3.5 flex flex-wrap items-center justify-between gap-3",
        className,
      )}
    >
      {count != null ? (
        <span className="text-[13px] text-secondary">{count}</span>
      ) : (
        <span />
      )}
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}

/** Back link used by detail views (Tenant / Group Members / Change Detail). */
export function BackLink({
  children,
  onClick,
}: {
  children: React.ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-secondary transition-colors hover:text-fg"
    >
      <span aria-hidden>‹</span>
      {children}
    </button>
  );
}

export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="mb-2 text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">
      {children}
    </p>
  );
}
