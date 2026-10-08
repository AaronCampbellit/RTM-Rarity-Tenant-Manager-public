import { cn } from "@/lib/utils";

export interface TabItem {
  key: string;
  label: string;
}

/** Underline tabs (Admin Settings). Active tab = accent underline + fg text. */
export function UnderlineTabs({
  tabs,
  value,
  onChange,
}: {
  tabs: TabItem[];
  value: string;
  onChange: (key: string) => void;
}) {
  return (
    <div className="mb-5 flex gap-1 border-b border-[var(--border-card)]">
      {tabs.map((t) => {
        const active = t.key === value;
        return (
          <button
            key={t.key}
            onClick={() => onChange(t.key)}
            className={cn(
              "-mb-px border-b-2 px-3.5 py-2.5 text-[13px] font-semibold transition-colors",
              active
                ? "border-[var(--ac)] text-fg-strong"
                : "border-transparent text-muted hover:text-body",
            )}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

/** Pill tabs (Global Reports report-type selector). */
export function PillTabs({
  tabs,
  value,
  onChange,
}: {
  tabs: TabItem[];
  value: string;
  onChange: (key: string) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {tabs.map((t) => {
        const active = t.key === value;
        return (
          <button
            key={t.key}
            onClick={() => onChange(t.key)}
            className={cn(
              "rounded-[8px] border px-3.5 py-2 text-[12.5px] font-semibold transition-colors",
              active
                ? "border-[var(--ac)]/40 bg-[var(--acb)] text-[var(--act)]"
                : "border-[var(--border-strong)] bg-control text-body hover:bg-[#2b2b32]",
            )}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}
