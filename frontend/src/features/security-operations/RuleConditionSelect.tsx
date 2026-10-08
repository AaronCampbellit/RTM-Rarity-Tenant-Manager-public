import { useMemo, useState } from "react";
import { Check, ChevronDown, Loader2, Search, X } from "lucide-react";
import { Dropdown } from "@/components/ui/dropdown";
import { cn } from "@/lib/utils";
import { filterRuleConditionOptions, mergeRuleConditionOptions } from "./securityRules";

export function RuleConditionSelect({
  label,
  values,
  options,
  placeholder,
  disabled = false,
  loading = false,
  onChange,
}: {
  label: string;
  values: string[];
  options: string[];
  placeholder: string;
  disabled?: boolean;
  loading?: boolean;
  onChange: (values: string[]) => void;
}) {
  const [query, setQuery] = useState("");
  const allOptions = useMemo(() => mergeRuleConditionOptions(options, values), [options, values]);
  const visibleOptions = useMemo(() => filterRuleConditionOptions(allOptions, query), [allOptions, query]);
  const selected = useMemo(() => new Set(values.map((value) => value.toLocaleLowerCase())), [values]);

  function toggle(value: string) {
    const key = value.toLocaleLowerCase();
    onChange(selected.has(key) ? values.filter((item) => item.toLocaleLowerCase() !== key) : [...values, value]);
  }

  const summary = values.length === 0
    ? placeholder
    : values.length <= 2
      ? values.join(", ")
      : `${values.slice(0, 2).join(", ")} +${values.length - 2}`;

  return (
    <Dropdown
      menuClassName="w-full min-w-0 p-0"
      trigger={({ open, toggle: toggleMenu }) => (
        <button
          type="button"
          aria-label={`${label}: ${values.length ? `${values.length} selected` : "none selected"}`}
          aria-expanded={open}
          disabled={disabled || loading}
          className={cn(
            "flex h-9 w-full items-center gap-2 rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-left text-[12.5px] outline-none transition-colors focus:border-[var(--ac)]/50 disabled:cursor-not-allowed disabled:opacity-55",
            values.length ? "text-body" : "text-faint",
          )}
          onClick={() => {
            if (!open) setQuery("");
            toggleMenu();
          }}
        >
          <span className="min-w-0 flex-1 truncate">{summary}</span>
          {loading ? <Loader2 className="size-3.5 shrink-0 animate-spin" /> : <ChevronDown className={cn("size-3.5 shrink-0 transition-transform", open && "rotate-180")} />}
        </button>
      )}
    >
      {() => (
        <div role="listbox" aria-label={`${label} options`} aria-multiselectable="true">
          <div className="relative border-b border-[var(--border-card)] p-2">
            <Search className="pointer-events-none absolute left-4 top-1/2 size-3.5 -translate-y-1/2 text-faint" />
            <input
              autoFocus
              aria-label={`Search ${label.toLocaleLowerCase()}`}
              className="h-8 w-full rounded-[7px] border border-[var(--border-strong)] bg-control pl-8 pr-3 text-[12px] text-body outline-none focus:border-[var(--ac)]/50"
              value={query}
              placeholder="Search available options…"
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="max-h-52 overflow-y-auto p-1">
            {visibleOptions.length ? visibleOptions.map((option) => {
              const checked = selected.has(option.toLocaleLowerCase());
              return (
                <button
                  key={option}
                  type="button"
                  role="option"
                  aria-selected={checked}
                  className="flex w-full items-center gap-2 rounded-[7px] px-2.5 py-2 text-left text-[12.5px] text-body hover:bg-white/5"
                  onClick={() => toggle(option)}
                >
                  <span className={cn("grid size-4 shrink-0 place-items-center rounded border", checked ? "border-[var(--ac)] bg-[var(--ac)] text-white" : "border-[var(--border-strong)]")}>
                    {checked && <Check className="size-3" />}
                  </span>
                  <span className="min-w-0 break-words">{option}</span>
                </button>
              );
            }) : <p className="px-3 py-5 text-center text-[12px] text-muted">No matching options</p>}
          </div>
          {values.length > 0 && (
            <div className="border-t border-[var(--border-card)] p-1">
              <button type="button" className="flex w-full items-center justify-center gap-1.5 rounded-[7px] px-2 py-1.5 text-[11.5px] text-muted hover:bg-white/5 hover:text-body" onClick={() => onChange([])}>
                <X className="size-3" /> Clear selected
              </button>
            </div>
          )}
        </div>
      )}
    </Dropdown>
  );
}
