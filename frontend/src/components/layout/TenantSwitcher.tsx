import { Check, ChevronDown } from "lucide-react";
import { Dropdown, DropdownItem } from "@/components/ui/dropdown";
import { useTenant } from "@/store/tenant";
import { cn } from "@/lib/utils";
import type { TenantConnectionStatus } from "@/types";

const DOT: Record<TenantConnectionStatus, string> = {
  Connected: "#56d364",
  Degraded: "#e3b341",
  Disconnected: "#f7868a",
};

/** Sidebar tenant switcher — selecting a tenant scopes all tool screens. */
export function TenantSwitcher() {
  const { tenants, activeTenant, setActiveTenant } = useTenant();

  return (
    <Dropdown
      menuClassName="w-[218px] max-h-[340px] overflow-y-auto"
      trigger={({ toggle }) => (
        <button
          onClick={toggle}
          className="flex w-full items-center gap-2.5 rounded-[10px] border border-[var(--border-card)] bg-raised px-3 py-2.5 text-left transition-colors hover:bg-[#2b2b32]"
        >
          <span
            className="size-[9px] shrink-0 rounded-full"
            style={{ background: DOT[activeTenant?.status ?? "Connected"] }}
          />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px] font-semibold text-fg">
              {activeTenant?.name ?? "Select tenant"}
            </span>
            <span className="block truncate text-[11px] text-muted">
              {activeTenant?.domain ?? "—"}
            </span>
          </span>
          <ChevronDown className="size-4 shrink-0 text-faint" />
        </button>
      )}
    >
      {(close) =>
        tenants.map((t) => (
          <DropdownItem
            key={t.id}
            onClick={() => {
              setActiveTenant(t.id);
              close();
            }}
          >
            <span
              className="size-[8px] shrink-0 rounded-full"
              style={{ background: DOT[t.status] }}
            />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13px] text-body">{t.name}</span>
              <span className="block truncate text-[11px] text-muted">
                {t.users.toLocaleString()} users
              </span>
            </span>
            <Check
              className={cn(
                "size-4 shrink-0 text-[var(--ac)]",
                t.id === activeTenant?.id ? "opacity-100" : "opacity-0",
              )}
            />
          </DropdownItem>
        ))
      }
    </Dropdown>
  );
}
