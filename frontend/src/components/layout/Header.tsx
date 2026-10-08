import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Bell, Loader2, Menu, RefreshCw, Search } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { useTenant } from "@/store/tenant";
import { usePageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import type { TenantConnectionStatus } from "@/types";

const DOT: Record<TenantConnectionStatus, string> = {
  Connected: "var(--color-success)",
  Degraded: "var(--color-warning)",
  Disconnected: "var(--color-danger)",
};

/** 58px top bar — title · tenant context (always visible) · search · sync · 🔔 */
export function Header({
  mobileNavigationOpen,
  onOpenNavigation,
}: {
  mobileNavigationOpen: boolean;
  onOpenNavigation: () => void;
}) {
  const { activeTenant, refreshTenants } = useTenant();
  const { title } = usePageTitle();
  const { requestSync } = useSync();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [syncing, setSyncing] = useState(false);
  const [search, setSearch] = useState("");

  const status = activeTenant?.status ?? "Connected";
  const isSecurityOperations = ["/security", "/detection-rules", "/security-events"].includes(pathname) || pathname.startsWith("/offline-investigations");
  const isDocumentation = pathname === "/documentation";

  async function handleSync() {
    if (!activeTenant || syncing) return;
    setSyncing(true);
    try {
      await api.tenants.test(activeTenant.id);
      await refreshTenants();
      requestSync();
    } catch {
      requestSync();
    } finally {
      setSyncing(false);
    }
  }

  return (
    <header className="flex h-[58px] shrink-0 items-center gap-3 border-b border-[var(--border-chrome)] bg-header px-4 sm:gap-4 sm:px-6">
      <Button
        variant="default"
        size="icon"
        aria-label="Open navigation"
        aria-controls="mobile-navigation"
        aria-expanded={mobileNavigationOpen}
        className="shrink-0 md:hidden"
        onClick={onOpenNavigation}
      >
        <Menu className="size-4" />
      </Button>
      <div className="flex min-w-0 items-center gap-3">
        <h1 className="truncate text-[15.5px] font-bold text-fg-strong">{title}</h1>
        {isSecurityOperations ? (
          <div className="hidden min-w-0 items-center gap-1.5 border-l border-[var(--border-card)] pl-3 sm:flex">
            <span className="size-[7px] shrink-0 rounded-full bg-info" />
            <span className="truncate text-[12px] text-muted">
              All managed tenants · security source coverage
            </span>
          </div>
        ) : isDocumentation ? (
          <div className="hidden min-w-0 items-center gap-1.5 border-l border-[var(--border-card)] pl-3 sm:flex">
            <span className="size-[7px] shrink-0 rounded-full bg-info" />
            <span className="truncate text-[12px] text-muted">RTM operator handbook</span>
          </div>
        ) : activeTenant && (
          <div className="hidden min-w-0 items-center gap-1.5 border-l border-[var(--border-card)] pl-3 sm:flex">
            <span
              className="size-[7px] shrink-0 rounded-full"
              style={{ background: DOT[status] }}
            />
            <span className="truncate text-[12px] text-muted">
              {activeTenant.name}
            </span>
          </div>
        )}
      </div>

      <div className="ml-auto flex items-center gap-2.5">
        <div className="relative hidden md:block">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" />
          <input
            aria-label={isDocumentation ? "Search documentation" : "Search users"}
            placeholder={isDocumentation ? "Search documentation…" : "Search…"}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && search.trim()) {
                navigate(
                  isDocumentation
                    ? `/documentation?q=${encodeURIComponent(search.trim())}`
                    : `/users?q=${encodeURIComponent(search.trim())}`,
                );
                setSearch("");
              }
            }}
            className="h-9 w-[260px] rounded-[8px] border border-[var(--border-strong)] bg-control pl-9 pr-3 text-[13px] text-fg placeholder:text-muted outline-none transition-colors focus:border-[var(--ac)]/50"
          />
        </div>
        {!isSecurityOperations && !isDocumentation && (
          <Button variant="default" onClick={handleSync} disabled={syncing}>
            {syncing ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
            Sync
          </Button>
        )}
        <Button
          variant="default"
          size="icon"
          aria-label="Notifications"
          className="relative"
          onClick={() => navigate("/jobs")}
        >
          <Bell className="size-4" />
        </Button>
      </div>
    </header>
  );
}
