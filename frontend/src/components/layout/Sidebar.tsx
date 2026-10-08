import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { KeyRound, LogOut, X } from "lucide-react";
import { NAV } from "./nav";
import { Logo } from "./Logo";
import { TenantSwitcher } from "./TenantSwitcher";
import { Avatar } from "@/components/common/Avatar";
import { Dropdown, DropdownItem } from "@/components/ui/dropdown";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useAuth } from "@/store/auth";
import { useSync } from "@/store/sync";
import { cn } from "@/lib/utils";
import { ChangePasswordDialog } from "@/features/auth/ChangePasswordDialog";

function isActive(pathname: string, to: string, match?: string[]) {
  if (pathname === to) return true;
  if (to !== "/" && pathname.startsWith(to + "/")) return true;
  return match?.some((m) => pathname.startsWith(m)) ?? false;
}

export function Sidebar({
  className,
  onClose,
}: {
  className?: string;
  onClose?: () => void;
}) {
  const { pathname } = useLocation();
  const { user, logout } = useAuth();
  const { version: syncVersion } = useSync();
  const jobs = useAsync(() => api.jobs.list(), [syncVersion]);
  const jobAlerts = (jobs.data ?? []).filter((j) => ["Failed", "Partial"].includes(j.status) && !j.acknowledged).length;
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);

  return (
    <>
    <aside
      aria-label="Primary navigation"
      className={cn(
        "flex h-full w-[250px] shrink-0 flex-col border-r border-[var(--border-chrome)] bg-sidebar",
        className,
      )}
    >
      <div className="flex items-center justify-between px-4 py-4">
        <Logo />
        {onClose && (
          <button
            type="button"
            autoFocus
            aria-label="Close navigation"
            onClick={onClose}
            className="grid size-9 place-items-center rounded-[8px] text-muted transition-colors hover:bg-white/[.05] hover:text-fg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ac)]"
          >
            <X className="size-4" />
          </button>
        )}
      </div>

      <div className="px-3 pb-2">
        <TenantSwitcher />
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-2">
        {NAV.map((section, si) => (
          <div key={si} className={cn(section.label && "mt-4")}>
            {section.label && (
              <p className="mb-1.5 px-2.5 text-[10px] font-bold uppercase tracking-[.8px] text-faint-2">
                {section.label}
              </p>
            )}
            {section.items.map((item) => {
              const active = isActive(pathname, item.to, item.match);
              const Icon = item.icon;
              return (
                <Link
                  key={item.key}
                  to={item.to}
                  onClick={onClose}
                  className={cn(
                    "mt-0.5 flex items-center gap-[11px] rounded-[7px] border-l-2 px-2.5 py-2 text-[13px] transition-colors",
                    active
                      ? "border-[var(--ac)] bg-[var(--acb)] font-semibold text-[var(--act)]"
                      : "border-transparent font-medium text-body hover:bg-white/[.03] hover:text-fg",
                  )}
                >
                  <Icon
                    className="size-4 shrink-0"
                    style={{ color: active ? "var(--ac)" : "#7d7d87" }}
                  />
                  <span className="flex-1">{item.label}</span>
                  {(item.badge || (item.key === "jobs" && jobAlerts > 0)) && (
                    <span className="grid size-[18px] place-items-center rounded-full bg-[var(--ac)] text-[10px] font-bold text-white">
                      {item.key === "jobs" && jobAlerts > 0 ? jobAlerts : item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="border-t border-[var(--border-chrome)] p-3">
        <Dropdown
          side="top"
          menuClassName="w-[218px]"
          trigger={({ toggle }) => (
            <button
              onClick={toggle}
              className="flex w-full items-center gap-2.5 rounded-[8px] px-1.5 py-1.5 text-left transition-colors hover:bg-white/[.03]"
            >
              <Avatar name={user?.name ?? "RTM User"} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13px] font-semibold text-fg">
                  {user?.name ?? "RTM User"}
                </span>
                <span className="block truncate text-[11px] text-muted">
                  {user?.role ?? (user?.isAdmin ? "Admin" : "Technician")}
                </span>
              </span>
              <LogOut className="size-4 shrink-0 text-faint" />
            </button>
          )}
        >
          {(close) => (
            <>
              <DropdownItem
                onClick={() => {
                  close();
                  setChangePasswordOpen(true);
                }}
              >
                <KeyRound className="size-4" />
                Change password
              </DropdownItem>
              <DropdownItem
                onClick={() => {
                  close();
                  logout();
                }}
              >
                <LogOut className="size-4" />
                Sign out
              </DropdownItem>
            </>
          )}
        </Dropdown>
      </div>
    </aside>
    <ChangePasswordDialog open={changePasswordOpen} onClose={() => setChangePasswordOpen(false)} />
    </>
  );
}
