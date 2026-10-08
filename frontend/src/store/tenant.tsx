import * as React from "react";
import { api } from "@/api/client";
import type { Tenant } from "@/types";

interface TenantContextValue {
  tenants: Tenant[];
  activeTenant: Tenant | undefined;
  setActiveTenant: (id: string) => void;
  refreshTenants: () => Promise<void>;
  loading: boolean;
}

const TenantContext = React.createContext<TenantContextValue | null>(null);
const STORAGE_KEY = "rtm.activeTenantId";

export function TenantProvider({ children }: { children: React.ReactNode }) {
  const [tenants, setTenants] = React.useState<Tenant[]>([]);
  const [activeId, setActiveId] = React.useState<string | null>(
    () => localStorage.getItem(STORAGE_KEY),
  );
  const [loading, setLoading] = React.useState(true);

  const refreshTenants = React.useCallback(async () => {
    try {
      const list = await api.tenants.list();
      setTenants(list);
      setActiveId((cur) => cur ?? list[0]?.id ?? null);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    refreshTenants();
  }, [refreshTenants]);

  React.useEffect(() => {
    if (activeId) localStorage.setItem(STORAGE_KEY, activeId);
  }, [activeId]);

  React.useEffect(() => {
    if (activeId && tenants.length > 0 && !tenants.some((t) => t.id === activeId)) {
      setActiveId(tenants[0]?.id ?? null);
    }
  }, [activeId, tenants]);

  React.useEffect(() => {
    if (!activeId) {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, [activeId]);

  const setActiveTenant = React.useCallback((id: string) => {
    setActiveId(id);
  }, []);

  const activeTenant = tenants.find((t) => t.id === activeId) ?? tenants[0];

  return (
    <TenantContext.Provider
      value={{ tenants, activeTenant, setActiveTenant, refreshTenants, loading }}
    >
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const ctx = React.useContext(TenantContext);
  if (!ctx) throw new Error("useTenant must be used within TenantProvider");
  return ctx;
}
