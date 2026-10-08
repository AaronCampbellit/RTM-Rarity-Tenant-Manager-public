import * as React from "react";

interface SyncContextValue {
  version: number;
  requestSync: () => void;
}
const SyncContext = React.createContext<SyncContextValue | null>(null);

export function SyncProvider({ children }: { children: React.ReactNode }) {
  const [version, setVersion] = React.useState(0);
  const requestSync = React.useCallback(() => {
    setVersion((v) => v + 1);
  }, []);

  return (
    <SyncContext.Provider value={{ version, requestSync }}>
      {children}
    </SyncContext.Provider>
  );
}

export function useSync() {
  const ctx = React.useContext(SyncContext);
  if (!ctx) throw new Error("useSync must be used within SyncProvider");
  return ctx;
}
