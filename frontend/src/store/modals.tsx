import * as React from "react";
import type { JobRef, WhatIfPreview, WorkingSet } from "@/types";

interface WorkingSetCtx {
  tenantId: string;
  tenant: string;
  userIds: string[];
  onSaved?: (workingSet: WorkingSet) => void;
}

/** A What-If gate instance: the computed preview plus the execute call that
 * fires when the operator approves. */
export interface WhatIfCtx {
  preview: WhatIfPreview;
  execute: () => Promise<JobRef>;
}

interface ModalsContextValue {
  whatIf: WhatIfCtx | null;
  openWhatIf: (ctx: WhatIfCtx) => void;
  closeWhatIf: () => void;
  workingSet: WorkingSetCtx | null;
  openWorkingSet: (ctx: WorkingSetCtx) => void;
  closeWorkingSet: () => void;
}

const ModalsContext = React.createContext<ModalsContextValue | null>(null);

/**
 * Centralizes the What-If preview + Save-as-Working-Set modals so any write
 * entry point opens the same mandatory gate. The preview is always computed
 * by the API from live tenant state — there is no canned fallback.
 */
export function ModalsProvider({ children }: { children: React.ReactNode }) {
  const [whatIf, setWhatIf] = React.useState<WhatIfCtx | null>(null);
  const [workingSet, setWorkingSet] = React.useState<WorkingSetCtx | null>(null);

  const value: ModalsContextValue = {
    whatIf,
    openWhatIf: setWhatIf,
    closeWhatIf: () => setWhatIf(null),
    workingSet,
    openWorkingSet: (ctx) => setWorkingSet(ctx),
    closeWorkingSet: () => setWorkingSet(null),
  };

  return (
    <ModalsContext.Provider value={value}>{children}</ModalsContext.Provider>
  );
}

export function useModals() {
  const ctx = React.useContext(ModalsContext);
  if (!ctx) throw new Error("useModals must be used within ModalsProvider");
  return ctx;
}
