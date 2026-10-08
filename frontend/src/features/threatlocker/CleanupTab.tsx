import { useMemo, useState } from "react";
import { AlertTriangle, Check, GitMerge, RefreshCw, ScanSearch, ShieldCheck, Sparkles } from "lucide-react";
import { api } from "@/api/client";
import { type RefreshingAsyncState, useRefreshingAsync } from "@/api/hooks";
import { loadSessionQuery } from "@/api/sessionQueryStore";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SearchInput } from "@/components/ui/input";
import type { TLAppCleanupCandidate, TLApplication } from "@/types";
import { AppCleanupDialog } from "./AppCleanupDialog";
import { cleanupStatusLabel, cleanupStatusTone } from "./cleanupLifecycle";
import { selectVisibleCleanupCandidates } from "./cleanupWorkflow";
import { threatLockerQueryKeys } from "./preload";

export function CleanupTab({
  apps,
}: {
  apps: RefreshingAsyncState<TLApplication[]>;
}) {
  const candidates = useRefreshingAsync(
    () => api.threatlocker.appCleanupCandidates(),
    [],
    { cacheKey: threatLockerQueryKeys.cleanupCandidates },
  );
  const operations = useRefreshingAsync(
    () => api.threatlocker.appCleanupOperations(),
    [],
    { cacheKey: threatLockerQueryKeys.cleanupOperations },
  );
  const [selectedId, setSelectedId] = useState("");
  const [query, setQuery] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [manualRefreshing, setManualRefreshing] = useState(false);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (candidates.data ?? []).filter((candidate) => {
      if (!needle) return true;
      return [candidate.name, candidate.os, ...candidate.applications.map((app) => `${app.name} ${app.organization}`)]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [candidates.data, query]);
  const selected = visible.find((candidate) => candidate.id === selectedId) ?? visible[0] ?? null;
  const displayedCandidates = selectVisibleCleanupCandidates(visible);
  const activeOperations = (operations.data ?? []).filter((operation) =>
    operation.status === "verification_pending" || operation.status === "needs_reconciliation",
  );
  const verifiedOperations = (operations.data ?? []).filter((operation) => operation.status === "verified");

  async function refreshAll() {
    setManualRefreshing(true);
    try {
      await loadSessionQuery(
        threatLockerQueryKeys.apps,
        () => api.threatlocker.apps(undefined, "", { refresh: true }),
        { force: true },
      );
      await Promise.all([
        loadSessionQuery(
          threatLockerQueryKeys.cleanupCandidates,
          () => api.threatlocker.appCleanupCandidates(),
          { force: true },
        ),
        loadSessionQuery(
          threatLockerQueryKeys.cleanupOperations,
          () => api.threatlocker.appCleanupOperations(),
          { force: true },
        ),
        loadSessionQuery(
          threatLockerQueryKeys.policies,
          () => api.threatlocker.policies(),
          { force: true },
        ),
      ]);
    } catch {
      // Session-query errors are rendered by the existing tab state.
    } finally {
      setManualRefreshing(false);
    }
  }

  return (
    <div className="space-y-4">
      <section className="overflow-hidden rounded-[12px] border border-[var(--border-card)] bg-card">
        <div className="grid gap-4 border-b border-[var(--border-card)] bg-gradient-to-br from-[var(--bg-raised)] to-card px-5 py-5 lg:grid-cols-[1fr_auto] lg:items-center">
          <div>
            <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[.8px] text-[var(--ac)]">
              <Sparkles className="size-3.5" />
              Guided application consolidation
            </div>
            <h2 className="mt-1.5 text-[20px] font-bold tracking-[-.3px] text-fg-strong">Clean up duplicate applications safely</h2>
            <p className="mt-1 max-w-3xl text-[12.5px] leading-5 text-muted">
              RTM ranks likely duplicate families, promotes a reviewed child policy when a parent target is missing,
              performs ThreatLocker&apos;s native merge, moves preserved policies to Global, and verifies every portal outcome.
            </p>
          </div>
          <Button variant="default" onClick={() => void refreshAll()} disabled={manualRefreshing || candidates.loading || operations.loading}>
            <RefreshCw className={`size-4 ${manualRefreshing || candidates.loading || operations.loading ? "animate-spin" : ""}`} />
            Refresh analysis
          </Button>
        </div>
        <div className="grid grid-cols-2 divide-x divide-[var(--border-card)] sm:grid-cols-4">
          <CleanupMetric label="Recommended groups" value={String(candidates.data?.length ?? 0)} detail="Ranked by safest first" />
          <CleanupMetric label="Parent ready" value={String((candidates.data ?? []).filter((item) => item.parentReady).length)} detail="Canonical app exists" />
          <CleanupMetric label="Needs verification" value={String(activeOperations.length)} detail="Portal re-check available" tone={activeOperations.length ? "warning" : "normal"} />
          <CleanupMetric label="Verified operations" value={String(verifiedOperations.length)} detail="All checks passed" tone="success" />
        </div>
      </section>

      {(candidates.error || operations.error) && (
        <div className="flex items-start gap-2 rounded-[9px] border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-[12px] text-red-300">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{(candidates.error ?? operations.error)?.message ?? "Unable to load cleanup analysis."}</span>
        </div>
      )}

      <section className="grid min-h-[540px] overflow-hidden rounded-[12px] border border-[var(--border-card)] bg-card lg:grid-cols-[360px_minmax(0,1fr)]">
        <aside className="border-b border-[var(--border-card)] bg-raised/30 lg:border-b-0 lg:border-r">
          <div className="space-y-3 border-b border-[var(--border-card)] p-3">
            <SearchInput
              placeholder="Search recommendations…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <div className="flex items-center justify-between text-[10.5px] text-muted">
              <span>{visible.length} candidate groups</span>
              <span>{visible.length > displayedCandidates.length ? `Showing top ${displayedCandidates.length}` : "Highest score first"}</span>
            </div>
          </div>
          <div className="max-h-[500px] space-y-1.5 overflow-y-auto p-2">
            {displayedCandidates.map((candidate, index) => (
              <button
                key={candidate.id}
                type="button"
                onClick={() => setSelectedId(candidate.id)}
                className={`w-full rounded-[9px] border px-3 py-3 text-left transition-colors ${
                  selected?.id === candidate.id
                    ? "border-[var(--ac)]/40 bg-[var(--ac)]/10"
                    : "border-transparent hover:border-[var(--border-card)] hover:bg-card"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      {index === 0 && <Sparkles className="size-3.5 shrink-0 text-[var(--ac)]" />}
                      <p className="truncate text-[12.5px] font-semibold text-fg">{candidate.name}</p>
                    </div>
                    <p className="mt-1 text-[10.5px] text-muted">
                      {candidate.applications.length} apps · {candidate.organizationCount} organizations · {candidate.os || `OS ${candidate.osType}`}
                    </p>
                  </div>
                  <span className="grid size-9 shrink-0 place-items-center rounded-full border border-[var(--border-card)] bg-control text-[12px] font-bold text-fg">
                    {candidate.score}
                  </span>
                </div>
                <div className="mt-2 flex items-center gap-1.5">
                  <Badge tone={candidate.confidence === "high" ? "success" : "warning"}>
                    {candidate.confidence === "high" ? "High match" : "Review"}
                  </Badge>
                  <Badge tone={candidate.parentReady ? "info" : "warning"}>
                    {candidate.parentReady ? "Parent ready" : "Promote first"}
                  </Badge>
                </div>
              </button>
            ))}
            {!candidates.loading && visible.length === 0 && (
              <div className="grid min-h-56 place-items-center px-6 text-center">
                <div>
                  <ScanSearch className="mx-auto size-7 text-faint" />
                  <p className="mt-2 text-[12.5px] font-semibold text-fg">No cleanup candidates</p>
                  <p className="mt-1 text-[11px] leading-4 text-muted">No cross-organization application families match this search.</p>
                </div>
              </div>
            )}
          </div>
        </aside>

        <div className="min-w-0 p-5">
          {selected ? (
            <CandidateDetail candidate={selected} onStart={() => setDialogOpen(true)} />
          ) : (
            <div className="grid h-full min-h-80 place-items-center text-center">
              <div>
                <ShieldCheck className="mx-auto size-8 text-faint" />
                <p className="mt-3 text-[13px] font-semibold text-fg">Select a recommendation</p>
                <p className="mt-1 text-[11.5px] text-muted">RTM will explain why the applications were grouped before any preview.</p>
              </div>
            </div>
          )}
        </div>
      </section>

      <section className="rounded-[12px] border border-[var(--border-card)] bg-card">
        <div className="flex items-center justify-between border-b border-[var(--border-card)] px-4 py-3">
          <div>
            <h3 className="text-[12.5px] font-semibold text-fg">Verification ledger</h3>
            <p className="mt-0.5 text-[11px] text-muted">Durable outcomes from the cleanup workflow.</p>
          </div>
          <Badge tone={activeOperations.length ? "warning" : "success"}>
            {activeOperations.length ? `${activeOperations.length} need attention` : "Current"}
          </Badge>
        </div>
        <div className="grid gap-2 p-3 md:grid-cols-2 xl:grid-cols-3">
          {(operations.data ?? []).slice(0, 6).map((operation) => (
            <div key={operation.id} className="rounded-[8px] border border-[var(--border-card)] bg-raised/30 px-3 py-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-[11px] font-semibold text-fg">{operation.id}</span>
                <Badge tone={cleanupStatusTone(operation.status)}>{cleanupStatusLabel(operation.status)}</Badge>
              </div>
              <p className="mt-1.5 text-[10.5px] text-muted">
                {operation.requestedBy} · {new Date(operation.updatedAt).toLocaleString()}
              </p>
            </div>
          ))}
          {!operations.loading && (operations.data?.length ?? 0) === 0 && (
            <p className="p-2 text-[11.5px] text-muted">No cleanup operations have run yet.</p>
          )}
        </div>
      </section>

      <AppCleanupDialog
        open={dialogOpen}
        apps={apps.data ?? []}
        selectedIds={selected?.applications.map((app) => app.id) ?? []}
        recommendedRetainedAppId={selected?.recommendedRetainedAppId}
        onClose={() => setDialogOpen(false)}
        onDone={refreshAll}
      />
    </div>
  );
}

function CandidateDetail({ candidate, onStart }: { candidate: TLAppCleanupCandidate; onStart: () => void }) {
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[var(--border-card)] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Badge tone={candidate.confidence === "high" ? "success" : "warning"}>
              {candidate.confidence === "high" ? "Best match" : "Review match"}
            </Badge>
            <span className="text-[11px] text-muted">Score {candidate.score}/100</span>
          </div>
          <h3 className="mt-2 text-[19px] font-bold text-fg-strong">{candidate.name}</h3>
          <p className="mt-1 text-[11.5px] text-muted">
            {candidate.applications.length} records across {candidate.organizationCount} organizations
          </p>
        </div>
        <Button variant="accent" onClick={onStart}>
          <GitMerge className="size-4" />
          Review guided cleanup
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <CleanupMetric label="File rules" value={String(candidate.totalFileRules)} detail="Deep preview deduplicates" />
        <CleanupMetric label="Policies" value={String(candidate.totalPolicies)} detail="Promoted into Global" />
        <CleanupMetric label="Canonical target" value={candidate.parentReady ? "Ready" : "Promote"} detail={candidate.parentReady ? "Parent-owned app found" : "Promote one policy first"} tone={candidate.parentReady ? "success" : "warning"} />
      </div>

      <div>
        <h4 className="text-[11px] font-bold uppercase tracking-[.6px] text-faint">Why RTM recommends this group</h4>
        <div className="mt-2 space-y-2">
          {candidate.reasons.map((reason) => (
            <div key={reason} className="flex items-start gap-2 rounded-[8px] border border-[var(--border-card)] bg-raised/30 px-3 py-2.5">
              <Check className="mt-0.5 size-3.5 shrink-0 text-emerald-300" />
              <span className="text-[11.5px] leading-4 text-secondary">{reason}</span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h4 className="text-[11px] font-bold uppercase tracking-[.6px] text-faint">Applications in this merge</h4>
        <div className="mt-2 overflow-hidden rounded-[9px] border border-[var(--border-card)]">
          {candidate.applications.map((app) => (
            <div key={app.id} className="grid gap-2 border-b border-[var(--border-card)] px-3 py-2.5 last:border-b-0 sm:grid-cols-[minmax(0,1fr)_140px_90px] sm:items-center">
              <div className="min-w-0">
                <p className="truncate text-[12px] font-semibold text-fg">{app.name}</p>
                <p className="truncate text-[10.5px] text-muted">{app.organization || app.organizationId}</p>
              </div>
              <Badge tone={app.id === candidate.recommendedRetainedAppId ? "info" : "neutral"}>
                {app.id === candidate.recommendedRetainedAppId ? "Retain as parent" : app.source === "parent" ? "Parent duplicate" : "Merge source"}
              </Badge>
              <span className="text-[10.5px] text-muted">{app.fileCount} files · {app.policyCount} policies</span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex items-start gap-2 rounded-[9px] border border-amber-500/25 bg-amber-500/10 px-3 py-2.5">
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-300" />
        <p className="text-[11px] leading-4 text-amber-100/80">
          Recommendation scores only build the review queue. The next step re-reads current file rules and policies and will block execution if the plan is unsafe.
        </p>
      </div>
    </div>
  );
}

function CleanupMetric({
  label,
  value,
  detail,
  tone = "normal",
}: {
  label: string;
  value: string;
  detail: string;
  tone?: "normal" | "success" | "warning";
}) {
  const valueTone = tone === "success" ? "text-emerald-300" : tone === "warning" ? "text-amber-300" : "text-fg-strong";
  return (
    <div className="min-w-0 px-4 py-3">
      <p className="text-[9.5px] font-bold uppercase tracking-[.6px] text-faint">{label}</p>
      <p className={`mt-1 text-[20px] font-bold ${valueTone}`}>{value}</p>
      <p className="mt-0.5 truncate text-[10.5px] text-muted">{detail}</p>
    </div>
  );
}
