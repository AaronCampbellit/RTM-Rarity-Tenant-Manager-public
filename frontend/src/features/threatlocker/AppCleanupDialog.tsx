import { useEffect, useMemo, useRef, useState } from "react";
import { Check, GitMerge, Loader2, Play, RefreshCw, ShieldCheck, X } from "lucide-react";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { TLAppCleanupOperation, TLAppCleanupPreview, TLAppCleanupResult, TLApplication } from "@/types";
import { cleanupStatusLabel, cleanupStatusTone, isActiveCleanupStatus } from "./cleanupLifecycle";
import { cleanupWorkflowStage, type CleanupWorkflowStage } from "./cleanupWorkflow";

interface AppCleanupDialogProps {
  open: boolean;
  tenantId?: string;
  apps: TLApplication[];
  selectedIds: string[];
  recommendedRetainedAppId?: string;
  onClose: () => void;
  onDone: () => void | Promise<void>;
}

export function AppCleanupDialog({
  open,
  tenantId,
  apps,
  selectedIds,
  recommendedRetainedAppId,
  onClose,
  onDone,
}: AppCleanupDialogProps) {
  const selectedKey = selectedIds.join("|");
  const selectedApps = useMemo(
    () => selectedIds.map((id) => apps.find((app) => app.id === id)).filter((app): app is TLApplication => !!app),
    [apps, selectedKey],
  );
  const [name, setName] = useState("");
  const [retainedAppId, setRetainedAppId] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(true);
  const [preview, setPreview] = useState<TLAppCleanupPreview | null>(null);
  const [result, setResult] = useState<TLAppCleanupResult | null>(null);
  const [parentPromotionResult, setParentPromotionResult] = useState<TLAppCleanupResult | null>(null);
  const [dialogApps, setDialogApps] = useState<TLApplication[]>([]);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [promotingParent, setPromotingParent] = useState(false);
  const [operations, setOperations] = useState<TLAppCleanupOperation[]>([]);
  const [loadingOperations, setLoadingOperations] = useState(false);
  const [reconcilingId, setReconcilingId] = useState("");
  const [verifyingId, setVerifyingId] = useState("");
  const [error, setError] = useState("");
  const initialized = useRef(false);

  useEffect(() => {
    if (!open) {
      initialized.current = false;
      return;
    }
    if (initialized.current) return;
    initialized.current = true;
    const baseName = selectedApps[0]?.name ?? "";
    const parent = apps.find(
      (app) => app.id === recommendedRetainedAppId,
    ) ?? apps.find(
      (app) => app.source === "parent" && normalize(app.name) === normalize(baseName),
    );
    setName(baseName);
    setRetainedAppId(parent?.id ?? "");
    setConfirmDelete(true);
    setPreview(null);
    setResult(null);
    setParentPromotionResult(null);
    setDialogApps(selectedApps);
    setError("");
  }, [apps, open, recommendedRetainedAppId, selectedApps, selectedKey]);

  useEffect(() => {
    setPreview(null);
    setResult(null);
    setError("");
  }, [name, retainedAppId, confirmDelete, selectedKey]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoadingOperations(true);
    api.threatlocker.appCleanupOperations(tenantId)
      .then((items) => {
        if (!cancelled) setOperations(items);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Unable to load cleanup operations.");
      })
      .finally(() => {
        if (!cancelled) setLoadingOperations(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, tenantId]);

  if (!open) return null;

  const parentApps = apps.filter((app) => app.source === "parent");
  const displayedApps = dialogApps.length > 0 ? dialogApps : selectedApps;
  const canPreview = selectedIds.length >= 2;
  const canExecute = !!preview && !preview.parentPromotion && preview.blocked.length === 0 && !executing && !verifyingId;
  const stage = cleanupWorkflowStage({
    hasCandidate: true,
    hasPreview: !!preview,
    needsParentPromotion: !!preview?.parentPromotion,
    operationStatus: result?.verificationStatus,
  });

  function requestBody() {
    return {
      appIds: selectedIds,
      retainedAppId: retainedAppId || undefined,
      name: name.trim() || undefined,
      confirmDelete,
    };
  }

  async function loadPreview() {
    setLoadingPreview(true);
    setError("");
    setResult(null);
    try {
      const next = await api.threatlocker.previewAppCleanup(tenantId, requestBody());
      setPreview(next);
      if (!next.parentPromotion) setParentPromotionResult(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to preview application cleanup.");
    } finally {
      setLoadingPreview(false);
    }
  }

  async function promoteParent() {
    const proposal = preview?.parentPromotion;
    if (!proposal) return;
    const accepted = window.confirm(
      `Move “${proposal.policyName}” to ${proposal.destinationGroupName}. ` +
      `ThreatLocker will use it to create the parent-owned application target. Continue?`,
    );
    if (!accepted) return;
    setPromotingParent(true);
    setError("");
    try {
      const promoted = await api.threatlocker.promoteCleanupParent(tenantId, proposal);
      setParentPromotionResult(promoted);
      await onDone();
      setOperations(await api.threatlocker.appCleanupOperations(tenantId));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to promote the child policy and create the parent target.");
    } finally {
      setPromotingParent(false);
    }
  }

  async function execute() {
    setExecuting(true);
    setError("");
    try {
      const res = await api.threatlocker.executeAppCleanup(tenantId, { ...requestBody(), approvalToken: preview?.approvalToken });
      setResult(res);
      await onDone();
      setOperations(await api.threatlocker.appCleanupOperations(tenantId));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to clean up applications.");
    } finally {
      setExecuting(false);
    }
  }

  async function verifyOperation(operationId: string) {
    setVerifyingId(operationId);
    setError("");
    try {
      const verified = await api.threatlocker.verifyAppCleanup(tenantId, operationId);
      setResult(verified.result);
      setOperations(await api.threatlocker.appCleanupOperations(tenantId));
      await onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to verify cleanup against ThreatLocker.");
    } finally {
      setVerifyingId("");
    }
  }

  async function reconcile(operationId: string) {
    setReconcilingId(operationId);
    setError("");
    try {
      await api.threatlocker.reconcileAppCleanup(tenantId, operationId, "not_applied");
      setOperations(await api.threatlocker.appCleanupOperations(tenantId));
      setPreview(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to reconcile cleanup operation.");
    } finally {
      setReconcilingId("");
    }
  }

  return (
    <Dialog open={open} onClose={onClose} width={860}>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-5 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-fg-strong">Clean up applications</h2>
          <p className="text-[12px] text-muted">{selectedIds.length} selected</p>
        </div>
        <button className="grid size-8 place-items-center rounded-[8px] text-muted hover:bg-raised hover:text-fg" onClick={onClose}>
          <X className="size-4" />
        </button>
      </div>

      <div className="space-y-4 p-5">
        <CleanupStepper stage={stage} />

        <div className="grid gap-3 md:grid-cols-[1.1fr_1fr]">
          <label className="block space-y-1.5">
            <span className="text-[12px] font-semibold text-secondary">Global app name</span>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="block space-y-1.5">
            <span className="text-[12px] font-semibold text-secondary">Retained application</span>
            <select value={retainedAppId} onChange={(e) => setRetainedAppId(e.target.value)} className={selectClass}>
              <option value="">Promote a child policy to create the parent target</option>
              {parentApps.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name} · {app.organization}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-end">
            <label className="flex h-9 w-full items-center gap-2 rounded-[8px] border border-[var(--border-card)] bg-raised/40 px-3 text-[12.5px] text-secondary">
              <Checkbox checked={confirmDelete} onChange={() => setConfirmDelete(!confirmDelete)} aria-label="Delete merged applications" />
              I understand the native merge removes source apps
            </label>
          </div>
        </div>

        <section className="rounded-[8px] border border-[var(--border-card)] bg-raised/30">
          <div className="flex items-center justify-between border-b border-[var(--border-card)] px-3 py-2">
            <h3 className="text-[12px] font-semibold text-secondary">Selected applications</h3>
            <span className="tabular text-[11.5px] text-muted">{displayedApps.length}</span>
          </div>
          <div className="max-h-36 overflow-y-auto p-2">
            <div className="grid gap-1.5 sm:grid-cols-2">
              {displayedApps.map((app) => (
                <div key={app.id} className="rounded-[7px] border border-[var(--border-card)] bg-card px-2.5 py-2">
                  <p className="truncate text-[12.5px] font-semibold text-fg">{app.name}</p>
                  <p className="text-[11.5px] text-muted">{app.fileCount} files · {app.policyCount} policies</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {preview && (
          <section className="space-y-3 rounded-[8px] border border-[var(--border-card)] bg-raised/30 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={preview.blocked.length ? "danger" : "success"}>
                {preview.blocked.length ? "Blocked" : "Ready"}
              </Badge>
              <span className="text-[12.5px] text-secondary">
                {preview.fileRuleCount} unique file rules · {preview.deleteAppIds.length} merge sources · {preview.preservedPolicies.length} preserved policies
              </span>
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              <SummaryLine label="Retained app" value={preview.retainedApp.name || "New parent app"} />
              <SummaryLine label="Global destination" value={preview.globalDestination.name || "Exact Global group required"} />
            </div>
            {preview.parentPromotion && (
              <div className="rounded-[9px] border border-amber-500/30 bg-amber-500/10 p-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-[11px] font-bold uppercase tracking-[.6px] text-amber-300">Create the parent target</p>
                    <h3 className="mt-1 text-[13px] font-semibold text-fg">Promote one child policy before merging</h3>
                    <p className="mt-1 max-w-xl text-[11.5px] leading-4 text-secondary">
                      ThreatLocker will not accept a child-owned application as the canonical target. Moving this attached policy to Global creates the parent-owned application.
                    </p>
                  </div>
                  <Button variant="accent" onClick={promoteParent} disabled={promotingParent || !preview.parentPromotion.approvalToken}>
                    {promotingParent ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
                    Promote policy to Global
                  </Button>
                </div>
                <div className="mt-3 grid gap-2 sm:grid-cols-3">
                  <SummaryLine label="Child application" value={preview.parentPromotion.applicationName} />
                  <SummaryLine label="Attached policy" value={preview.parentPromotion.policyName} />
                  <SummaryLine label="Destination" value={preview.parentPromotion.destinationGroupName} />
                </div>
                <div className="mt-3 grid gap-1.5 text-[10.5px] text-muted sm:grid-cols-3">
                  <span><b className="mr-1 text-amber-300">1</b>Queue the reviewed policy</span>
                  <span><b className="mr-1 text-amber-300">2</b>Refresh until parent appears</span>
                  <span><b className="mr-1 text-amber-300">3</b>Preview the native merge</span>
                </div>
                {parentPromotionResult && (
                  <div className="mt-3 flex items-center justify-between gap-3 rounded-[7px] border border-[var(--border-card)] bg-card px-3 py-2">
                    <span className="text-[11.5px] text-secondary">
                      Promotion queued as {parentPromotionResult.operationId}. Refresh to discover the parent target.
                    </span>
                    <Button variant="default" onClick={loadPreview} disabled={loadingPreview}>
                      <RefreshCw className={loadingPreview ? "animate-spin" : ""} />
                      Refresh parent target
                    </Button>
                  </div>
                )}
              </div>
            )}
            {preview.preservedPolicies.length > 0 && !preview.parentPromotion && (
              <div className="rounded-[8px] border border-[var(--border-card)] bg-card">
                <div className="flex items-center justify-between border-b border-[var(--border-card)] px-3 py-2">
                  <div>
                    <h3 className="text-[12px] font-semibold text-secondary">Policies preserved through the merge</h3>
                    <p className="mt-0.5 text-[10.5px] text-muted">RTM snapshots these IDs, then queues each child-owned policy to Global serially.</p>
                  </div>
                  <Badge tone="info">{preview.preservedPolicies.length}</Badge>
                </div>
                <div className="max-h-40 space-y-1.5 overflow-y-auto p-2">
                  {preview.preservedPolicies.map((policy) => (
                    <div key={policy.id} className="grid gap-1 rounded-[7px] border border-[var(--border-card)] bg-raised/30 px-2.5 py-2 sm:grid-cols-[minmax(0,1fr)_120px_150px] sm:items-center">
                      <span className="truncate text-[11.5px] font-semibold text-fg">{policy.name}</span>
                      <span className="text-[10.5px] text-muted">{policy.action || "policy"}</span>
                      <span className="truncate text-[10.5px] text-muted">{policy.appliesTo || policy.organizationId || "Owning organization"}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {preview.warnings.length > 0 && <MessageList tone="warning" items={preview.warnings} />}
            {preview.blocked.length > 0 && <MessageList tone="danger" items={preview.blocked} />}
          </section>
        )}

        {result && (
          <section className="rounded-[8px] border border-[var(--border-card)] bg-raised/30 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={result.verificationStatus ? cleanupStatusTone(result.verificationStatus) : "warning"}>
                {result.verificationStatus ? cleanupStatusLabel(result.verificationStatus) : result.status}
              </Badge>
              <span className="text-[12.5px] text-secondary">
                Native-merged {result.deletedAppIds.length} source apps and queued {result.promotedPolicyIds.length} preserved policies to Global.
              </span>
            </div>
            {result.operationId && (
              <p className="mt-2 text-[11.5px] text-muted">
                {verifyingId === result.operationId
                  ? `Operation ${result.operationId} is being verified against ThreatLocker.`
                  : `Operation ${result.operationId} has a durable verification record.`}
              </p>
            )}
            {result.verification.checks.length > 0 && (
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                {result.verification.checks.map((check) => (
                  <div key={check.key} className="rounded-[7px] border border-[var(--border-card)] bg-card px-2.5 py-2">
                    <div className="flex items-center gap-2">
                      <span className={`grid size-4 place-items-center rounded-full ${check.passed ? "bg-emerald-500/20 text-emerald-300" : "bg-red-500/20 text-red-300"}`}>
                        {check.passed ? <Check className="size-3" /> : <X className="size-3" />}
                      </span>
                      <p className="text-[11.5px] font-semibold text-fg">{check.label}</p>
                    </div>
                    <p className="mt-1 text-[10.5px] leading-4 text-muted">{check.details}</p>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        <section className="rounded-[8px] border border-[var(--border-card)] bg-raised/30">
          <div className="flex items-center justify-between border-b border-[var(--border-card)] px-3 py-2">
            <div>
              <h3 className="text-[12px] font-semibold text-secondary">Operation ledger</h3>
              <p className="mt-0.5 text-[11px] text-muted">Portal verification is required before an equivalent cleanup can run again.</p>
            </div>
            <RefreshCw className={`size-3.5 text-muted ${loadingOperations ? "animate-spin" : ""}`} />
          </div>
          <div className="max-h-44 space-y-2 overflow-y-auto p-2">
            {operations.slice(0, 8).map((operation) => (
              <div key={operation.id} className="rounded-[7px] border border-[var(--border-card)] bg-card px-2.5 py-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge tone={cleanupStatusTone(operation.status)}>{cleanupStatusLabel(operation.status)}</Badge>
                      <span className="truncate text-[11.5px] text-muted">{operation.id}</span>
                    </div>
                    <p className="mt-1 text-[11px] text-muted">
                      {operation.requestedBy} · {new Date(operation.createdAt).toLocaleString()}
                    </p>
                  </div>
                  {isActiveCleanupStatus(operation.status) && (
                    <div className="flex items-center gap-1.5">
                      <Button
                        variant="ghost"
                        onClick={() => reconcile(operation.id)}
                        disabled={reconcilingId !== "" || verifyingId !== ""}
                      >
                        Not applied
                      </Button>
                      {operation.status !== "submitted" && (
                        <Button
                          variant="default"
                          onClick={() => verifyOperation(operation.id)}
                          disabled={verifyingId !== "" || reconcilingId !== ""}
                        >
                          {verifyingId === operation.id ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
                          {operation.status === "needs_reconciliation" ? "Verify again" : "Verify now"}
                        </Button>
                      )}
                    </div>
                  )}
                </div>
                {operation.error && <p className="mt-1.5 text-[11.5px] text-[#f7868a]">{operation.error}</p>}
              </div>
            ))}
            {!loadingOperations && operations.length === 0 && (
              <p className="px-1 py-3 text-center text-[11.5px] text-muted">No cleanup operations yet.</p>
            )}
          </div>
        </section>

        {error && (
          <p className="rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            {error}
          </p>
        )}
      </div>

      <div className="flex items-center justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
        <Button variant="ghost" onClick={onClose}>Close</Button>
        <Button variant="default" onClick={loadPreview} disabled={!canPreview || loadingPreview || executing}>
          {loadingPreview ? <Loader2 className="animate-spin" /> : <Play />}
          Preview
        </Button>
        <Button variant="accent" onClick={execute} disabled={!canExecute}>
          {executing || verifyingId ? <Loader2 className="animate-spin" /> : <GitMerge />}
          {verifyingId ? "Verifying portal…" : "Execute cleanup"}
        </Button>
      </div>
    </Dialog>
  );
}

const WORKFLOW_STEPS: Array<{ key: CleanupWorkflowStage; label: string }> = [
  { key: "discover", label: "Candidate" },
  { key: "review", label: "Apps" },
  { key: "parent", label: "Parent target" },
  { key: "approve", label: "Merge + policies" },
  { key: "verify", label: "Verify" },
  { key: "complete", label: "Complete" },
];

function CleanupStepper({ stage }: { stage: CleanupWorkflowStage }) {
  const activeIndex = WORKFLOW_STEPS.findIndex((item) => item.key === stage);
  return (
    <ol className="grid grid-cols-6 overflow-hidden rounded-[9px] border border-[var(--border-card)] bg-raised/30">
      {WORKFLOW_STEPS.map((step, index) => {
        const complete = index < activeIndex || stage === "complete";
        const active = index === activeIndex;
        return (
          <li key={step.key} aria-current={active ? "step" : undefined} className={`flex min-w-0 items-center gap-2 border-r border-[var(--border-card)] px-2 py-2.5 last:border-r-0 ${active ? "bg-[var(--ac)]/10" : ""}`}>
            <span className={`grid size-5 shrink-0 place-items-center rounded-full text-[10px] font-bold ${complete ? "bg-emerald-500/20 text-emerald-300" : active ? "bg-[var(--ac)] text-white" : "bg-control text-faint"}`}>
              {complete ? <Check className="size-3" /> : index + 1}
            </span>
            <span className={`truncate text-[10.5px] font-semibold ${active ? "text-fg" : "text-muted"}`}>{step.label}</span>
          </li>
        );
      })}
    </ol>
  );
}

function SummaryLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[7px] border border-[var(--border-card)] bg-card px-3 py-2">
      <p className="text-[11px] font-semibold uppercase tracking-[.4px] text-faint">{label}</p>
      <p className="mt-1 truncate text-[12.5px] font-semibold text-fg">{value}</p>
    </div>
  );
}

function MessageList({ tone, items }: { tone: "warning" | "danger"; items: string[] }) {
  const color = tone === "danger" ? "text-[#f7868a]" : "text-[#e3b341]";
  return (
    <div className="space-y-1">
      {items.map((item) => (
        <p key={item} className={`text-[12px] ${color}`}>{item}</p>
      ))}
    </div>
  );
}

function normalize(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}

const selectClass =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none transition-colors focus:border-[var(--ac)]/50 focus:ring-1 focus:ring-[var(--ac)]/30";
