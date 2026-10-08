import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Download,
  FileSearch,
  Loader2,
  Play,
  ShieldOff,
  X,
} from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { hasPermission, useAuth } from "@/store/auth";
import { useTenant } from "@/store/tenant";
import { useSetPageTitle } from "@/store/page";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog } from "@/components/ui/dialog";
import { SearchInput } from "@/components/ui/input";
import { DataTable, type Column } from "@/components/common/DataTable";
import { Avatar } from "@/components/common/Avatar";
import { userTone } from "@/components/common/status";
import { downloadAuditedCsv } from "@/lib/csv";
import type {
  ShareClassification,
  ShareFinding,
  ShareInvestigation,
  ShareRevokePreview,
  StatusTone,
  User,
} from "@/types";

const CLASSIFICATION_LABEL: Record<ShareClassification, string> = {
  direct_user: "Direct grant",
  specific_people_link: "Specific-people link",
  broad_link: "Broad link",
  group_based: "Via group",
  site_membership: "Site membership",
  inherited: "Inherited",
};

const CLASSIFICATION_TONE: Record<ShareClassification, StatusTone> = {
  direct_user: "danger",
  specific_people_link: "warning",
  broad_link: "warning",
  group_based: "info",
  site_membership: "info",
  inherited: "neutral",
};

/**
 * Share Detective: find everything shared with a user or guest across the
 * tenant's SharePoint/OneDrive — the offboarding / access-review workflow.
 * The scan is read-only and coverage-honest; revoking confirmed direct grants
 * goes through the standard What-If → approval → execute pipeline.
 */
export function ShareDetectivePage({ embedded = false }: { embedded?: boolean }) {
  useSetPageTitle(embedded ? "SharePoint" : "Share Detective");
  const { activeTenant } = useTenant();
  const { user } = useAuth();
  const tenantId = activeTenant?.id ?? "";

  const users = useAsync(() => api.users.list(tenantId), [tenantId], { enabled: Boolean(tenantId) });
  const [subject, setSubject] = useState<User | null>(null);
  const [q, setQ] = useState("");
  const [inv, setInv] = useState<ShareInvestigation | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [revoking, setRevoking] = useState(false);
  const pollRef = useRef<number | null>(null);

  // Poll a running investigation until it settles.
  useEffect(() => {
    if (!inv || inv.status !== "running") return;
    pollRef.current = window.setInterval(async () => {
      try {
        const fresh = await api.shareDetective.get(inv.tenantId, inv.id);
        setInv(fresh);
        if (fresh.status !== "running" && pollRef.current) {
          window.clearInterval(pollRef.current);
        }
      } catch {
        // transient poll failure — keep trying until the timeout server-side
      }
    }, 1000);
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [inv?.id, inv?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  // Tenant switch resets the workflow (investigations are tenant-scoped).
  useEffect(() => {
    setSubject(null);
    setInv(null);
    setSelected(new Set());
    setError(null);
  }, [tenantId]);

  const candidates = useMemo(
    () =>
      (users.data ?? []).filter(
        (u) =>
          u.name.toLowerCase().includes(q.toLowerCase()) ||
          u.upn.toLowerCase().includes(q.toLowerCase()),
      ),
    [users.data, q],
  );

  async function start() {
    if (!subject || starting) return;
    setStarting(true);
    setError(null);
    setSelected(new Set());
    try {
      setInv(await api.shareDetective.start(tenantId, subject.id));
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Could not start the investigation.");
    } finally {
      setStarting(false);
    }
  }

  const findings = inv?.findings ?? [];
  const coverage = inv?.coverage ?? [];
  const revocableSelected = findings.filter((f) => selected.has(f.id) && f.revocable && !f.revoked);

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const exportCsv = () => {
    if (!inv) return;
    void downloadAuditedCsv(
      {
        kind: "share-detective",
        filename: `share-detective-${inv.subject.upn}.csv`,
        rowCount: findings.length,
        tenantId,
        headers: ["Site", "Path", "Type", "Classification", "Role", "Via", "Revocable", "Revoked", "Detail"],
        rows: findings.map((f) => [
          f.siteName,
          f.itemPath,
          f.itemType,
          CLASSIFICATION_LABEL[f.classification],
          f.role,
          f.via ?? "",
          f.revocable ? "yes" : "no",
          f.revoked ? "yes" : "no",
          f.detail ?? "",
        ]),
      },
      api.exports.generate,
    );
  };

  const findingColumns: Column<ShareFinding>[] = [
    {
      key: "sel",
      header: "",
      width: "44px",
      cell: (f) => (
        <Checkbox
          checked={selected.has(f.id)}
          onChange={() => toggle(f.id)}
          aria-label={`Select finding on ${f.itemPath}`}
        />
      ),
    },
    {
      key: "path",
      header: "Item",
      cell: (f) => (
        <div className="min-w-0">
          <p className="truncate font-semibold text-fg">{f.itemPath}</p>
          <p className="truncate text-[11.5px] text-muted">
            {f.siteName} · {f.itemType}
          </p>
        </div>
      ),
    },
    {
      key: "class",
      header: "Access",
      width: "170px",
      cell: (f) => (
        <Badge tone={CLASSIFICATION_TONE[f.classification]} dot={false}>
          {CLASSIFICATION_LABEL[f.classification]}
        </Badge>
      ),
    },
    { key: "role", header: "Role", width: "90px", cell: (f) => <span className="text-secondary">{f.role}</span> },
    {
      key: "via",
      header: "Via",
      width: "140px",
      cell: (f) => <span className="truncate text-secondary">{f.via ?? "—"}</span>,
    },
    {
      key: "state",
      header: "State",
      width: "120px",
      cell: (f) =>
        f.revoked ? (
          <Badge tone="neutral" dot={false}>Revoked</Badge>
        ) : f.revocable ? (
          <Badge tone="success" dot={false}>Revocable</Badge>
        ) : (
          <Badge tone="neutral" dot={false}>Manual review</Badge>
        ),
    },
  ];

  return (
    <div className="space-y-4 pb-16">
      {/* purpose banner */}
      <div className="flex items-center gap-2.5 rounded-[12px] border border-[rgba(91,141,239,.3)] bg-[rgba(91,141,239,.1)] px-4 py-3">
        <FileSearch className="size-5 shrink-0 text-[#79a8ff]" />
        <div>
          <p className="text-[13px] font-semibold text-fg-strong">
            Shared-access investigation · Read-only scan
          </p>
          <p className="text-[12px] text-secondary">
            Find every SharePoint/OneDrive item shared with a user or guest. Coverage is
            reported honestly — a skipped site is a visible gap, never a silent miss.
            Revoking findings requires a What-If preview and is audited.
          </p>
        </div>
      </div>

      {/* subject picker */}
      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[260px] flex-1">
            <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
              Subject (member or guest)
            </label>
            <SearchInput
              placeholder="Search by name or UPN…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setSubject(null);
              }}
            />
          </div>
          {subject && (
            <div className="flex items-center gap-2.5 rounded-[10px] border border-[var(--border-strong)] bg-control px-3 py-2">
              <Avatar name={subject.name} />
              <div>
                <p className="text-[13px] font-semibold text-fg">{subject.name}</p>
                <p className="text-[11.5px] text-muted">{subject.upn}</p>
              </div>
              <Badge tone={userTone(subject.status)}>{subject.status}</Badge>
              <Button variant="ghost" size="icon" aria-label="Clear subject" onClick={() => setSubject(null)}>
                <X className="size-4" />
              </Button>
            </div>
          )}
          <Button variant="accent" onClick={start} disabled={!subject || starting}>
            {starting ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
            {starting ? "Starting…" : "Start Investigation"}
          </Button>
        </div>

        {/* candidate list appears while typing without a chosen subject */}
        {!subject && q.length > 0 && (
          <div className="mt-3 max-h-[240px] overflow-y-auto rounded-[10px] border border-[var(--border-card)]">
            {candidates.length === 0 && (
              <p className="px-4 py-3 text-[12.5px] text-muted">No users match.</p>
            )}
            {candidates.slice(0, 8).map((u) => (
              <button
                key={u.id}
                className="flex w-full items-center gap-3 border-b border-[var(--border-card)] px-4 py-2 text-left last:border-0 hover:bg-control"
                onClick={() => setSubject(u)}
              >
                <Avatar name={u.name} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[13px] font-semibold text-fg">{u.name}</p>
                  <p className="truncate text-[12px] text-muted">{u.upn}</p>
                </div>
                <Badge tone={userTone(u.status)}>{u.status}</Badge>
              </button>
            ))}
          </div>
        )}
      </Card>

      {error && (
        <div className="flex items-start gap-2 rounded-[10px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3.5 py-2.5 text-[12.5px] text-[#f7868a]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {inv && (
        <>
          {/* status + summary */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <h3 className="text-[14px] font-bold text-fg-strong">
                {inv.subject.name} <span className="font-normal text-muted">({inv.subject.upn})</span>
              </h3>
              {inv.status === "running" && (
                <Badge tone="info">
                  <Loader2 className="mr-1 inline size-3 animate-spin" />
                  Scanning…
                </Badge>
              )}
              {inv.status === "completed" && <Badge tone="success">Completed</Badge>}
              {inv.status === "failed" && <Badge tone="danger">Failed</Badge>}
            </div>
            <Button variant="default" onClick={exportCsv} disabled={findings.length === 0}>
              <Download className="size-4" />
              Export CSV
            </Button>
          </div>

          {inv.status === "failed" && inv.error && (
            <div className="rounded-[10px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3.5 py-2.5 text-[12.5px] text-[#f7868a]">
              {inv.error}
            </div>
          )}

          <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-6">
            <StatCard label="Sites discovered" value={inv.summary.sitesDiscovered} />
            <StatCard label="Sites scanned" value={inv.summary.sitesScanned} />
            <StatCard
              label="Sites skipped"
              value={inv.summary.sitesSkipped}
              tone={inv.summary.sitesSkipped > 0 ? "warning" : undefined}
            />
            <StatCard label="Items inspected" value={inv.summary.itemsScanned} />
            <StatCard label="Findings" value={findings.length} />
            <StatCard
              label="Revocable"
              value={findings.filter((f) => f.revocable && !f.revoked).length}
              tone="danger"
            />
          </div>

          {/* coverage honesty */}
          {coverage.some((c) => c.status !== "scanned") && (
            <div className="rounded-[10px] border border-[rgba(245,166,35,.3)] bg-[rgba(245,166,35,.08)] px-3.5 py-2.5 text-[12.5px] leading-relaxed text-[#f5c163]">
              <p className="font-semibold">Partial coverage — results are incomplete:</p>
              {coverage
                .filter((c) => c.status !== "scanned")
                .map((c) => (
                  <p key={c.siteId}>
                    {c.siteName}: {c.status} {c.reason ? `— ${c.reason}` : ""}
                  </p>
                ))}
            </div>
          )}

          {/* findings */}
          <DataTable
            columns={findingColumns}
            rows={findings}
            loading={inv.status === "running" && findings.length === 0}
            getRowId={(f) => f.id}
            isRowActive={(f) => selected.has(f.id)}
            emptyTitle={
              inv.status === "completed"
                ? "Nothing is shared with this subject in the scanned sites"
                : "Scanning…"
            }
          />

          {/* floating revoke bar */}
          {selected.size > 0 && hasPermission(user, "changes.execute") && (
            <div className="fixed bottom-6 left-[calc(250px+50%-125px)] z-30 -translate-x-1/2 animate-pop">
              <div className="flex items-center gap-2 rounded-[12px] border border-[var(--border-strong)] bg-raised px-3 py-2 shadow-[0_14px_40px_rgba(0,0,0,.55)]">
                <span className="px-1.5 text-[13px] font-semibold text-fg">
                  {selected.size} selected · {revocableSelected.length} revocable
                </span>
                <span className="h-5 w-px bg-white/10" />
                <Button variant="accent" size="sm" onClick={() => setRevoking(true)}>
                  <ShieldOff className="size-3.5" />
                  What If Revoke
                </Button>
                <Button variant="ghost" size="icon" aria-label="Clear" onClick={() => setSelected(new Set())}>
                  <X className="size-4" />
                </Button>
              </div>
            </div>
          )}

          <RevokeDialog
            open={revoking}
            investigation={inv}
            findingIds={Array.from(selected)}
            onClose={() => setRevoking(false)}
            onDone={async () => {
              setRevoking(false);
              setSelected(new Set());
              try {
                setInv(await api.shareDetective.get(inv.tenantId, inv.id));
              } catch {
                // refresh is best-effort — findings were updated server-side
              }
            }}
          />
        </>
      )}
    </div>
  );
}

function StatCard({ label, value, tone }: { label: string; value: number; tone?: StatusTone }) {
  return (
    <Card className="p-4">
      <p className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">{label}</p>
      {tone && value > 0 ? (
        <div className="mt-1.5">
          <Badge tone={tone}>{value}</Badge>
        </div>
      ) : (
        <p className="mt-1 text-[18px] font-bold text-fg-strong">{value}</p>
      )}
    </Card>
  );
}

/** What-If revoke: preview (plan + warnings + approval token) → execute.
 * Only confirmed direct grants are deleted; everything else is listed with
 * its manual-review reason. Not revertible, and says so. */
function RevokeDialog({
  open,
  investigation,
  findingIds,
  onClose,
  onDone,
}: {
  open: boolean;
  investigation: ShareInvestigation;
  findingIds: string[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [preview, setPreview] = useState<ShareRevokePreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPreview(null);
    setError(null);
    setBusy(true);
    api.shareDetective
      .revokePreview(investigation.tenantId, investigation.id, findingIds)
      .then(setPreview)
      .catch((err) =>
        setError(err instanceof RtmApiError ? err.message : "Could not build the revoke plan."),
      )
      .finally(() => setBusy(false));
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  async function execute() {
    if (!preview) return;
    setExecuting(true);
    setError(null);
    try {
      const result = await api.shareDetective.revoke(
        investigation.tenantId,
        investigation.id,
        findingIds,
        preview.approvalToken,
      );
      if (result.failed.length > 0) {
        setError(`${result.failed.length} finding(s) failed to revoke — see change history.`);
        setExecuting(false);
        return;
      }
      setExecuting(false);
      onDone();
    } catch (err) {
      setExecuting(false);
      setError(err instanceof RtmApiError ? err.message : "The revoke failed.");
    }
  }

  return (
    <Dialog open={open} onClose={() => !executing && onClose()} width={560}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-[rgba(229,72,77,.12)]">
            <ShieldOff className="size-4 text-[#f7868a]" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">What If — revoke shared access</h2>
            <p className="text-[12px] text-muted">
              {investigation.subject.name} · {investigation.tenantName}
            </p>
          </div>
          {preview && (
            <span className="ml-auto">
              <Badge tone={preview.risk === "High" ? "danger" : "warning"}>{preview.risk} risk</Badge>
            </span>
          )}
        </div>

        {busy && (
          <div className="grid h-[120px] place-items-center">
            <Loader2 className="size-5 animate-spin text-muted" />
          </div>
        )}

        {preview && (
          <>
            <div className="mt-3 max-h-[260px] overflow-y-auto rounded-[10px] border border-[var(--border-card)]">
              {preview.actions.map((a) => (
                <div
                  key={a.findingId}
                  className="flex items-start justify-between gap-3 border-b border-[var(--border-card)] px-3.5 py-2 last:border-0"
                >
                  <div className="min-w-0">
                    <p className="truncate text-[12.5px] font-semibold text-fg">{a.itemPath}</p>
                    <p className="truncate text-[11.5px] text-muted">
                      {a.siteName}
                      {a.reason ? ` — ${a.reason}` : ""}
                    </p>
                  </div>
                  <Badge tone={a.action === "delete_permission" ? "danger" : "neutral"} dot={false}>
                    {a.action === "delete_permission" ? "Delete permission" : "Manual review"}
                  </Badge>
                </div>
              ))}
            </div>

            {preview.warnings.length > 0 && (
              <div className="mt-3 space-y-1 rounded-[8px] border border-[rgba(245,166,35,.3)] bg-[rgba(245,166,35,.08)] px-3 py-2 text-[12px] leading-relaxed text-[#f5c163]">
                {preview.warnings.map((wng, i) => (
                  <p key={i}>{wng}</p>
                ))}
              </div>
            )}
          </>
        )}

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="default" onClick={onClose} disabled={executing}>
            Cancel
          </Button>
          <Button
            variant="accent"
            onClick={execute}
            disabled={busy || executing || !preview || preview.revocableCount === 0}
          >
            {executing && <Loader2 className="size-4 animate-spin" />}
            Revoke {preview?.revocableCount ?? 0} grant{preview?.revocableCount === 1 ? "" : "s"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
