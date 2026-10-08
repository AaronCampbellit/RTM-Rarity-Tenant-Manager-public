import { useMemo, useState } from "react";
import { AlertTriangle, FolderSearch, Loader2, RotateCcw, ShieldCheck, UserPlus } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog } from "@/components/ui/dialog";
import type {
  SharePointInventoryNode,
  SharePointPermissionPreview,
  SharePointPermissionRequest,
  SharePointPermissionTarget,
  SharePointScopePermission,
} from "@/types";

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

function targetFor(node: SharePointInventoryNode): SharePointPermissionTarget {
  return {
    siteId: node.siteId ?? node.id,
    driveId: node.driveId,
    itemId: node.itemId,
    kind: node.kind,
    path: node.path,
  };
}

export function ScopePermissionsModal({
  node,
  tenantId,
  onClose,
  onScanFiles,
}: {
  node: SharePointInventoryNode | null;
  tenantId: string;
  onClose: () => void;
  onScanFiles: (node: SharePointInventoryNode) => Promise<void>;
}) {
  const [refresh, setRefresh] = useState(0);
  const [principal, setPrincipal] = useState("");
  const [role, setRole] = useState("Read");
  const [preview, setPreview] = useState<SharePointPermissionPreview | null>(null);
  const [pending, setPending] = useState<SharePointPermissionRequest | null>(null);
  const [breakInheritance, setBreakInheritance] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const target = node ? targetFor(node) : null;

  const permissions = useAsync(
    () => target ? api.sharepoint.scopePermissions(tenantId, target) : Promise.resolve([]),
    [tenantId, node?.id, refresh],
  );
  const users = useAsync(
    () => node ? api.users.list(tenantId) : Promise.resolve([]),
    [tenantId, !!node],
  );
  const groups = useAsync(
    () => node ? api.groups.list(tenantId) : Promise.resolve([]),
    [tenantId, !!node],
  );
  const principals = useMemo(() => [
    ...(users.data ?? []).map((user) => ({ id: user.id, upn: user.upn, label: `${user.name} (${user.upn})`, kind: user.status === "Guest" ? "Guest" as const : "User" as const })),
    ...(groups.data ?? [])
      .filter((group) => group.type === "Security" || group.type === "M365" || group.type === "Mail-enabled Sec.")
      .map((group) => ({
        id: group.id,
        upn: "",
        label: `${group.name} (${group.type})`,
        kind: group.type === "M365" ? "Microsoft 365 Group" as const : "Security Group" as const,
      })),
  ], [users.data, groups.data]);

  function resetAndClose() {
    if (busy) return;
    setPreview(null);
    setPending(null);
    setError(null);
    setBreakInheritance(false);
    onClose();
  }

  async function createPreview(request: SharePointPermissionRequest) {
    setBusy(true);
    setError(null);
    try {
      const result = await api.sharepoint.previewPermission(tenantId, request);
      setPending(request);
      setPreview(result);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Could not build the permission preview.");
    } finally {
      setBusy(false);
    }
  }

  function grant() {
    if (!target || !principal) return;
    const selected = principals.find((item) => item.id === principal);
    void createPreview({
      target,
      principalId: principal,
      principalUpn: selected?.upn,
      principalType: selected?.kind,
      role,
      operation: "grant",
    });
  }

  function revoke(permission: SharePointScopePermission) {
    if (!target) return;
    void createPreview({
      target,
      principalId: permission.principalId,
      principalUpn: permission.principalUpn,
      principalType: permission.type,
      role: permission.role,
      operation: "revoke",
      breakInheritance: permission.inherited && breakInheritance,
      copyAssignments: permission.inherited && breakInheritance,
    });
  }

  async function execute() {
    if (!pending || !preview) return;
    setBusy(true);
    setError(null);
    try {
      await api.sharepoint.executePermission(tenantId, pending, preview.approvalToken);
      setPreview(null);
      setPending(null);
      setBreakInheritance(false);
      setRefresh((value) => value + 1);
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "The SharePoint permission change failed.");
    } finally {
      setBusy(false);
    }
  }

  const canScanFiles = node?.kind === "site" || node?.kind === "library" || node?.kind === "folder";

  return (
    <>
      <Dialog open={!!node && !preview} onClose={resetAndClose} width={720}>
        <div className="p-5">
          <div className="flex items-start gap-3">
            <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
              <ShieldCheck className="size-4 text-secondary" />
            </div>
            <div className="min-w-0 flex-1">
              <h2 className="text-[15px] font-bold text-fg-strong">{node?.name}</h2>
              <p className="truncate text-[12px] text-muted">{node?.path}</p>
            </div>
            {node?.hasUniquePermissions ? (
              <Badge tone="warning" dot={false}>Unique permissions</Badge>
            ) : (
              <Badge tone="neutral" dot={false}>Inherited</Badge>
            )}
          </div>

          <div className="mt-5 flex items-center justify-between">
            <h3 className="text-[11px] font-bold uppercase tracking-wide text-muted">Effective access</h3>
            {canScanFiles && node && (
              <Button variant="default" size="sm" disabled={busy} onClick={() => void onScanFiles(node)}>
                <FolderSearch className="size-3.5" /> Scan file permissions
              </Button>
            )}
          </div>

          {permissions.loading ? (
            <div className="flex items-center gap-2 py-8 text-[12.5px] text-muted">
              <Loader2 className="size-4 animate-spin" /> Loading access…
            </div>
          ) : permissions.error ? (
            <p className="py-6 text-[12.5px] text-[#f7868a]">{permissions.error.message}</p>
          ) : (
            <div className="mt-2 overflow-hidden rounded-[10px] border border-[var(--border-card)]">
              {(permissions.data ?? []).map((permission) => (
                <div key={permission.id} className="flex items-center gap-3 border-b border-[var(--border-card)] px-3.5 py-2.5 last:border-0">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[12.5px] font-semibold text-fg">{permission.principal}</p>
                    <p className="truncate text-[11.5px] text-muted">
                      {permission.type} · {permission.source}
                      {permission.principalUpn ? ` · ${permission.principalUpn}` : ""}
                    </p>
                  </div>
                  {permission.inherited && <Badge tone="info" dot={false}>Inherited</Badge>}
                  <Badge tone={permission.role === "Full Control" ? "warning" : "neutral"} dot={false}>{permission.role}</Badge>
                  <Button variant="ghost" size="sm" disabled={busy} onClick={() => revoke(permission)}>What If Revoke</Button>
                </div>
              ))}
              {(permissions.data?.length ?? 0) === 0 && (
                <p className="px-3.5 py-8 text-center text-[12.5px] text-muted">No role assignments were returned.</p>
              )}
            </div>
          )}

          {(permissions.data ?? []).some((permission) => permission.inherited) && (
            <label className="mt-3 flex items-start gap-2 rounded-[9px] border border-[var(--border-card)] bg-raised/40 px-3 py-2.5 text-[12px] text-secondary">
              <Checkbox checked={breakInheritance} onChange={() => setBreakInheritance((value) => !value)} />
              <span>
                Advanced: break inheritance locally before revoking. Leave this off to change the source assignment.
              </span>
            </label>
          )}

          <h3 className="mb-2 mt-5 text-[11px] font-bold uppercase tracking-wide text-muted">Grant access</h3>
          <div className="grid grid-cols-[1fr_150px_auto] gap-2">
            <select aria-label="User, guest, or security group" value={principal} onChange={(event) => setPrincipal(event.target.value)} className={SELECT_CLASS}>
              <option value="">Select a user, guest, or group…</option>
              {principals.map((item) => <option key={`${item.kind}-${item.id}`} value={item.id}>{item.label}</option>)}
            </select>
            <select aria-label="SharePoint role" value={role} onChange={(event) => setRole(event.target.value)} className={SELECT_CLASS}>
              <option>Read</option>
              <option>Edit</option>
              <option>Full Control</option>
            </select>
            <Button variant="accent" disabled={!principal || busy} onClick={grant}>
              <UserPlus className="size-4" /> What If
            </Button>
          </div>

          {node?.hasUniquePermissions && node.kind !== "site" && target && (
            <Button
              variant="outline"
              className="mt-3"
              disabled={busy}
              onClick={() => void createPreview({ target, principalId: "", role: "", operation: "restore_inheritance" })}
            >
              <RotateCcw className="size-4" /> What If Restore Inheritance
            </Button>
          )}
          {error && <ErrorBanner message={error} />}
        </div>
      </Dialog>

      <Dialog open={!!preview} onClose={() => !busy && setPreview(null)} width={620}>
        <div className="p-5">
          <div className="flex items-center gap-3">
            <AlertTriangle className="size-5 text-[#e3b341]" />
            <div className="flex-1">
              <h2 className="text-[15px] font-bold text-fg-strong">What If — SharePoint permission</h2>
              <p className="text-[12px] text-muted">{preview?.operation} · {preview?.target.path}</p>
            </div>
            <Badge tone={preview?.risk === "High" ? "danger" : "warning"}>{preview?.risk} risk</Badge>
          </div>
          {preview?.effectiveTarget && preview.effectiveTarget.path !== preview.target.path && (
            <div className="mt-4 rounded-[10px] border border-[rgba(91,141,239,.3)] bg-[rgba(91,141,239,.08)] px-3.5 py-3 text-[12.5px] text-body">
              <p className="font-semibold text-fg">Guided to permission source</p>
              <p>{preview.effectiveTarget.kind}: {preview.effectiveTarget.path}</p>
            </div>
          )}
          {preview?.warnings.map((warning) => (
            <div key={warning} className="mt-3 rounded-[10px] border border-[rgba(210,161,6,.35)] bg-[rgba(210,161,6,.08)] px-3.5 py-3 text-[12.5px] text-[#e3b341]">{warning}</div>
          ))}
          {error && <ErrorBanner message={error} />}
          <div className="mt-5 flex justify-end gap-2">
            <Button variant="default" disabled={busy} onClick={() => setPreview(null)}>Cancel</Button>
            <Button variant="accent" disabled={busy} onClick={() => void execute()}>
              {busy && <Loader2 className="size-4 animate-spin" />} Approve &amp; Execute
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" /><span>{message}</span>
    </div>
  );
}
