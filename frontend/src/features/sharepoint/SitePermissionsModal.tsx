import { useState } from "react";
import { AlertTriangle, Globe, Loader2, UserPlus } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { ChangeRequest, Site, SitePermission } from "@/types";

const ROLES: SitePermission["role"][] = ["Read", "Edit", "Full Control"];

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

function roleTone(role: SitePermission["role"]) {
  return role === "Full Control" ? "warning" : role === "Edit" ? "info" : "neutral";
}

function typeTone(t: SitePermission["type"]) {
  return t === "External" || t === "Link" ? "danger" : "neutral";
}

/**
 * Site permissions: who can access the site (owners/members/visitors, direct
 * grants, external users, sharing links) plus the grant/revoke access write
 * flow — both are What-If-gated like every other write.
 */
export function SitePermissionsModal({
  site,
  tenantId,
  onClose,
}: {
  site: Site | null;
  tenantId: string;
  onClose: () => void;
}) {
  const { openWhatIf } = useModals();
  const open = !!site;
  const siteId = site?.id ?? "";

  const perms = useAsync(
    () => (open ? api.sharepoint.permissions(tenantId, siteId) : Promise.resolve([])),
    [tenantId, siteId, open],
  );
  const users = useAsync(
    () => (open ? api.users.list(tenantId) : Promise.resolve([])),
    [tenantId, open],
  );

  const [grantUserId, setGrantUserId] = useState("");
  const [grantRole, setGrantRole] = useState<SitePermission["role"]>("Read");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function close() {
    if (busy) return;
    setGrantUserId("");
    setGrantRole("Read");
    setError(null);
    onClose();
  }

  async function runWhatIf(body: ChangeRequest) {
    setBusy(true);
    setError(null);
    try {
      const preview = await api.changes.preview(body);
      setBusy(false);
      close();
      openWhatIf({ preview, execute: () => api.changes.execute(body, preview.approvalToken) });
    } catch (err) {
      setBusy(false);
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Could not generate the preview. Please try again.",
      );
    }
  }

  const grant = () =>
    runWhatIf({
      action: "grant_site_access",
      tenantId,
      siteId,
      role: grantRole,
      userIds: [grantUserId],
    });

  // Revoke needs the directory user id; permissions rows carry the UPN.
  const revoke = (p: SitePermission) => {
    const user = users.data?.find((u) => u.upn === p.principalUpn);
    if (!user) return;
    void runWhatIf({
      action: "revoke_site_access",
      tenantId,
      siteId,
      role: p.role,
      userIds: [user.id],
    });
  };

  return (
    <Dialog open={open} onClose={close} width={560}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Globe className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">{site?.name}</h2>
            <p className="mono text-[11px] text-muted">{site?.url}</p>
          </div>
          <div className="ml-auto">
            <Badge tone={site?.externalSharing === "Internal" ? "neutral" : "warning"} dot={false}>
              Sharing: {site?.externalSharing}
            </Badge>
          </div>
        </div>

        <h3 className="mb-2 mt-5 text-[12px] font-bold uppercase tracking-wide text-muted">
          Access
        </h3>
        {perms.loading ? (
          <div className="flex items-center gap-2 py-3 text-[12.5px] text-muted">
            <Loader2 className="size-4 animate-spin" /> Loading permissions…
          </div>
        ) : perms.error ? (
          <p className="py-2 text-[12.5px] text-[#f7868a]">{perms.error.message}</p>
        ) : (perms.data?.length ?? 0) === 0 ? (
          <p className="py-2 text-[12.5px] text-muted">No permission entries found.</p>
        ) : (
          <div className="rounded-[10px] border border-[var(--border)] bg-raised/40">
            {perms.data!.map((p, i) => {
              const canRevoke =
                (p.type === "User" || p.type === "External") &&
                !!users.data?.some((u) => u.upn === p.principalUpn);
              return (
                <div
                  key={p.id}
                  className={`flex items-center justify-between gap-2 px-3.5 py-2.5 ${
                    i > 0 ? "border-t border-[var(--border)]" : ""
                  }`}
                >
                  <div className="min-w-0">
                    <p className="truncate text-[12.5px] font-semibold text-fg">{p.principal}</p>
                    <p className="truncate text-[11.5px] text-muted">
                      {p.source}
                      {p.principalUpn !== "—" && p.type !== "Group" ? ` · ${p.principalUpn}` : ""}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {(p.type === "External" || p.type === "Link") && (
                      <Badge tone={typeTone(p.type)} dot={false}>
                        {p.type === "Link" ? "Anonymous link" : "External"}
                      </Badge>
                    )}
                    <Badge tone={roleTone(p.role)} dot={false}>
                      {p.role}
                    </Badge>
                    {canRevoke && (
                      <Button variant="ghost" size="sm" disabled={busy} onClick={() => revoke(p)}>
                        Revoke
                      </Button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <h3 className="mb-2 mt-5 text-[12px] font-bold uppercase tracking-wide text-muted">
          Grant access
        </h3>
        <div className="flex items-center gap-2">
          <select
            value={grantUserId}
            onChange={(e) => setGrantUserId(e.target.value)}
            className={SELECT_CLASS}
          >
            <option value="">{users.loading ? "Loading users…" : "Select a user…"}</option>
            {users.data?.map((u) => (
              <option key={u.id} value={u.id}>
                {u.name} ({u.upn})
              </option>
            ))}
          </select>
          <select
            value={grantRole}
            onChange={(e) => setGrantRole(e.target.value as SitePermission["role"])}
            className={`${SELECT_CLASS} w-[150px] shrink-0`}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <Button
            variant="accent"
            className="shrink-0"
            disabled={!grantUserId || busy}
            onClick={grant}
          >
            {busy ? <Loader2 className="size-4 animate-spin" /> : <UserPlus className="size-4" />}
            What If
          </Button>
        </div>

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <p className="mt-3 text-[12px] text-muted">
          Grants and revocations run through the What-If gate — nothing changes
          until the preview is approved.
        </p>
      </div>
    </Dialog>
  );
}
