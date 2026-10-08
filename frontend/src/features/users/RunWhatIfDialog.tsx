import { useState } from "react";
import { AlertTriangle, Loader2, Play } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import type { ChangeRequest } from "@/types";
import { USER_ACTIONS } from "./userActions";

const GROUP_ACTIONS = new Set<ChangeRequest["action"]>(["add_to_group", "remove_from_group"]);
const LICENSE_ACTIONS = new Set<ChangeRequest["action"]>(["assign_license", "remove_license"]);

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

/**
 * Step 1 of the write flow: choose the action and its target (group or
 * license, where applicable), then generate the live What-If preview and
 * hand off to the mandatory What-If gate.
 */
export function RunWhatIfDialog({
  open,
  tenantId,
  userIds,
  onClose,
}: {
  open: boolean;
  tenantId: string;
  userIds: string[];
  onClose: () => void;
}) {
  const { openWhatIf } = useModals();
  const [action, setAction] = useState<ChangeRequest["action"]>("add_to_group");
  const isGroupAction = GROUP_ACTIONS.has(action);
  const isLicenseAction = LICENSE_ACTIONS.has(action);
  const isSensitiveUserAction = action === "reset_password" || action === "revoke_user_access";

  const groups = useAsync(
    () => (open && isGroupAction ? api.groups.list(tenantId) : Promise.resolve([])),
    [tenantId, open, isGroupAction],
  );
  const licenses = useAsync(
    () => (open && isLicenseAction ? api.licenses.list(tenantId) : Promise.resolve([])),
    [tenantId, open, isLicenseAction],
  );

  const [groupId, setGroupId] = useState("");
  const [skuId, setSkuId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function close() {
    if (busy) return;
    setAction("add_to_group");
    setGroupId("");
    setSkuId("");
    setError(null);
    onClose();
  }

  const canGenerate = (isGroupAction ? !!groupId : isLicenseAction ? !!skuId : true) &&
    (!isSensitiveUserAction || userIds.length <= 10);

  async function generate() {
    if (!canGenerate) return;
    setBusy(true);
    setError(null);
    const body: ChangeRequest = {
      action,
      tenantId,
      userIds,
      ...(isGroupAction ? { groupId } : {}),
      ...(isLicenseAction ? { skuId } : {}),
    };
    try {
      const preview = await api.changes.preview(body);
      setBusy(false);
      setAction("add_to_group");
      setGroupId("");
      setSkuId("");
      onClose();
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

  return (
    <Dialog open={open} onClose={close} width={440}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Play className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Run What If</h2>
            <p className="text-[12px] text-muted">
              Apply an action to {userIds.length} selected user{userIds.length === 1 ? "" : "s"}
            </p>
          </div>
        </div>

        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          Action
        </label>
        <select
          value={action}
          onChange={(e) => {
            setAction(e.target.value as ChangeRequest["action"]);
            setGroupId("");
            setSkuId("");
          }}
          className={SELECT_CLASS}
        >
          {USER_ACTIONS.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>

        {isGroupAction && (
          <>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Target group
            </label>
            <select
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              className={SELECT_CLASS}
            >
              <option value="">
                {groups.loading ? "Loading groups…" : "Select a group…"}
              </option>
              {groups.data?.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name} ({g.type})
                </option>
              ))}
            </select>
          </>
        )}

        {isLicenseAction && (
          <>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              License
            </label>
            <select
              value={skuId}
              onChange={(e) => setSkuId(e.target.value)}
              className={SELECT_CLASS}
            >
              <option value="">
                {licenses.loading ? "Loading licenses…" : "Select a license…"}
              </option>
              {licenses.data?.map((l) => (
                <option key={l.skuId} value={l.skuId}>
                  {l.product} ({l.available} available)
                </option>
              ))}
            </select>
          </>
        )}

        {action === "reset_password" && (
          <p className="mt-3 text-[12px] font-medium text-[#f7868a]">
            Replaces the password, forces a change at next sign-in, and cannot be reverted.
          </p>
        )}

        {action === "revoke_user_access" && (
          <div className="mt-3 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.08)] px-3 py-2.5 text-[12px] text-body">
            <p className="font-semibold text-[#f7868a]">Compromised-account containment</p>
            <p className="mt-1 text-muted">
              Resets the password, removes registered MFA methods, and signs the user out on every device. This cannot be reverted.
            </p>
          </div>
        )}

        {isSensitiveUserAction && userIds.length > 10 && (
          <p className="mt-3 text-[12px] font-medium text-[#f7868a]">
            Select no more than 10 users so RTM can return every one-time password safely.
          </p>
        )}

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <p className="mt-3 text-[12px] text-muted">
          The What-If preview is computed from the tenant's current state —
          nothing changes until you approve it.
        </p>

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button variant="accent" onClick={generate} disabled={!canGenerate || busy}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Generate Preview
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
