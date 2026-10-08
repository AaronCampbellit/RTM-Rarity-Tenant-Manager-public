import { useState } from "react";
import { AlertTriangle, Loader2, Play } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import type { ChangeRequest, MailboxPermission } from "@/types";

const ACTIONS: { value: ChangeRequest["action"]; label: string }[] = [
  { value: "set_forwarding", label: "Set mail forwarding" },
  { value: "clear_forwarding", label: "Clear mail forwarding" },
  { value: "enable_auto_reply", label: "Enable auto-reply" },
  { value: "disable_auto_reply", label: "Disable auto-reply" },
  { value: "grant_mailbox_permission", label: "Grant mailbox permission" },
  { value: "revoke_mailbox_permission", label: "Revoke mailbox permission" },
];

const PERMISSIONS: MailboxPermission["permission"][] = [
  "Full Access",
  "Send As",
  "Send on Behalf",
];

const PERM_ACTIONS = new Set<ChangeRequest["action"]>([
  "grant_mailbox_permission",
  "revoke_mailbox_permission",
]);

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

/**
 * Step 1 of the Exchange write flow: choose the mailbox action and its
 * parameters (forwarding address, auto-reply message, or delegate +
 * permission), then generate the live What-If preview and hand off to the
 * mandatory What-If gate.
 */
export function ExchangeActionDialog({
  open,
  tenantId,
  mailboxIds,
  onClose,
}: {
  open: boolean;
  tenantId: string;
  mailboxIds: string[];
  onClose: () => void;
}) {
  const { openWhatIf } = useModals();
  const [action, setAction] = useState<ChangeRequest["action"]>("set_forwarding");
  const isPermAction = PERM_ACTIONS.has(action);

  const users = useAsync(
    () => (open && isPermAction ? api.users.list(tenantId) : Promise.resolve([])),
    [tenantId, open, isPermAction],
  );

  const [forwardTo, setForwardTo] = useState("");
  const [message, setMessage] = useState("");
  const [delegateId, setDelegateId] = useState("");
  const [permission, setPermission] = useState<MailboxPermission["permission"]>("Send on Behalf");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setAction("set_forwarding");
    setForwardTo("");
    setMessage("");
    setDelegateId("");
    setPermission("Send on Behalf");
    setError(null);
  }

  function close() {
    if (busy) return;
    reset();
    onClose();
  }

  const canGenerate =
    action === "set_forwarding"
      ? forwardTo.includes("@")
      : action === "enable_auto_reply"
        ? message.trim().length > 0
        : isPermAction
          ? !!delegateId
          : true;

  async function generate() {
    if (!canGenerate) return;
    setBusy(true);
    setError(null);
    const body: ChangeRequest = {
      action,
      tenantId,
      mailboxIds,
      ...(action === "set_forwarding" ? { forwardTo } : {}),
      ...(action === "enable_auto_reply" ? { autoReplyMessage: message } : {}),
      ...(isPermAction ? { delegateId, permission } : {}),
    };
    try {
      const preview = await api.changes.preview(body);
      setBusy(false);
      reset();
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
              Apply an action to {mailboxIds.length} selected mailbox
              {mailboxIds.length === 1 ? "" : "es"}
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
            setError(null);
          }}
          className={SELECT_CLASS}
        >
          {ACTIONS.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>

        {action === "set_forwarding" && (
          <>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Forward to
            </label>
            <Input
              type="email"
              placeholder="mailbox@domain.com"
              value={forwardTo}
              onChange={(e) => setForwardTo(e.target.value)}
            />
            <p className="mt-2 text-[12px] font-medium text-[#f5b569]">
              All new mail will be forwarded — double-check external addresses.
            </p>
          </>
        )}

        {action === "enable_auto_reply" && (
          <>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Auto-reply message
            </label>
            <Textarea
              rows={3}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="I am out of the office until…"
            />
          </>
        )}

        {isPermAction && (
          <>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Delegate
            </label>
            <select
              value={delegateId}
              onChange={(e) => setDelegateId(e.target.value)}
              className={SELECT_CLASS}
            >
              <option value="">
                {users.loading ? "Loading users…" : "Select a user…"}
              </option>
              {users.data?.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.name} ({u.upn})
                </option>
              ))}
            </select>
            <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
              Permission
            </label>
            <select
              value={permission}
              onChange={(e) => setPermission(e.target.value as MailboxPermission["permission"])}
              className={SELECT_CLASS}
            >
              {PERMISSIONS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <p className="mt-2 text-[11.5px] leading-5 text-muted">
              Send on Behalf is supported by the live Exchange Admin API. Full
              Access and Send As require the controlled PowerShell connector
              and currently fail closed for live tenants.
            </p>
          </>
        )}

        {(action === "clear_forwarding" || action === "disable_auto_reply") && (
          <p className="mt-3 text-[12px] font-medium text-[#f5b569]">
            The previous state is not snapshotted — this cannot be reverted
            automatically.
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
