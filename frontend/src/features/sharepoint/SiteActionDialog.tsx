import { useState } from "react";
import { AlertTriangle, Loader2, Play } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useModals } from "@/store/modals";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import type { ChangeRequest, Site } from "@/types";

const LEVELS: { value: Site["externalSharing"]; hint: string }[] = [
  { value: "Internal", hint: "No external sharing — organization accounts only" },
  { value: "External", hint: "New and existing guests can be invited" },
  { value: "Anyone", hint: "Anonymous sharing links — no sign-in required" },
];

const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[13px] text-fg outline-none focus:border-[var(--ac)]";

/**
 * Step 1 of the SharePoint sharing write flow: pick the external sharing
 * level for the selected sites, then generate the live What-If preview and
 * hand off to the mandatory What-If gate.
 */
export function SiteActionDialog({
  open,
  tenantId,
  siteIds,
  onClose,
}: {
  open: boolean;
  tenantId: string;
  siteIds: string[];
  onClose: () => void;
}) {
  const { openWhatIf } = useModals();
  const [level, setLevel] = useState<Site["externalSharing"]>("Internal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function close() {
    if (busy) return;
    setLevel("Internal");
    setError(null);
    onClose();
  }

  async function generate() {
    setBusy(true);
    setError(null);
    const body: ChangeRequest = {
      action: "set_site_sharing",
      tenantId,
      siteIds,
      sharingLevel: level,
    };
    try {
      const preview = await api.changes.preview(body);
      setBusy(false);
      setLevel("Internal");
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

  const hint = LEVELS.find((l) => l.value === level)?.hint;

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
              Change external sharing on {siteIds.length} selected site
              {siteIds.length === 1 ? "" : "s"}
            </p>
          </div>
        </div>

        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          External sharing level
        </label>
        <select
          value={level}
          onChange={(e) => setLevel(e.target.value as Site["externalSharing"])}
          className={SELECT_CLASS}
        >
          {LEVELS.map((l) => (
            <option key={l.value} value={l.value}>
              {l.value}
            </option>
          ))}
        </select>
        {hint && <p className="mt-2 text-[12px] text-muted">{hint}</p>}

        {level === "Anyone" && (
          <p className="mt-3 text-[12px] font-medium text-[#f7868a]">
            “Anyone” enables anonymous access links on these sites.
          </p>
        )}
        <p className="mt-3 text-[12px] font-medium text-[#f5b569]">
          The previous sharing level is not snapshotted — this cannot be
          reverted automatically.
        </p>

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
          <Button variant="accent" onClick={generate} disabled={busy}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Generate Preview
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
