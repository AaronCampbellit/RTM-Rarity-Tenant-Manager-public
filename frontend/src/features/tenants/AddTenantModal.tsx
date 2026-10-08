import { useState } from "react";
import { AlertTriangle, Building2, Clock3, Loader2, X } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { CreatedTenant } from "@/types";

type HistoryWindow = "start_now" | "last_24h" | "last_7d" | "maximum_available";
type HistoricalIncidentMode = "recent_24h" | "all" | "baseline_only";

const HISTORY_WINDOW_OPTIONS: ReadonlyArray<readonly [HistoryWindow, string, string]> = [
  ["start_now", "Start now", "No historical import"],
  ["last_24h", "Past 24 hours", "Quick context"],
  ["last_7d", "Past 7 days", "Recommended"],
  ["maximum_available", "Maximum available", "Up to 7 days today"],
];

/**
 * Connect a new managed tenant (admin-only). Directory (tenant) ID, plus an
 * optional per-tenant app registration — leave the client fields empty to use
 * the global app registration configured on the server. The secret is
 * write-only: the API stores it and never returns it.
 */
export function AddTenantModal({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  /** Fired as soon as the tenant is saved (even if its connection test
   * failed); closing is handled by the modal itself. */
  onCreated: (t: CreatedTenant) => void;
}) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [directoryId, setDirectoryId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [exClientId, setExClientId] = useState("");
  const [exClientSecret, setExClientSecret] = useState("");
  const [spAdminUrl, setSpAdminUrl] = useState("");
  const [historyWindow, setHistoryWindow] = useState<HistoryWindow>("last_7d");
  const [historicalIncidentMode, setHistoricalIncidentMode] =
    useState<HistoricalIncidentMode>("recent_24h");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Set when the tenant was saved but its first connection test failed — the
  // modal stays open to show why (missing consent, bad secret, …).
  const [savedWarning, setSavedWarning] = useState<string | null>(null);

  function reset() {
    setName("");
    setDomain("");
    setDirectoryId("");
    setClientId("");
    setClientSecret("");
    setExClientId("");
    setExClientSecret("");
    setSpAdminUrl("");
    setHistoryWindow("last_7d");
    setHistoricalIncidentMode("recent_24h");
    setError(null);
    setSavedWarning(null);
    setBusy(false);
  }

  function close() {
    if (busy) return;
    reset();
    onClose();
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if ((clientId === "") !== (clientSecret === "")) {
      setError(
        "Provide both a client ID and a client secret, or leave both empty to use the global app registration.",
      );
      return;
    }
    if ((exClientId === "") !== (exClientSecret === "")) {
      setError(
        "Provide both an Exchange Online client ID and secret, or leave both empty to reuse the Graph app.",
      );
      return;
    }
    if (spAdminUrl.trim() === "") {
      setError("The SharePoint admin URL is required for inventory and permission management.");
      return;
    }
    setBusy(true);
    try {
      const created = await api.tenants.create({
        name,
        domain,
        microsoftTenantId: directoryId,
        clientId: clientId || undefined,
        clientSecret: clientSecret || undefined,
        exchangeClientId: exClientId || undefined,
        exchangeClientSecret: exClientSecret || undefined,
        sharePointAdminUrl: spAdminUrl.trim() || undefined,
        historyWindow,
        historicalIncidentMode:
          historyWindow === "start_now" ? "baseline_only" : historicalIncidentMode,
      });
      if (created.connectionError) {
        // Saved, but Microsoft said no: keep the modal up with the reason.
        setBusy(false);
        setSavedWarning(created.connectionError);
        onCreated(created);
        return;
      }
      reset();
      onCreated(created);
      onClose();
    } catch (err) {
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Unable to connect the tenant. Please try again.",
      );
      setBusy(false);
    }
  }

  if (savedWarning) {
    return (
      <Dialog open={open} onClose={close} width={520}>
        <div className="px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="grid size-9 place-items-center rounded-[9px] bg-[rgba(245,166,35,.12)]">
              <AlertTriangle className="size-4 text-[#f5c163]" />
            </div>
            <h2 className="text-[15px] font-bold text-fg-strong">
              Tenant saved — not connected yet
            </h2>
          </div>
          <p className="mt-3 text-[12.5px] leading-relaxed text-muted">
            <span className="font-semibold text-fg">{name}</span> was added and
            its credentials are stored, but the connection test failed:
          </p>
          <div className="mt-2.5 rounded-[8px] border border-[rgba(245,166,35,.3)] bg-[rgba(245,166,35,.08)] px-3 py-2 text-[12.5px] leading-relaxed text-[#f5c163]">
            {savedWarning}
          </div>
          <p className="mt-2.5 text-[12px] text-muted">
            Fix the app registration in Entra, then use{" "}
            <span className="font-semibold text-secondary">Test Connection</span>{" "}
            on the tenant page to retry — no need to re-add the tenant.
          </p>
          <div className="mt-4 flex justify-end">
            <Button variant="accent" onClick={close}>
              Got it
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onClose={close} width={520}>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised">
            <Building2 className="size-4 text-secondary" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Connect Tenant</h2>
            <p className="text-[12px] text-muted">
              The connection is tested immediately with the tenant's credentials.
            </p>
          </div>
        </div>
        <button
          onClick={close}
          className="grid size-8 cursor-pointer place-items-center rounded-[8px] text-muted hover:bg-raised hover:text-fg"
          aria-label="Close"
        >
          <X className="size-4" />
        </button>
      </div>

      <form onSubmit={submit} className="space-y-3.5 px-5 py-4">
        <Field label="Tenant name" required>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Fabrikam, Inc."
            required
            autoFocus
          />
        </Field>
        <Field label="Primary domain" required>
          <Input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="fabrikam.onmicrosoft.com"
            required
          />
        </Field>
        <Field label="Directory (tenant) ID" required>
          <Input
            value={directoryId}
            onChange={(e) => setDirectoryId(e.target.value)}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="mono"
            required
          />
        </Field>

        <div className="rounded-[10px] border border-[rgba(93,145,255,.28)] bg-[rgba(93,145,255,.06)] p-3.5">
          <div className="flex items-start gap-2.5">
            <div className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-[8px] bg-[rgba(93,145,255,.12)]">
              <Clock3 className="size-4 text-info" />
            </div>
            <div>
              <p className="text-[12px] font-semibold text-secondary">
                Security history import
              </p>
              <p className="mt-0.5 text-[11.5px] leading-relaxed text-muted">
                Live monitoring starts immediately. Historical evidence imports
                separately in the background for baselines and rule building.
              </p>
            </div>
          </div>
          <fieldset className="mt-3">
            <legend className="mb-1.5 text-[11px] font-semibold text-secondary">
              Evidence window
            </legend>
            <div className="grid grid-cols-2 gap-2" data-testid="history-window-options">
              {HISTORY_WINDOW_OPTIONS.map(([value, label, detail]) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setHistoryWindow(value)}
                  aria-pressed={historyWindow === value}
                  className={`rounded-[8px] border px-2.5 py-2 text-left transition ${
                    historyWindow === value
                      ? "border-[var(--ac)]/55 bg-[rgba(229,72,77,.1)]"
                      : "border-[var(--border-card)] bg-control hover:border-[var(--border-strong)]"
                  }`}
                >
                  <span className="block text-[11.5px] font-semibold text-fg">{label}</span>
                  <span
                    className={`mt-0.5 block text-[10px] ${
                      value === "last_7d" ? "text-info" : "text-muted"
                    }`}
                  >
                    {detail}
                  </span>
                </button>
              ))}
            </div>
          </fieldset>
          <label className="mt-3 block">
            <span className="mb-1.5 block text-[11px] font-semibold text-secondary">
              Historical alert handling
            </span>
            <select
              value={historyWindow === "start_now" ? "baseline_only" : historicalIncidentMode}
              onChange={(event) =>
                setHistoricalIncidentMode(event.target.value as HistoricalIncidentMode)
              }
              disabled={historyWindow === "start_now"}
              className="h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[11.5px] text-body outline-none focus:border-[var(--ac)]/50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <option value="recent_24h">
                Use all history for baselines; open incidents only from the latest 24 hours
                (recommended)
              </option>
              <option value="all">Create incidents for every matching historical event</option>
              <option value="baseline_only">
                Baseline only — do not create incidents from imported history
              </option>
            </select>
          </label>
          <p className="mt-2 text-[10.5px] leading-relaxed text-muted">
            Microsoft 365 audit history is currently limited to seven days. Imported records
            are deduplicated against the live Graph and unified-audit lanes.
          </p>
        </div>

        <div className="rounded-[10px] border border-[var(--border-card)] bg-raised/40 p-3.5">
          <p className="text-[12px] font-semibold text-secondary">
            Microsoft Graph app registration (optional)
          </p>
          <p className="mb-3 mt-0.5 text-[11.5px] text-muted">
            Leave empty to use the global app registration configured on the
            server. The client secret is stored server-side and never shown
            again.
          </p>
          <div className="space-y-3">
            <Field label="Client ID">
              <Input
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                placeholder="Application (client) ID"
                className="mono"
              />
            </Field>
            <Field label="Client secret">
              <Input
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder="Secret value"
                autoComplete="off"
              />
            </Field>
          </div>
        </div>

        <div className="rounded-[10px] border border-[var(--border-card)] bg-raised/40 p-3.5">
          <p className="text-[12px] font-semibold text-secondary">
            Exchange Online admin app (optional)
          </p>
          <p className="mb-3 mt-0.5 text-[11.5px] text-muted">
            Dedicated app registration for the Exchange Online Admin API.
            Send on Behalf requires Exchange.ManageAsAppV2 plus Recipient
            Management RBAC. Leave empty to reuse the Graph app above.
          </p>
          <div className="space-y-3">
            <Field label="Client ID">
              <Input
                value={exClientId}
                onChange={(e) => setExClientId(e.target.value)}
                placeholder="Application (client) ID"
                className="mono"
              />
            </Field>
            <Field label="Client secret">
              <Input
                type="password"
                value={exClientSecret}
                onChange={(e) => setExClientSecret(e.target.value)}
                placeholder="Secret value"
                autoComplete="off"
              />
            </Field>
          </div>
        </div>

        <div className="rounded-[10px] border border-[var(--border-card)] bg-raised/40 p-3.5">
          <p className="text-[12px] font-semibold text-secondary">
            SharePoint administration
          </p>
          <p className="mb-3 mt-0.5 text-[11.5px] text-muted">
            RTM uses the centrally configured certificate-backed app. Enter
            this tenant&apos;s SharePoint admin URL; no tenant certificate or
            client secret is stored here.
          </p>
          <div className="space-y-3">
            <Field label="SharePoint admin URL">
              <Input
                value={spAdminUrl}
                onChange={(e) => setSpAdminUrl(e.target.value)}
                placeholder="https://contoso-admin.sharepoint.com"
                className="mono"
              />
            </Field>
          </div>
        </div>

        {error && (
          <div className="flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" variant="accent" disabled={busy}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Connect Tenant
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-[12px] font-semibold text-secondary">
        {label}
        {required && <span className="text-[var(--ac)]"> *</span>}
      </label>
      {children}
    </div>
  );
}
