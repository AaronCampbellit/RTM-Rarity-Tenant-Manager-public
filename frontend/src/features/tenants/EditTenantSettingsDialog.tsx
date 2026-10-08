import { useEffect, useState } from "react";
import { AlertTriangle, Building2, Loader2, X } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { Tenant, TenantSettingsUpdate } from "@/types";

export function EditTenantSettingsDialog({
  open,
  tenant,
  onClose,
  onSaved,
}: {
  open: boolean;
  tenant: Tenant;
  onClose: () => void;
  onSaved: (tenant: Tenant) => void;
}) {
  const [name, setName] = useState(tenant.name);
  const [domain, setDomain] = useState(tenant.domain);
  const [directoryId, setDirectoryId] = useState(tenant.microsoftTenantId);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [exchangeClientId, setExchangeClientId] = useState("");
  const [exchangeSecret, setExchangeSecret] = useState("");
  const [sharePointAdminUrl, setSharePointAdminUrl] = useState("");
  const [clearGraph, setClearGraph] = useState(false);
  const [clearExchange, setClearExchange] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setName(tenant.name);
    setDomain(tenant.domain);
    setDirectoryId(tenant.microsoftTenantId);
    setClientId("");
    setClientSecret("");
    setExchangeClientId("");
    setExchangeSecret("");
    setSharePointAdminUrl("");
    setClearGraph(false);
    setClearExchange(false);
    setError(null);
  }, [open, tenant]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (!name.trim() || !domain.trim() || !directoryId.trim()) {
      setError("Tenant name, domain, and directory ID are required.");
      return;
    }
    if (!clearGraph && ((clientId === "") !== (clientSecret === ""))) {
      setError("Replacing the Graph app requires both a client ID and replacement secret.");
      return;
    }
    if (!clearExchange && ((exchangeClientId === "") !== (exchangeSecret === ""))) {
      setError("Replacing the Exchange app requires both a client ID and replacement secret.");
      return;
    }
    if (sharePointAdminUrl && !/^https:\/\/[^/]+\.sharepoint\.com\/?$/i.test(sharePointAdminUrl.trim())) {
      setError("SharePoint admin URL must be an HTTPS sharepoint.com URL.");
      return;
    }
    const body: TenantSettingsUpdate = {
      name: name.trim(),
      domain: domain.trim(),
      microsoftTenantId: directoryId.trim(),
      clearGraph,
      clearExchange,
    };
    if (!clearGraph && clientId) {
      body.clientId = clientId.trim();
      body.clientSecret = clientSecret;
    }
    if (!clearExchange && exchangeClientId) {
      body.exchangeClientId = exchangeClientId.trim();
      body.exchangeClientSecret = exchangeSecret;
    }
    if (sharePointAdminUrl.trim()) body.sharePointAdminUrl = sharePointAdminUrl.trim();
    setBusy(true);
    try {
      const result = await api.tenants.update(tenant.id, body);
      onSaved(result.tenant);
      onClose();
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "Unable to update tenant settings.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={() => !busy && onClose()} width={620}>
      <div className="flex items-center justify-between border-b border-[var(--border-card)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-raised"><Building2 className="size-4 text-secondary" /></div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Edit Tenant Settings</h2>
            <p className="text-[12px] text-muted">Blank secret fields preserve the current stored value.</p>
          </div>
        </div>
        <button onClick={onClose} disabled={busy} className="grid size-8 place-items-center rounded-[8px] text-muted hover:bg-raised" aria-label="Close">
          <X className="size-4" />
        </button>
      </div>
      <form onSubmit={submit} className="max-h-[72vh] space-y-3.5 overflow-y-auto px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Tenant name"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Primary domain"><Input value={domain} onChange={(e) => setDomain(e.target.value)} /></Field>
        </div>
        <Field label="Directory (tenant) ID"><Input className="mono" value={directoryId} onChange={(e) => setDirectoryId(e.target.value)} /></Field>

        <ServiceSection title="Microsoft Graph" configured={tenant.connections.graph} clear={clearGraph} onClear={() => setClearGraph(!clearGraph)} clearLabel="Use global app">
          <Field label="Replacement client ID"><Input disabled={clearGraph} className="mono" value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="Leave blank to keep current app" /></Field>
          <Field label="Replacement client secret"><Input disabled={clearGraph} type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder="Leave blank to keep current secret" autoComplete="off" /></Field>
        </ServiceSection>

        <ServiceSection title="Exchange Online" configured={tenant.connections.exchange} clear={clearExchange} onClear={() => setClearExchange(!clearExchange)} clearLabel="Use inherited Graph app">
          <Field label="Replacement client ID"><Input disabled={clearExchange} className="mono" value={exchangeClientId} onChange={(e) => setExchangeClientId(e.target.value)} placeholder="Leave blank to keep current app" /></Field>
          <Field label="Replacement client secret"><Input disabled={clearExchange} type="password" value={exchangeSecret} onChange={(e) => setExchangeSecret(e.target.value)} placeholder="Leave blank to keep current secret" autoComplete="off" /></Field>
        </ServiceSection>

        <ServiceSection title="SharePoint administration" configured={tenant.connections.sharePoint}>
          <Field label="SharePoint admin URL"><Input className="mono" value={sharePointAdminUrl} onChange={(e) => setSharePointAdminUrl(e.target.value)} placeholder={tenant.connections.sharePoint ? "Leave blank to keep current URL" : "https://contoso-admin.sharepoint.com"} /></Field>
        </ServiceSection>

        {error && <div className="flex gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]"><AlertTriangle className="mt-0.5 size-4 shrink-0" />{error}</div>}
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" variant="default" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button type="submit" variant="accent" disabled={busy}>{busy && <Loader2 className="size-4 animate-spin" />}Save Settings</Button>
        </div>
      </form>
    </Dialog>
  );
}

function ServiceSection({ title, configured, clear, onClear, clearLabel, children }: {
  title: string; configured: boolean; clear?: boolean; onClear?: () => void; clearLabel?: string; children: React.ReactNode;
}) {
  return <div className="space-y-3 rounded-[10px] border border-[var(--border-card)] bg-raised/40 p-3.5">
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-2"><p className="text-[12px] font-semibold text-secondary">{title}</p><Badge tone={configured ? "success" : "neutral"}>{configured ? "Configured" : "Inherited / not configured"}</Badge></div>
      {configured && onClear && <label className="flex items-center gap-2 text-[11.5px] text-muted"><Checkbox checked={!!clear} onChange={onClear} />{clearLabel}</label>}
    </div>
    {children}
  </div>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><label className="mb-1.5 block text-[12px] font-semibold text-secondary">{label}</label>{children}</div>;
}
