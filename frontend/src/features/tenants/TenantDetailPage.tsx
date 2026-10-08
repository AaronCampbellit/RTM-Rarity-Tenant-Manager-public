import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AlertTriangle, Building2, ChevronDown, KeyRound, Loader2, RefreshCw, Settings, ShieldCheck, Trash2 } from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { hasPermission, useAuth } from "@/store/auth";
import { useSetPageTitle } from "@/store/page";
import { useSync } from "@/store/sync";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Avatar } from "@/components/common/Avatar";
import { BackLink, SectionLabel } from "@/components/common/PageToolbar";
import { HybridNotice } from "@/components/common/HybridNotice";
import { tenantTone, changeTone, identityModeTone, identityModeLabel, isHybridMode } from "@/components/common/status";
import { roleTone } from "@/components/common/status";
import type { ExchangeBootstrapPreview, ExchangeBootstrapStart, Preflight, PreflightCheck } from "@/types";
import { EditTenantSettingsDialog } from "./EditTenantSettingsDialog";
import { groupPreflightChecks } from "./preflight";

export function TenantDetailPage() {
  useSetPageTitle("Tenant Detail");
  const { id } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const { version: syncVersion } = useSync();
  const [refreshKey, setRefreshKey] = useState(0);
  const tenant = useAsync(() => api.tenants.get(id ?? ""), [id, refreshKey, syncVersion], { enabled: Boolean(id) });
  const techs = useAsync(() => api.admin.technicians(), [syncVersion]);
  const changes = useAsync(() => api.changes.list(), [syncVersion]);
  const [removing, setRemoving] = useState(false);
  const [editing, setEditing] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [testOk, setTestOk] = useState(false);
  const [exchangeAuthorization, setExchangeAuthorization] = useState<"success" | "error" | "cancelled" | null>(null);
  const [exchangeBootstrapOpen, setExchangeBootstrapOpen] = useState(false);
  const [preflightRefresh, setPreflightRefresh] = useState(0);

  useEffect(() => {
    const status = searchParams.get("exchangeAuthorization");
    if (status !== "success" && status !== "error" && status !== "cancelled") return;
    setExchangeAuthorization(status);
    if (status === "success") setPreflightRefresh((value) => value + 1);
    const next = new URLSearchParams(searchParams);
    next.delete("exchangeAuthorization");
    next.delete("assignment");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  async function testConnection() {
    if (!id || testing) return;
    setTesting(true);
    setTestError(null);
    setTestOk(false);
    try {
      const res = await api.tenants.test(id);
      if (res.status === "Connected") {
        setTestOk(true);
      } else {
        setTestError(res.error || "The connection test failed.");
      }
    } catch (err) {
      setTestError(
        err instanceof RtmApiError ? err.message : "The connection test failed.",
      );
    } finally {
      setTesting(false);
      setRefreshKey((k) => k + 1); // pick up the persisted status + timestamp
    }
  }

  const t = tenant.data;

  if (tenant.error) {
    return (
      <div>
        <BackLink onClick={() => navigate("/tenants")}>Tenants</BackLink>
        <Card className="p-8 text-center text-[13px] text-[#f7868a]">
          {tenant.error.message}
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <BackLink onClick={() => navigate("/tenants")}>Tenants</BackLink>

      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="grid size-11 place-items-center rounded-[11px] bg-raised">
            <Building2 className="size-5 text-secondary" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-[18px] font-bold text-fg-strong">{t?.name ?? "…"}</h2>
              {t && <Badge tone={tenantTone(t.status)}>{t.status}</Badge>}
            </div>
            <p className="text-[12.5px] text-muted">{t?.domain ?? ""}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="default" onClick={testConnection} disabled={testing}>
            {testing ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <RefreshCw className="size-4" />
            )}
            {testing ? "Testing…" : "Test Connection"}
          </Button>
          {hasPermission(user, "tenants.manage") && t && (
            <>
              <Button variant="outline" onClick={() => setEditing(true)}>
                <Settings className="size-4" />
                Edit Tenant Settings
              </Button>
              <Button variant="outline" onClick={() => setRemoving(true)}>
                <Trash2 className="size-4" />
                Remove Tenant
              </Button>
            </>
          )}
        </div>
      </div>

      {testError && (
        <div className="flex items-start gap-2 rounded-[10px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3.5 py-2.5 text-[12.5px] text-[#f7868a]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{testError}</span>
        </div>
      )}
      {testOk && (
        <div className="rounded-[10px] border border-[rgba(48,164,108,.35)] bg-[rgba(48,164,108,.1)] px-3.5 py-2.5 text-[12.5px] text-[#5bd695]">
          Connection test succeeded — Microsoft Graph is reachable with this
          tenant's credentials.
        </div>
      )}
      {exchangeAuthorization && (
        <div className={`flex items-start gap-2 rounded-[10px] border px-3.5 py-2.5 text-[12.5px] ${exchangeAuthorization === "success" ? "border-[rgba(48,164,108,.35)] bg-[rgba(48,164,108,.1)] text-[#5bd695]" : exchangeAuthorization === "cancelled" ? "border-[rgba(210,154,35,.35)] bg-[rgba(210,154,35,.1)] text-[#efbd55]" : "border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] text-[#f7868a]"}`}>
          {exchangeAuthorization !== "success" && <AlertTriangle className="mt-0.5 size-4 shrink-0" />}
          <span>
            {exchangeAuthorization === "success"
              ? "Exchange authorization completed. RTM is re-running Permission Preflight now."
              : exchangeAuthorization === "cancelled"
                ? "Exchange authorization was cancelled; no role assignment was changed."
                : "Exchange authorization did not complete. Review the signing administrator and try again."}
          </span>
        </div>
      )}

      {t && (
        <EditTenantSettingsDialog
          open={editing}
          tenant={t}
          onClose={() => setEditing(false)}
          onSaved={() => setRefreshKey((key) => key + 1)}
        />
      )}

      {t && (
        <RemoveTenantDialog
          open={removing}
          tenant={t}
          onClose={() => setRemoving(false)}
          onRemoved={() => navigate("/tenants")}
        />
      )}

      {/* Hybrid AD identity notice — prominent when the tenant syncs objects
          from on-prem Active Directory. */}
      {t && isHybridMode(t.identityMode) && (
        <HybridNotice
          mode={t.identityMode}
          syncedUsers={t.syncedUsers}
          cloudUsers={t.cloudUsers}
          syncedGroups={t.syncedGroups}
          cloudGroups={t.cloudGroups}
        />
      )}

      {/* 4-up cards */}
      <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <InfoCard label="Microsoft Tenant ID" value={t?.microsoftTenantId ?? "…"} mono />
        <InfoCard label="Connection" value={t?.status ?? "…"} tone={t ? tenantTone(t.status) : undefined} />
        <InfoCard
          label="Identity"
          value={t ? identityModeLabel(t.identityMode) : "…"}
          tone={t ? identityModeTone(t.identityMode) : undefined}
        />
        <InfoCard label="Last Graph Test" value={t?.lastGraphTest ?? "…"} />
        <InfoCard label="Users" value={(t?.users ?? 0).toLocaleString()} />
      </div>

      {/* modules */}
      <div>
        <SectionLabel>Enabled Modules</SectionLabel>
        <div className="flex flex-wrap gap-2">
          {(t?.modules ?? []).map((m) => (
            <span
              key={m}
              className="rounded-[20px] border border-[var(--border-strong)] bg-control px-3 py-1.5 text-[12px] font-medium text-body"
            >
              {m}
            </span>
          ))}
        </div>
      </div>

      {/* service connections */}
      {t && (
        <div>
          <SectionLabel>Service Connections</SectionLabel>
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
            <ConnectionCard
              label="Microsoft Graph"
              configured={t.connections.graph}
              configuredText="Dedicated app registration"
              inheritedText="Using the global app"
            />
            <ConnectionCard
              label="Exchange Online"
              configured={t.connections.exchange}
              configuredText="Dedicated app registration"
              inheritedText="Inherits the Graph app"
              action={hasPermission(user, "tenants.manage") ? (
                <Button variant="outline" size="sm" onClick={() => setExchangeBootstrapOpen(true)}>
                  <KeyRound className="size-3.5" />
                  Authorize Exchange
                </Button>
              ) : undefined}
            />
            <ConnectionCard
              label="SharePoint Admin"
              configured={t.connections.sharePoint}
              configuredText="Admin URL + central certificate app"
              inheritedText="Admin URL not configured"
            />
          </div>
        </div>
      )}

      {/* preflight: required vs granted Graph permissions per feature area */}
      {t && <PreflightCard tenantId={t.id} refreshToken={preflightRefresh} />}

      {t && (
        <ExchangeBootstrapDialog
          open={exchangeBootstrapOpen}
          tenant={t}
          onClose={() => setExchangeBootstrapOpen(false)}
        />
      )}

      {/* techs + activity */}
      <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
        <Card>
          <div className="border-b border-[var(--border-card)] px-4 py-3">
            <h3 className="text-[13.5px] font-semibold text-fg">Assigned Technicians</h3>
          </div>
          <div>
            {techs.data?.slice(0, 4).map((tech) => (
              <div
                key={tech.id}
                className="flex items-center gap-3 border-b border-[var(--border-card)] px-4 py-2.5 last:border-0"
              >
                <Avatar name={tech.name} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[13px] font-semibold text-fg">{tech.name}</p>
                  <p className="truncate text-[12px] text-muted">{tech.email}</p>
                </div>
                <Badge tone={roleTone(tech.role)} dot={false}>
                  {tech.role}
                </Badge>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <div className="border-b border-[var(--border-card)] px-4 py-3">
            <h3 className="text-[13.5px] font-semibold text-fg">Recent Activity</h3>
          </div>
          <div>
            {changes.data?.slice(0, 5).map((c) => (
              <div
                key={c.id}
                className="flex items-center justify-between gap-3 border-b border-[var(--border-card)] px-4 py-2.5 last:border-0"
              >
                <div className="min-w-0">
                  <p className="truncate text-[13px] font-semibold text-fg">{c.action}</p>
                  <p className="truncate text-[12px] text-muted">
                    {c.technician} · {c.timestamp}
                  </p>
                </div>
                <Badge tone={changeTone(c.status)}>{c.status}</Badge>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
/** Preflight check: probes which Graph application permissions the tenant's
 * app registration actually holds, per RTM feature area — catching a missing
 * admin consent here instead of as a 403 mid-write. Write permissions can't
 * be probed without writing and show as "Unchecked". */
function PreflightCard({ tenantId, refreshToken = 0 }: { tenantId: string; refreshToken?: number }) {
  const [preflight, setPreflight] = useState<Preflight | null>(null);
  const [loadingSaved, setLoadingSaved] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function run() {
    setBusy(true);
    setError(null);
    setOpen(true);
    try {
      setPreflight(await api.tenants.runPreflight(tenantId));
    } catch (err) {
      setError(err instanceof RtmApiError ? err.message : "The preflight check failed.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    let alive = true;
    setLoadingSaved(true);
    setError(null);
    setPreflight(null);
    setOpen(false);
    api.tenants.preflight(tenantId)
      .then((saved) => {
        if (alive) setPreflight(saved);
      })
      .catch((err) => {
        if (!alive || (err instanceof RtmApiError && err.status === 404)) return;
        setError(err instanceof RtmApiError ? err.message : "The saved preflight result could not be loaded.");
        setOpen(true);
      })
      .finally(() => {
        if (alive) setLoadingSaved(false);
      });
    return () => {
      alive = false;
    };
  }, [tenantId]);

  useEffect(() => {
    if (refreshToken > 0) void run();
    // run is intentionally tied to the callback signal, not each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshToken]);

  const missing = preflight?.checks.filter((c) => c.status === "missing").length ?? 0;
  const failed = preflight?.checks.filter((c) => c.status === "error").length ?? 0;
  const unavailable = preflight?.checks.filter((c) => c.status === "not_provisioned").length ?? 0;
  const groups = useMemo(() => groupPreflightChecks(preflight?.checks ?? []), [preflight?.checks]);
  const detailsId = `permission-preflight-${tenantId}`;

  return (
    <Card>
      <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={detailsId}
          className="flex min-w-0 flex-1 items-center gap-3 rounded-[7px] text-left outline-none focus-visible:ring-2 focus-visible:ring-[var(--ac)]/50"
          onClick={() => setOpen((current) => !current)}
        >
          <ChevronDown className={`size-4 shrink-0 text-muted transition-transform ${open ? "rotate-0" : "-rotate-90"}`} />
          <div className="min-w-0">
            <h3 className="text-[13.5px] font-semibold text-fg">Permission Preflight</h3>
            <p className="text-[12px] text-muted">
              {loadingSaved
                ? "Loading the last saved permission snapshot…"
                : preflight
                  ? `Saved results from ${new Date(preflight.ranAt).toLocaleString()} · expand to review by RTM section.`
                  : "No saved preflight yet · run it once, then review the stored results here anytime."}
            </p>
          </div>
        </button>
        <div className="flex shrink-0 items-center gap-2.5 self-end sm:self-auto">
          {preflight && (
            <Badge tone={missing > 0 ? "danger" : failed > 0 || unavailable > 0 ? "warning" : preflight.mode === "sample" ? "neutral" : "success"}>
              {missing > 0
                ? `${missing} requirement${missing === 1 ? "" : "s"} missing`
                : failed > 0
                  ? `${failed} check${failed === 1 ? "" : "s"} need attention`
                  : unavailable > 0
                    ? `${unavailable} optional service${unavailable === 1 ? "" : "s"} unavailable`
                : preflight.mode === "sample"
                  ? "Sample mode"
                  : "All read probes passed"}
            </Badge>
          )}
          <Button variant="default" size="sm" onClick={run} disabled={busy}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />}
            {busy ? "Probing…" : preflight ? "Re-run Preflight" : "Run Preflight"}
          </Button>
        </div>
      </div>

      {open && (
        <div id={detailsId} className="border-t border-[var(--border-card)]">
          {error && (
            <div role="alert" className="mx-4 my-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {loadingSaved && !preflight && (
            <p className="flex items-center gap-2 px-4 py-4 text-[12.5px] text-muted">
              <Loader2 className="size-4 animate-spin" /> Loading saved results…
            </p>
          )}

          {!loadingSaved && !preflight && !error && (
            <p className="px-4 py-4 text-[12.5px] text-muted">
              No saved result is available. Run preflight once to probe the tenant with harmless reads; future visits will load that snapshot without contacting Microsoft again.
            </p>
          )}

          {preflight && groups.map((group) => {
            const categoryId = `${detailsId}-${group.category.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
            return (
            <section key={group.category} aria-labelledby={categoryId}>
              <div className="flex items-center justify-between gap-3 border-y border-[var(--border-card)] bg-th px-4 py-2 first:border-t-0">
                <div>
                  <h4 id={categoryId} className="text-[11px] font-bold uppercase tracking-[.45px] text-secondary">
                    {group.category}
                  </h4>
                  <p className="mt-0.5 text-[10.5px] text-faint">{group.checks.length} permission requirement{group.checks.length === 1 ? "" : "s"}</p>
                </div>
                <Badge tone={group.missing ? "danger" : group.attention ? "warning" : preflight.mode === "sample" ? "neutral" : "success"}>
                  {group.missing ? `${group.missing} missing` : group.attention ? `${group.attention} need attention` : preflight.mode === "sample" ? "Sample" : "Ready"}
                </Badge>
              </div>
              {group.checks.map((c) => (
                <div
                  key={`${c.resource ?? "Microsoft Graph"}:${c.area}:${c.permission}`}
                  className="flex flex-col gap-2 border-b border-[var(--border-card)] px-4 py-2.5 last:border-0 sm:flex-row sm:items-center sm:gap-3"
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[13px] font-semibold text-fg">{c.area}</p>
                    <p className="mono truncate text-[11.5px] text-muted">
                      {c.resource ?? "Microsoft Graph"} · {c.permission}
                    </p>
                  </div>
                  {c.detail && c.status !== "sample" && c.status !== "unchecked" && (
                    <p className="max-w-full text-[11.5px] leading-4 text-muted sm:max-w-[45%]" title={c.detail}>
                      {c.detail}
                    </p>
                  )}
                  <Badge className="self-start sm:self-auto" tone={preflightTone(c.status)} dot={false}>
                    {c.status === "ok" && c.grantedVia
                      ? `Granted via ${c.grantedVia}`
                      : preflightLabel(c.status)}
                  </Badge>
                </div>
              ))}
            </section>
            );
          })}
        </div>
      )}
    </Card>
  );
}

function preflightTone(status: PreflightCheck["status"]) {
  switch (status) {
    case "ok":
      return "success" as const;
    case "missing":
      return "danger" as const;
    case "error":
      return "warning" as const;
    case "not_provisioned":
      return "warning" as const;
    default: // sample | unchecked
      return "neutral" as const;
  }
}

function preflightLabel(status: PreflightCheck["status"]) {
  switch (status) {
    case "ok":
      return "Granted";
    case "missing":
      return "Missing";
    case "error":
      return "Error";
    case "not_provisioned":
      return "Defender unavailable";
    case "sample":
      return "Sample";
    default:
      return "Unchecked";
  }
}

function ExchangeBootstrapDialog({
  open,
  tenant,
  onClose,
}: {
  open: boolean;
  tenant: { id: string; name: string };
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authorization, setAuthorization] = useState<ExchangeBootstrapStart | null>(null);
  const [preview, setPreview] = useState<ExchangeBootstrapPreview | null>(null);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const details = preview?.preview ?? expectedExchangeBootstrapPreview;

  useEffect(() => {
    if (!open) return;
    let active = true;
    setBusy(true);
    setError(null);
    void api.tenants.previewExchangeBootstrap(tenant.id)
      .then((value) => { if (active) setPreview(value); })
      .catch((err) => { if (active) setError(err instanceof RtmApiError ? err.message : "The Exchange authorization preview could not be generated."); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [open, tenant.id]);

  function close() {
    if (busy) return;
    setError(null);
    setAuthorization(null);
    setPreview(null);
    setClientId("");
    setClientSecret("");
    onClose();
  }

  async function authorize() {
    if (!preview || !preview.httpsReady || !clientId.trim() || !clientSecret) return;
    setBusy(true);
    setError(null);
    try {
      const start = await api.tenants.startExchangeBootstrap(tenant.id, preview.approvalToken, clientId.trim(), clientSecret);
      setAuthorization(start);
      setClientId("");
      setClientSecret("");
      window.location.assign(start.authorizationUrl);
    } catch (err) {
      setClientSecret("");
      setError(err instanceof RtmApiError ? err.message : "Exchange authorization could not be started.");
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={close} width={620}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-[rgba(92,139,242,.12)]">
            <KeyRound className="size-4 text-[#82aaff]" />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-fg-strong">Authorize Exchange</h2>
            <p className="text-[12px] text-muted">{tenant.name}</p>
          </div>
        </div>

        <p className="mt-3 text-[12.5px] leading-relaxed text-muted">
          A tenant administrator will sign in to Microsoft for one short-lived setup session. RTM will make exactly one idempotent Exchange role assignment to its runtime app.
        </p>

        <div className="mt-4 space-y-2 rounded-[10px] border border-[var(--border-card)] bg-raised p-3.5 text-[12px]">
          <AuthorizationRow label="Temporary delegated permission" value={details.delegatedPermission} />
          <AuthorizationRow label="Runtime application permission" value={details.runtimePermission} />
          <AuthorizationRow label="Exchange role" value={details.exchangeRole} />
          <AuthorizationRow label="Assignment scope" value={details.scope} />
          <AuthorizationRow label="Bootstrap token" value={details.tokenRetention} />
        </div>

        <div className="mt-3 rounded-[10px] border border-[var(--border-card)] bg-raised p-3.5">
          <p className="text-[12px] font-semibold text-fg-strong">One-time bootstrap application</p>
          <p className="mt-1 text-[11.5px] leading-relaxed text-muted">
            Enter the temporary confidential app credentials for this run. RTM keeps them only in memory until Microsoft returns or the 10-minute attempt expires.
          </p>
          <label className="mt-3 block text-[11.5px] font-medium text-muted" htmlFor="exchange-bootstrap-callback">Web redirect URI</label>
          <Input id="exchange-bootstrap-callback" className="mt-1 mono text-[11px]" value={preview?.callbackUrl ?? "Preparing callback URL…"} readOnly />
          <p className="mt-1 text-[10.5px] text-muted">Register this exact URI as a Web redirect URI on the bootstrap app.</p>
          <label className="mt-3 block text-[11.5px] font-medium text-muted" htmlFor="exchange-bootstrap-client-id">Application (client) ID</label>
          <Input id="exchange-bootstrap-client-id" className="mt-1 mono" value={clientId} onChange={(event) => setClientId(event.target.value)} placeholder="00000000-0000-0000-0000-000000000000" autoComplete="off" spellCheck={false} disabled={busy} />
          <label className="mt-3 block text-[11.5px] font-medium text-muted" htmlFor="exchange-bootstrap-client-secret">Client secret</label>
          <Input id="exchange-bootstrap-client-secret" className="mt-1 mono" type="password" value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} placeholder="Enter for this authorization only" autoComplete="off" spellCheck={false} disabled={busy} />
        </div>

        {preview && !preview.httpsReady && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] leading-relaxed text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>RTM needs a Microsoft-reachable HTTPS URL before authorization can start. The callback above is derived from this RTM deployment.</span>
          </div>
        )}

        <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(210,154,35,.3)] bg-[rgba(210,154,35,.08)] px-3 py-2 text-[12px] leading-relaxed text-[#efbd55]">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>The Exchange role-assignment endpoint is Microsoft Graph beta. The signed-in Microsoft account must be allowed to manage Exchange roles.</span>
        </div>

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="default" onClick={close} disabled={busy}>Cancel</Button>
          <Button variant="accent" onClick={authorize} disabled={busy || !preview || !preview.httpsReady || !clientId.trim() || !clientSecret || authorization !== null}>
            {busy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
            {busy ? (preview ? "Opening Microsoft…" : "Preparing preview…") : "Continue to Microsoft"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

const expectedExchangeBootstrapPreview: ExchangeBootstrapStart["preview"] = {
  delegatedPermission: "RoleManagement.ReadWrite.Exchange",
  runtimePermission: "Exchange.ManageAsAppV2",
  exchangeRole: "Recipient Management",
  scope: "All mailboxes in this tenant",
  tokenRetention: "Discarded immediately after authorization",
  apiVersion: "Microsoft Graph beta",
};

function AuthorizationRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-muted">{label}</span>
      <span className="mono max-w-[58%] break-words text-right text-[11.5px] text-fg">{value}</span>
    </div>
  );
}

/** Destructive confirm: the tenant name must be typed back before the delete
 * fires. Removal revokes technician grants with it (server-side, audited). */
function RemoveTenantDialog({
  open,
  tenant,
  onClose,
  onRemoved,
}: {
  open: boolean;
  tenant: { id: string; name: string };
  onClose: () => void;
  onRemoved: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const armed = typed === tenant.name;

  function close() {
    if (busy) return;
    setTyped("");
    setError(null);
    onClose();
  }

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await api.tenants.remove(tenant.id);
      onRemoved();
    } catch (err) {
      setError(
        err instanceof RtmApiError
          ? err.message
          : "Unable to remove the tenant. Please try again.",
      );
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={close} width={460}>
      <div className="px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="grid size-9 place-items-center rounded-[9px] bg-[rgba(229,72,77,.12)]">
            <Trash2 className="size-4 text-[#f7868a]" />
          </div>
          <h2 className="text-[15px] font-bold text-fg-strong">Remove tenant</h2>
        </div>
        <p className="mt-3 text-[12.5px] leading-relaxed text-muted">
          This disconnects <span className="font-semibold text-fg">{tenant.name}</span> from
          RTM, deletes its stored connection credentials, and revokes every
          technician's access to it. Microsoft 365 itself is not modified. This
          cannot be undone.
        </p>
        <label className="mb-1.5 mt-4 block text-[12px] font-semibold text-secondary">
          Type <span className="mono text-fg">{tenant.name}</span> to confirm
        </label>
        <Input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={tenant.name}
          autoFocus
        />

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-[8px] border border-[rgba(229,72,77,.35)] bg-[rgba(229,72,77,.1)] px-3 py-2 text-[12.5px] text-[#f7868a]">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="default" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button variant="accent" onClick={confirm} disabled={!armed || busy}>
            {busy && <Loader2 className="size-4 animate-spin" />}
            Remove Tenant
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

/** One service-integration row: shows whether the tenant has a dedicated app
 * registration stored or inherits the Graph / global app. */
function ConnectionCard({
  label,
  configured,
  configuredText,
  inheritedText,
  unconfiguredBadge = "Inherited",
  action,
}: {
  label: string;
  configured: boolean;
  configuredText: string;
  inheritedText: string;
  unconfiguredBadge?: string;
  action?: React.ReactNode;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">{label}</p>
        <Badge tone={configured ? "success" : "neutral"} dot={false}>
          {configured ? "Configured" : unconfiguredBadge}
        </Badge>
      </div>
      <p className="mt-2 text-[12.5px] text-secondary">
        {configured ? configuredText : inheritedText}
      </p>
      {action && <div className="mt-2.5">{action}</div>}
    </Card>
  );
}

function InfoCard({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: ReturnType<typeof tenantTone>;
}) {
  return (
    <Card className="p-4">
      <p className="text-[10.5px] font-bold uppercase tracking-[.5px] text-faint">{label}</p>
      {tone ? (
        <div className="mt-2">
          <Badge tone={tone}>{value}</Badge>
        </div>
      ) : (
        <p className={`mt-1.5 break-words text-[13px] font-semibold text-fg ${mono ? "mono text-[12px]" : ""}`}>
          {value}
        </p>
      )}
    </Card>
  );
}
