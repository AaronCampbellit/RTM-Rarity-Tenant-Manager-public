import { useEffect, useMemo, useState } from "react";
import {
  Braces,
  Building2,
  CheckCircle2,
  Cloud,
  Contact,
  KeyRound,
  ListTree,
  Loader2,
  Search,
  Server,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import { api, RtmApiError } from "@/api/client";
import { Avatar } from "@/components/common/Avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { User, UserRaw } from "@/types";
import {
  attributeSummary,
  formatUserDate,
  humanizeUserAttribute,
  isPopulatedAttribute,
  stringList,
} from "./userRaw";

type View = "overview" | "attributes" | "json";

const OVERVIEW_SECTIONS = [
  {
    title: "Organization",
    icon: Building2,
    fields: ["jobTitle", "department", "companyName", "employeeId", "employeeType", "employeeHireDate", "officeLocation"],
  },
  {
    title: "Contact & location",
    icon: Contact,
    fields: ["mail", "businessPhones", "mobilePhone", "otherMails", "streetAddress", "city", "state", "postalCode", "country", "usageLocation", "preferredLanguage"],
  },
  {
    title: "Directory identity",
    icon: KeyRound,
    fields: ["userPrincipalName", "mailNickname", "identities", "proxyAddresses", "imAddresses", "securityIdentifier"],
  },
  {
    title: "Directory source",
    icon: Server,
    fields: ["onPremisesSamAccountName", "onPremisesUserPrincipalName", "onPremisesDomainName", "onPremisesDistinguishedName", "onPremisesLastSyncDateTime", "onPremisesImmutableId"],
  },
] as const;

const DATE_FIELDS = new Set([
  "createdDateTime",
  "employeeHireDate",
  "externalUserStateChangeDateTime",
  "onPremisesLastSyncDateTime",
  "signInSessionsValidFromDateTime",
]);

export function UserRawModal({
  open,
  tenantId,
  user,
  onClose,
}: {
  open: boolean;
  tenantId: string;
  user: User | null;
  onClose: () => void;
}) {
  const [raw, setRaw] = useState<UserRaw | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [filter, setFilter] = useState("");

  useEffect(() => {
    if (!open || !user) return;
    setRaw(null);
    setError(null);
    setView("overview");
    setFilter("");
    setLoading(true);
    api.users
      .raw(tenantId, user.id)
      .then(setRaw)
      .catch((reason) =>
        setError(reason instanceof RtmApiError ? reason.message : "Could not load the user details."),
      )
      .finally(() => setLoading(false));
  }, [open, tenantId, user]);

  const entries = useMemo(
    () => raw ? Object.entries(raw.attributes).sort(([left], [right]) => left.localeCompare(right)) : [],
    [raw],
  );
  const filteredEntries = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return entries;
    return entries.filter(([key, value]) =>
      `${key} ${humanizeUserAttribute(key)} ${attributeSummary(value)}`.toLowerCase().includes(needle),
    );
  }, [entries, filter]);

  const attributes = raw?.attributes ?? {};
  const displayName = stringValue(attributes.displayName) || user?.name || "User";
  const upn = stringValue(attributes.userPrincipalName) || user?.upn || "";
  const enabled = typeof attributes.accountEnabled === "boolean"
    ? attributes.accountEnabled
    : user?.status !== "Disabled";
  const userType = stringValue(attributes.userType) || (user?.status === "Guest" ? "Guest" : "Member");
  const synced = attributes.onPremisesSyncEnabled === true || user?.sourceOfAuthority === "on_prem";
  const assignedLicenses = Array.isArray(attributes.assignedLicenses) ? attributes.assignedLicenses.length : 0;

  return (
    <Dialog open={open} onClose={onClose} width={920} className="overflow-hidden">
      <div className="flex max-h-[88vh] min-h-[580px] flex-col">
        <header className="shrink-0 border-b border-[var(--border-card)] px-5 pt-5 sm:px-6">
          <div className="flex items-start gap-3">
            <Avatar name={displayName} className="size-11 text-[14px]" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="truncate text-[18px] font-bold text-fg-strong">{displayName}</h2>
                <Badge tone={enabled ? "success" : "danger"}>{enabled ? "Active" : "Disabled"}</Badge>
                <Badge tone={synced ? "warning" : "info"} dot={false}>{synced ? "On-premises sync" : "Cloud managed"}</Badge>
              </div>
              <p className="mt-1 break-all text-[12.5px] text-muted">{upn}</p>
              <p className="mt-1 text-[11px] text-faint">Read-only Microsoft Graph directory details · viewing is audited</p>
            </div>
            <Button variant="ghost" size="icon" aria-label="Close user details" onClick={onClose}><X /></Button>
          </div>

          <nav aria-label="User detail views" className="mt-5 flex gap-5">
            <ViewTab active={view === "overview"} onClick={() => setView("overview")} icon={<UserRound />}>Overview</ViewTab>
            <ViewTab active={view === "attributes"} onClick={() => setView("attributes")} icon={<ListTree />}>All attributes</ViewTab>
            <ViewTab active={view === "json"} onClick={() => setView("json")} icon={<Braces />}>Raw JSON</ViewTab>
          </nav>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto">
          {loading ? (
            <div className="grid min-h-[360px] place-items-center">
              <div className="text-center"><Loader2 className="mx-auto size-5 animate-spin text-muted" /><p className="mt-3 text-[12px] text-muted">Loading directory details…</p></div>
            </div>
          ) : error ? (
            <div className="m-6 rounded-[10px] border border-danger/25 bg-[var(--bg-danger)] px-4 py-3 text-[12.5px] text-danger">{error}</div>
          ) : raw && view === "overview" ? (
            <div className="space-y-5 p-5 sm:p-6">
              <section aria-label="Account summary" className="grid overflow-hidden rounded-[10px] border border-[var(--border-card)] bg-control sm:grid-cols-2 lg:grid-cols-4">
                <SummaryFact icon={enabled ? <CheckCircle2 /> : <ShieldCheck />} label="Account" value={enabled ? "Enabled" : "Disabled"} />
                <SummaryFact icon={<UserRound />} label="User type" value={userType} />
                <SummaryFact icon={synced ? <Server /> : <Cloud />} label="Source" value={synced ? "On-premises AD" : "Microsoft Entra"} />
                <SummaryFact icon={<ShieldCheck />} label="Licensing" value={assignedLicenses ? `${assignedLicenses} assigned` : user?.license || "None assigned"} />
              </section>

              <div className="grid gap-5 lg:grid-cols-2">
                {OVERVIEW_SECTIONS.map((section) => {
                  const rows = section.fields.filter((key) => isPopulatedAttribute(attributes[key]));
                  if (rows.length === 0) return null;
                  const Icon = section.icon;
                  return <InfoSection key={section.title} title={section.title} icon={<Icon />}>{rows.map((key) => <InfoRow key={key} field={key} value={attributes[key]} />)}</InfoSection>;
                })}
              </div>

              <InfoSection title="Account lifecycle & access" icon={<ShieldCheck />}>
                <InfoRow field="id" value={attributes.id ?? raw.id} />
                <InfoRow field="createdDateTime" value={attributes.createdDateTime} />
                <InfoRow field="signInSessionsValidFromDateTime" value={attributes.signInSessionsValidFromDateTime} />
                <InfoRow field="externalUserState" value={attributes.externalUserState} />
                <InfoRow field="showInAddressList" value={attributes.showInAddressList} />
                <InfoRow field="assignedLicenses" value={attributes.assignedLicenses} />
              </InfoSection>
            </div>
          ) : raw && view === "attributes" ? (
            <div className="p-5 sm:p-6">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div><h3 className="text-[14px] font-semibold text-fg">All directory attributes</h3><p className="mt-0.5 text-[11.5px] text-muted">{entries.length} populated fields returned by Microsoft Graph</p></div>
                <div className="relative w-full sm:w-[280px]"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" /><Input aria-label="Filter user attributes" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter attributes…" className="pl-9" /></div>
              </div>
              <div className="overflow-hidden rounded-[10px] border border-[var(--border-card)]">
                {filteredEntries.map(([key, value]) => <AttributeRow key={key} field={key} value={value} />)}
                {filteredEntries.length === 0 && <p className="px-4 py-12 text-center text-[12.5px] text-muted">No attributes match “{filter}”.</p>}
              </div>
            </div>
          ) : raw && view === "json" ? (
            <div className="p-5 sm:p-6">
              <div className="mb-3"><h3 className="text-[14px] font-semibold text-fg">Raw Microsoft Graph response</h3><p className="mt-0.5 text-[11.5px] text-muted">For troubleshooting and advanced inspection. Empty Graph properties are omitted.</p></div>
              <pre className="mono max-h-[58vh] overflow-auto rounded-[10px] border border-[var(--border-card)] bg-[#0d0d10] p-4 text-[11.5px] leading-5 text-body">{JSON.stringify(raw.attributes, null, 2)}</pre>
            </div>
          ) : null}
        </main>
      </div>
    </Dialog>
  );
}

function ViewTab({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon: React.ReactNode; children: React.ReactNode }) {
  return <button type="button" role="tab" aria-selected={active} onClick={onClick} className={`flex items-center gap-1.5 border-b-2 pb-3 text-[12.5px] font-semibold transition-colors [&_svg]:size-3.5 ${active ? "border-[var(--ac)] text-fg" : "border-transparent text-muted hover:text-body"}`}>{icon}{children}</button>;
}

function SummaryFact({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return <div className="flex items-center gap-3 border-b border-[var(--border-card)] px-4 py-3.5 last:border-b-0 sm:[&:nth-child(odd)]:border-r lg:border-b-0 lg:border-r lg:last:border-r-0"><span className="grid size-8 shrink-0 place-items-center rounded-[8px] bg-[var(--acb)] text-[var(--act)] [&_svg]:size-4">{icon}</span><div className="min-w-0"><p className="text-[10px] font-bold uppercase tracking-[.45px] text-faint">{label}</p><p className="mt-0.5 truncate text-[12.5px] font-semibold text-fg">{value}</p></div></div>;
}

function InfoSection({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return <section><h3 className="mb-2 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[.5px] text-faint"><span className="text-muted [&_svg]:size-3.5">{icon}</span>{title}</h3><dl className="divide-y divide-[var(--border-card)] overflow-hidden rounded-[10px] border border-[var(--border-card)] bg-control">{children}</dl></section>;
}

function InfoRow({ field, value }: { field: string; value: unknown }) {
  if (!isPopulatedAttribute(value)) return null;
  return <div className="grid gap-1 px-3.5 py-2.5 sm:grid-cols-[155px_minmax(0,1fr)] sm:gap-4"><dt className="text-[11.5px] text-muted">{humanizeUserAttribute(field)}</dt><dd className="min-w-0 break-words text-[12px] text-fg">{renderReadableValue(field, value)}</dd></div>;
}

function AttributeRow({ field, value }: { field: string; value: unknown }) {
  const complex = typeof value === "object" && value !== null;
  return <div className="grid gap-2 border-b border-[var(--border-card)] px-4 py-3 last:border-0 sm:grid-cols-[220px_minmax(0,1fr)] sm:gap-5"><div><p className="text-[12px] font-medium text-body">{humanizeUserAttribute(field)}</p><p className="mono mt-0.5 break-all text-[10px] text-faint">{field}</p></div><div className="min-w-0 break-words text-[12px] text-fg">{complex ? <details><summary className="cursor-pointer select-none text-secondary hover:text-fg">{attributeSummary(value)}</summary><pre className="mono mt-2 overflow-x-auto whitespace-pre-wrap rounded-[8px] bg-[#0d0d10] p-3 text-[10.5px] leading-5 text-body">{JSON.stringify(value, null, 2)}</pre></details> : renderReadableValue(field, value)}</div></div>;
}

function renderReadableValue(field: string, value: unknown): React.ReactNode {
  if (!isPopulatedAttribute(value)) return <span className="text-faint">Not set</span>;
  if (typeof value === "boolean") return <Badge tone={value ? "success" : "neutral"} dot={false}>{value ? "Yes" : "No"}</Badge>;
  if (DATE_FIELDS.has(field) && typeof value === "string") return formatUserDate(value);
  if (field === "identities" && Array.isArray(value)) return <div className="space-y-2">{value.map((identity, index) => {
    if (!identity || typeof identity !== "object") return <span key={index}>{String(identity)}</span>;
    const row = identity as Record<string, unknown>;
    return <div key={index}><p className="font-medium text-fg">{stringValue(row.issuerAssignedId) || "Sign-in identity"}</p><p className="mt-0.5 text-[10.5px] text-muted">{stringValue(row.signInType) || "identity"}{row.issuer ? ` · ${stringValue(row.issuer)}` : ""}</p></div>;
  })}</div>;
  if (field === "assignedLicenses" && Array.isArray(value)) return value.length ? <div className="space-y-1.5">{value.map((license, index) => {
    const row = license && typeof license === "object" ? license as Record<string, unknown> : {};
    return <div key={index}><p className="mono break-all text-[11px]">{stringValue(row.skuId) || String(license)}</p><p className="text-[10.5px] text-muted">{Array.isArray(row.disabledPlans) && row.disabledPlans.length ? `${row.disabledPlans.length} disabled plans` : "All service plans enabled"}</p></div>;
  })}</div> : "None assigned";
  if (Array.isArray(value)) {
    const values = stringList(value);
    return values.length ? <div className="flex flex-wrap gap-1.5">{values.map((item) => <span key={item} className="max-w-full break-all rounded-[5px] bg-white/[.05] px-2 py-1 text-[11px] text-secondary">{item}</span>)}</div> : "None";
  }
  if (typeof value === "object") return <pre className="mono whitespace-pre-wrap text-[10.5px] leading-5">{JSON.stringify(value, null, 2)}</pre>;
  return String(value);
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}
