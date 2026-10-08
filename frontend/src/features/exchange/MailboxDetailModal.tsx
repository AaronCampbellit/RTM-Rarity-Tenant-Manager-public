import { useEffect, useState } from "react";
import { AlertTriangle, Clock3, Database, Forward, KeyRound, Loader2, Mail, ShieldCheck, X } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { Dialog } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Mailbox, MailboxSettings } from "@/types";

type DetailTab = "overview" | "mail-flow" | "access";

function permTone(permission: string) {
  return permission === "Full Access" ? "warning" : permission === "Send As" ? "info" : "neutral";
}

function displayDate(value: string, includeTime = false) {
  if (!value) return "Not collected";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, includeTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" }).format(date);
}

function mailboxType(mailbox: Mailbox, settings: MailboxSettings | null) {
  const purpose = settings?.userPurpose?.toLowerCase();
  if (purpose === "shared" || purpose === "room" || purpose === "equipment" || purpose === "user") {
    return purpose[0].toUpperCase() + purpose.slice(1);
  }
  return mailbox.type;
}

function sourceLabel(source: Mailbox["sourceOfAuthority"]) {
  return source === "on_prem" ? "On-prem sync" : source === "cloud" ? "Cloud" : "Unknown";
}

function cleanMessage(value: string) {
  return value.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function friendlyEnum(value: string) {
  const labels: Record<string, string> = {
    alwaysEnabled: "Always enabled",
    contactsOnly: "Contacts only",
    sendToDelegateAndInformationToPrincipal: "Send to delegate; inform principal",
    sendToDelegateAndPrincipal: "Send to delegate and principal",
    sendToDelegateOnly: "Send to delegate only",
  };
  if (labels[value]) return labels[value];
  const words = value.replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " ");
  return words ? words[0].toUpperCase() + words.slice(1) : "Not collected";
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[10.5px] font-bold uppercase tracking-wide text-muted">{label}</p>
      <p className={cn("mt-1 break-words text-[12.5px] text-fg", mono && "font-mono text-[11.5px]")}>{value || "Not collected"}</p>
    </div>
  );
}

function LoadingRow({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 py-8 text-[12.5px] text-muted">
      <Loader2 className="size-4 animate-spin" /> {label}
    </div>
  );
}

/** Read-only mailbox detail with explicit Graph/Reports/Exchange coverage. */
export function MailboxDetailModal({
  mailbox,
  tenantId,
  onClose,
}: {
  mailbox: Mailbox | null;
  tenantId: string;
  onClose: () => void;
}) {
  const open = !!mailbox;
  const id = mailbox?.id ?? "";
  const [tab, setTab] = useState<DetailTab>("overview");
  useEffect(() => setTab("overview"), [id]);

  const settings = useAsync(
    () => (open ? api.exchange.settings(tenantId, id) : Promise.resolve(null)),
    [tenantId, id, open],
  );
  const perms = useAsync(
    () => (open ? api.exchange.permissions(tenantId, id) : Promise.resolve({ permissions: [], coverage: [] })),
    [tenantId, id, open],
  );

  if (!mailbox) return null;
  const delegateCoveragePartial = perms.data?.coverage.some((item) => item.status !== "collected") ?? false;
  const detailType = mailboxType(mailbox, settings.data ?? null);

  return (
    <Dialog open={open} onClose={onClose} width={780}>
      <div className="sticky top-0 z-10 border-b border-[var(--border)] bg-card px-5 pt-4">
        <div className="flex items-start gap-3">
          <div className="grid size-10 shrink-0 place-items-center rounded-[10px] bg-raised">
            <Mail className="size-4.5 text-secondary" />
          </div>
          <div className="min-w-0">
            <h2 className="truncate text-[15px] font-bold text-fg-strong">{mailbox.name}</h2>
            <p className="truncate text-[12px] text-muted">{mailbox.email}</p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge tone={detailType === "User" ? "info" : "neutral"} dot={false}>{detailType}</Badge>
            <Button variant="ghost" size="icon" aria-label="Close mailbox details" onClick={onClose}>
              <X className="size-4" />
            </Button>
          </div>
        </div>

        <div className="mt-4 flex gap-5" role="tablist" aria-label="Mailbox detail sections">
          {(["overview", "mail-flow", "access"] as const).map((value) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={tab === value}
              onClick={() => setTab(value)}
              className={cn(
                "border-b-2 px-0.5 pb-3 text-[12.5px] font-semibold capitalize transition-colors",
                tab === value ? "border-[var(--ac)] text-fg-strong" : "border-transparent text-muted hover:text-fg",
              )}
            >
              {value.replace("-", " ")}
            </button>
          ))}
        </div>
      </div>

      <div className="min-h-[390px] px-5 py-4">
        {tab === "overview" && (
          <div className="space-y-4">
            <section>
              <div className="mb-2.5 flex items-center gap-2">
                <ShieldCheck className="size-3.5 text-secondary" />
                <h3 className="text-[11px] font-bold uppercase tracking-wide text-muted">Identity</h3>
                <Badge className="ml-auto" tone="info" dot={false}>Microsoft Graph</Badge>
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-[10px] border border-[var(--border)] bg-raised/40 p-4 md:grid-cols-3">
                <Field label="Primary email" value={mailbox.email} />
                <Field label="User principal name" value={mailbox.userPrincipalName} />
                <Field label="Account" value={mailbox.accountStatus} />
                <Field label="Source" value={sourceLabel(mailbox.sourceOfAuthority)} />
                <Field label="Created" value={displayDate(mailbox.createdAt)} />
                <Field label="Assigned licenses" value={String(mailbox.licenseCount)} />
                <div className="col-span-2 md:col-span-3">
                  <Field label="Aliases" value={mailbox.aliases.length ? mailbox.aliases.join(", ") : "None returned"} />
                </div>
              </div>
            </section>

            <section>
              <div className="mb-2.5 flex items-center gap-2">
                <Database className="size-3.5 text-secondary" />
                <h3 className="text-[11px] font-bold uppercase tracking-wide text-muted">Usage and quota</h3>
                <Badge className="ml-auto" tone={mailbox.usageAvailable ? "success" : "warning"}>
                  {mailbox.usageAvailable ? `Current through ${displayDate(mailbox.usageAsOf)}` : "Coverage unavailable"}
                </Badge>
              </div>
              <div className="grid grid-cols-2 gap-x-6 gap-y-4 rounded-[10px] border border-[var(--border)] bg-raised/40 p-4 md:grid-cols-4">
                <Field label="Storage used" value={mailbox.usageAvailable ? mailbox.size : "Not collected"} />
                <Field label="Items" value={mailbox.usageAvailable ? mailbox.items.toLocaleString() : "Not collected"} />
                <Field label="Last activity" value={mailbox.usageAvailable ? displayDate(mailbox.lastActivityAt) : "Not collected"} />
                <Field label="Archive" value={mailbox.archive} />
                <Field label="Deleted items" value={mailbox.usageAvailable ? mailbox.deletedItems.toLocaleString() : "Not collected"} />
                <Field label="Deleted size" value={mailbox.usageAvailable ? mailbox.deletedSize : "Not collected"} />
                <Field label="Warning quota" value={mailbox.usageAvailable ? mailbox.warningQuota : "Not collected"} />
                <Field label="Send quota" value={mailbox.usageAvailable ? mailbox.sendQuota : "Not collected"} />
                <Field label="Send/receive quota" value={mailbox.usageAvailable ? mailbox.sendReceiveQuota : "Not collected"} />
                <Field label="Litigation hold" value={mailbox.litigationHold === "—" ? "Not collected" : mailbox.litigationHold} />
              </div>
              {!mailbox.usageAvailable && (
                <p className="mt-2 text-[11.5px] text-muted">{mailbox.usageDetail}</p>
              )}
            </section>
          </div>
        )}

        {tab === "mail-flow" && (
          settings.loading ? <LoadingRow label="Loading mailbox settings…" /> : settings.error ? (
            <div className="rounded-[10px] border border-[var(--border-strong)] bg-raised/40 p-4 text-[12.5px] text-fg">
              Mailbox settings could not be read. {settings.error.message}
            </div>
          ) : settings.data ? (
            <div className="space-y-4">
              <section>
                <div className="mb-2.5 flex items-center gap-2">
                  <Forward className="size-3.5 text-secondary" />
                  <h3 className="text-[11px] font-bold uppercase tracking-wide text-muted">Forwarding and redirects</h3>
                  <Badge className="ml-auto" tone={settings.data.rulesAvailable ? "success" : "warning"}>
                    {settings.data.rulesAvailable ? "Rules inspected" : "Coverage unavailable"}
                  </Badge>
                </div>
                {!settings.data.rulesAvailable ? (
                  <div className="flex gap-3 rounded-[10px] border border-[var(--border-strong)] bg-raised/40 p-4">
                    <AlertTriangle className="mt-0.5 size-4 shrink-0 text-[var(--color-warning)]" />
                    <p className="text-[12.5px] text-secondary">{settings.data.rulesDetail}</p>
                  </div>
                ) : settings.data.forwardingRules.length === 0 ? (
                  <div className="rounded-[10px] border border-[var(--border)] bg-raised/40 p-4 text-[12.5px] text-muted">
                    No forwarding, redirect, or forward-as-attachment actions were found in Inbox rules.
                  </div>
                ) : (
                  <div className="overflow-hidden rounded-[10px] border border-[var(--border)] bg-raised/40">
                    {settings.data.forwardingRules.map((rule, index) => (
                      <div key={`${rule.id}-${rule.mode}`} className={cn("flex items-start gap-3 px-4 py-3", index > 0 && "border-t border-[var(--border)]")}>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-[12.5px] font-semibold text-fg">{rule.name}</p>
                            {rule.managedByRtm && <Badge tone="info" dot={false}>RTM managed</Badge>}
                            {rule.hasError && <Badge tone="danger">Rule error</Badge>}
                          </div>
                          <p className="mt-1 break-all text-[11.5px] text-muted">{rule.mode} → {rule.recipients.join(", ")}</p>
                        </div>
                        <Badge tone={rule.enabled ? "success" : "neutral"}>{rule.enabled ? "Enabled" : "Disabled"}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              <section>
                <div className="mb-2.5 flex items-center gap-2">
                  <Clock3 className="size-3.5 text-secondary" />
                  <h3 className="text-[11px] font-bold uppercase tracking-wide text-muted">Automatic replies and locale</h3>
                </div>
                <div className="rounded-[10px] border border-[var(--border)] bg-raised/40">
                  <div className="grid grid-cols-2 gap-x-6 gap-y-4 border-b border-[var(--border)] p-4 md:grid-cols-4">
                    <Field label="Auto-reply" value={friendlyEnum(settings.data.autoReplyStatus || (settings.data.autoReply ? "enabled" : "disabled"))} />
                    <Field label="Schedule starts" value={displayDate(settings.data.autoReplyStart, true)} />
                    <Field label="Schedule ends" value={displayDate(settings.data.autoReplyEnd, true)} />
                    <Field label="External audience" value={friendlyEnum(settings.data.externalAudience || "none")} />
                    <Field label="Time zone" value={settings.data.timeZone} />
                    <Field label="Language" value={settings.data.language} />
                    <Field label="Date format" value={settings.data.dateFormat} mono />
                    <Field label="Time format" value={settings.data.timeFormat} mono />
                    <Field label="Working days" value={settings.data.workingDays.length ? settings.data.workingDays.map(friendlyEnum).join(", ") : "Not collected"} />
                    <Field label="Working hours" value={settings.data.workingHoursStart && settings.data.workingHoursEnd ? `${settings.data.workingHoursStart} – ${settings.data.workingHoursEnd}` : "Not collected"} mono />
                  </div>
                  {settings.data.autoReply && (
                    <div className="grid gap-3 p-4 md:grid-cols-2">
                      <div>
                        <p className="text-[10.5px] font-bold uppercase tracking-wide text-muted">Internal reply</p>
                        <p className="mt-1.5 text-[12px] text-secondary">{cleanMessage(settings.data.autoReplyMessage) || "No message returned"}</p>
                      </div>
                      <div>
                        <p className="text-[10.5px] font-bold uppercase tracking-wide text-muted">External reply</p>
                        <p className="mt-1.5 text-[12px] text-secondary">{cleanMessage(settings.data.externalAutoReplyMessage) || "No message returned"}</p>
                      </div>
                    </div>
                  )}
                </div>
              </section>
            </div>
          ) : null
        )}

        {tab === "access" && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <KeyRound className="size-3.5 text-secondary" />
              <h3 className="text-[11px] font-bold uppercase tracking-wide text-muted">Delegate permissions</h3>
              <Badge className="ml-auto" tone={perms.error ? "danger" : delegateCoveragePartial ? "warning" : "success"}>
                {perms.error ? "Read failed" : delegateCoveragePartial ? "Partial coverage" : "Exchange data"}
              </Badge>
            </div>
            {perms.loading ? <LoadingRow label="Loading delegate permissions…" /> : perms.error ? (
              <div className="rounded-[10px] border border-[var(--border-strong)] bg-raised/40 p-4 text-[12.5px] text-fg">
                Delegate permissions could not be read. {perms.error.message}
              </div>
            ) : (
              <div className="space-y-3">
                <div className="grid gap-2 sm:grid-cols-3">
                  {(perms.data?.coverage ?? []).map((coverage) => (
                    <div key={coverage.permission} className="rounded-[9px] border border-[var(--border)] bg-raised/40 px-3 py-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[11.5px] font-semibold text-fg">{coverage.permission}</p>
                        <Badge tone={coverage.status === "collected" ? "success" : "warning"} dot={false}>
                          {coverage.status === "collected" ? "Collected" : "Not supported"}
                        </Badge>
                      </div>
                      <p className="mt-1 text-[10.5px] text-muted">{coverage.source}</p>
                    </div>
                  ))}
                </div>

                {(perms.data?.permissions.length ?? 0) === 0 ? (
                  <div className="rounded-[10px] border border-[var(--border)] bg-raised/40 p-4 text-[12.5px] text-muted">
                    No Send on Behalf delegates were returned. Full Access and Send As are not included in Microsoft&apos;s current Admin API coverage.
                  </div>
                ) : (
                  <div className="overflow-hidden rounded-[10px] border border-[var(--border)] bg-raised/40">
                    {perms.data!.permissions.map((permission, index) => (
                      <div key={permission.id} className={cn("flex items-center justify-between gap-4 px-4 py-3", index > 0 && "border-t border-[var(--border)]")}>
                        <div className="min-w-0">
                          <p className="truncate text-[12.5px] font-semibold text-fg">{permission.delegate}</p>
                          <p className="truncate text-[11.5px] text-muted">{permission.delegateUpn}</p>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          {permission.granted && <span className="hidden text-[11px] text-muted sm:inline">since {permission.granted}</span>}
                          <Badge tone={permTone(permission.permission)} dot={false}>{permission.permission}</Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {delegateCoveragePartial && (
                  <div className="flex gap-2 rounded-[9px] border border-[var(--border-strong)] bg-raised/30 px-3 py-2.5">
                    <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-[var(--color-warning)]" />
                    <p className="text-[11.5px] leading-5 text-muted">
                      Full Access and Send As require RTM&apos;s controlled Exchange Online PowerShell connector. No conclusion is made for those two permission families.
                    </p>
                  </div>
                )}
              </div>
            )}

            {settings.data && (
              <div className="grid grid-cols-1 gap-4 rounded-[10px] border border-[var(--border)] bg-raised/40 p-4 md:grid-cols-2">
                <Field label="Delegate meeting delivery" value={friendlyEnum(settings.data.delegateMeetingMessageDelivery)} />
                <Field label="Mailbox purpose" value={friendlyEnum(settings.data.userPurpose)} />
              </div>
            )}
          </div>
        )}
      </div>

      <div className="border-t border-[var(--border)] px-5 py-3 text-[11.5px] text-muted">
        Settings and forwarding rules come from Microsoft Graph. Send on Behalf comes from the Exchange Online Admin API. Full Access and Send As require Exchange Online PowerShell.
      </div>
    </Dialog>
  );
}
