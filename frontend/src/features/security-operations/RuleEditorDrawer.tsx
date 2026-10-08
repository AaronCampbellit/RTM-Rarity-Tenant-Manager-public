import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, CheckCircle2, History, Loader2, Play, Save, X } from "lucide-react";
import { api } from "@/api/client";
import { useAsync } from "@/api/hooks";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { useTenant } from "@/store/tenant";
import type { SecurityDetectionRule, SecurityDetectionRuleRevision, SecurityRuleConditionOptions, SecurityRuleExclusion, SecurityRulePreview } from "@/types";
import { RuleConditionSelect } from "./RuleConditionSelect";
import { editableSecurityRule, SELECT_CLASS } from "./securityRules";

const LIST_FIELDS = [
  { key: "workloads", label: "Workloads", optionKey: "workloads", placeholder: "Select workloads…" },
  { key: "operations", label: "Operations", optionKey: "operations", placeholder: "Select operations…" },
  { key: "actors", label: "Actors (contains any)", optionKey: "actors", placeholder: "Select observed actors…" },
  { key: "clientIps", label: "Client IPs", optionKey: "clientIps", placeholder: "Select observed IPs…" },
  { key: "results", label: "Results", optionKey: "results", placeholder: "Select results…" },
  { key: "objectContains", label: "Objects (contains any)", optionKey: "objects", placeholder: "Select observed objects…" },
  { key: "rawContains", label: "Raw evidence fields (all required)", optionKey: "rawEvidenceTerms", placeholder: "Select evidence fields…" },
] as const;

const EMPTY_OPTIONS: SecurityRuleConditionOptions = {
  workloads: [], operations: [], actors: [], clientIps: [], results: [], objects: [], rawEvidenceTerms: [],
  eventsScanned: 0, evidenceWindowDays: 180, limited: false,
};

export function RuleEditorDrawer({ initial, onClose, onSaved }: {
  initial: SecurityDetectionRule;
  onClose: () => void;
  onSaved: (rule: SecurityDetectionRule) => void;
}) {
  const { tenants } = useTenant();
  const [rule, setRule] = useState(() => editableSecurityRule(initial));
  const [preview, setPreview] = useState<SecurityRulePreview>();
  const [revisions, setRevisions] = useState<SecurityDetectionRuleRevision[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const baseline = initial.builtIn && !initial.override;
  const usesBuiltInTrigger = initial.builtIn && rule.definition.triggerMode !== "custom";
  const optionTenantId = rule.scope === "tenant" ? rule.tenantId : undefined;
  const optionQuery = useAsync(() => api.security.ruleOptions(optionTenantId), [optionTenantId]);
  const conditionOptions = optionQuery.data ?? EMPTY_OPTIONS;

  useEffect(() => {
    if (!initial.id || baseline) return;
    void api.security.ruleRevisions(initial.id).then(setRevisions).catch(() => setRevisions([]));
  }, [baseline, initial.id]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  function patch(next: Partial<SecurityDetectionRule>) {
    setRule((current) => ({ ...current, ...next }));
    setPreview(undefined);
  }

  function patchDefinition(key: string, value: unknown) {
    setRule((current) => ({ ...current, definition: { ...current.definition, [key]: value } }));
    setPreview(undefined);
  }

  function setTriggerMode(mode: "builtIn" | "custom") {
    setRule((current) => ({
      ...current,
      detectionType: mode === "custom" && !["direct", "threshold"].includes(current.detectionType)
        ? "direct"
        : current.detectionType,
      definition: mode === "custom"
        ? { ...current.definition, triggerMode: "custom", operationMatch: current.definition.operationMatch ?? "contains" }
        : { triggerMode: "builtIn", exclusions: current.definition.exclusions ?? [] },
    }));
    setPreview(undefined);
  }

  async function runPreview(target = rule) {
    setBusy(true); setError(undefined);
    try {
      const result = await api.security.previewRule({ rule: target });
      setPreview(result);
      return result;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Rule preview failed.");
    } finally { setBusy(false); }
  }

  async function saveDraft() {
    setBusy(true); setError(undefined);
    try {
      const draft = { ...rule, enabled: false };
      const saved = rule.id
        ? await api.security.updateRule(rule.id, { rule: draft })
        : await api.security.createRule({ rule: draft });
      onSaved(saved);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Rule save failed.");
    } finally { setBusy(false); }
  }

  async function applyPreviewed() {
    let approved = preview;
    if (!approved) approved = await runPreview();
    if (!approved) return;
    setBusy(true); setError(undefined);
    try {
      const saved = rule.id
        ? await api.security.updateRule(rule.id, { rule, approvalToken: approved.approvalToken })
        : await api.security.createRule({ rule, approvalToken: approved.approvalToken });
      onSaved(saved);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Rule update failed. Run a fresh preview and retry.");
      setPreview(undefined);
    } finally { setBusy(false); }
  }

  async function restore(item: SecurityDetectionRuleRevision) {
    setBusy(true); setError(undefined);
    try {
      let token: string | undefined;
      if (rule.enabled || item.snapshot.enabled) {
        const result = await api.security.previewRule({ rule: item.snapshot });
        token = result.approvalToken;
      }
      const saved = await api.security.restoreRule(rule.id, item.revision, token);
      onSaved(saved);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Revision restore failed.");
    } finally { setBusy(false); }
  }

  return createPortal(
    <div className="fixed inset-0 z-50 animate-fade">
      <button aria-label="Close rule editor" className="absolute inset-0 cursor-default bg-black/55 backdrop-blur-[1px]" onClick={onClose} />
      <aside role="dialog" aria-modal="true" aria-labelledby="rule-editor-title" className="absolute inset-y-0 right-0 flex w-full max-w-[680px] animate-[drawer-in_.2s_ease-out] flex-col border-l border-[var(--border-strong)] bg-sidebar shadow-[var(--shadow-drawer)]">
        <div className="flex items-start gap-3 border-b border-[var(--border-card)] px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 id="rule-editor-title" className="text-[17px] font-bold text-fg-strong">{baseline ? "Configure built-in rule" : rule.id ? "Edit detection rule" : "Create detection rule"}</h2>
              {initial.builtIn && <Badge tone={baseline ? "info" : "warning"}>{baseline ? "Built-in baseline" : "Built-in override"}</Badge>}
            </div>
            <p className="mt-1 text-[12px] text-muted">Preview against retained evidence before an enabled rule changes.</p>
          </div>
          <Button variant="ghost" size="icon" aria-label="Close" onClick={onClose}><X /></Button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-5">
          <div className="space-y-5">
            <section className="grid gap-3 sm:grid-cols-2">
              <Field label="Rule name" wide><Input value={rule.name} onChange={(event) => patch({ name: event.target.value })} /></Field>
              <Field label="Description" wide><Textarea rows={3} value={rule.description} onChange={(event) => patch({ description: event.target.value })} /></Field>
              {initial.builtIn && <Field label="Trigger engine"><select aria-label="Trigger engine" className={SELECT_CLASS} value={rule.definition.triggerMode ?? "builtIn"} onChange={(event) => setTriggerMode(event.target.value as "builtIn" | "custom")}><option value="builtIn">Built-in detector</option><option value="custom">Custom event match</option></select></Field>}
              <Field label="Evaluation type"><select className={SELECT_CLASS} disabled={usesBuiltInTrigger} value={rule.detectionType} onChange={(event) => patch({ detectionType: event.target.value })}><option value="direct">Direct match</option><option value="threshold">Threshold</option>{usesBuiltInTrigger && !["direct", "threshold"].includes(rule.detectionType) && <option value={rule.detectionType}>{rule.detectionType}</option>}</select></Field>
              <Field label="Scope"><select className={SELECT_CLASS} value={rule.scope} onChange={(event) => patch({ scope: event.target.value as "global" | "tenant", tenantId: event.target.value === "global" ? undefined : tenants[0]?.id })}><option value="global">All managed tenants</option><option value="tenant">One tenant</option></select></Field>
              {rule.scope === "tenant" && <Field label="Tenant"><select className={SELECT_CLASS} value={rule.tenantId ?? ""} onChange={(event) => patch({ tenantId: event.target.value })}>{tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}</select></Field>}
              <Field label="Severity"><select className={SELECT_CLASS} value={rule.severity} onChange={(event) => patch({ severity: event.target.value })}>{["Critical", "High", "Medium", "Low", "Informational"].map((item) => <option key={item}>{item}</option>)}</select></Field>
              <Field label="Confidence"><select className={SELECT_CLASS} value={rule.confidence} onChange={(event) => patch({ confidence: event.target.value })}>{["high", "medium", "low"].map((item) => <option key={item}>{item}</option>)}</select></Field>
              <label className="flex items-center gap-2 self-end rounded-[8px] border border-[var(--border-card)] bg-card px-3 py-2.5 text-[13px] text-body"><input type="checkbox" checked={rule.enabled} onChange={(event) => patch({ enabled: event.target.checked })} /> Enabled after approval</label>
            </section>

            <section>
              <SectionTitle>Match conditions</SectionTitle>
              {usesBuiltInTrigger && <p className="mb-3 rounded-[8px] border border-info/25 bg-[var(--bg-info)] px-3 py-2 text-[12px] text-info">The specialized built-in detector is active. Choose <strong>Custom event match</strong> above to replace its trigger with editable workload, operation, actor, IP, result, object, and raw-evidence conditions. The shipped baseline remains unchanged.</p>}
              {initial.builtIn && !usesBuiltInTrigger && <p className="mb-3 rounded-[8px] border border-warning/25 bg-[var(--bg-warning)] px-3 py-2 text-[12px] text-warning">This override replaces the specialized built-in detector. Add at least one match condition, then preview it against retained evidence before applying.</p>}
              {!usesBuiltInTrigger && <p className="mb-3 text-[11.5px] leading-relaxed text-muted">Choose from supported Microsoft 365 values and the normalized evidence RTM observed during the last {conditionOptions.evidenceWindowDays} days{conditionOptions.eventsScanned ? ` (${conditionOptions.eventsScanned.toLocaleString()} events scanned)` : ""}. Raw provider values and secrets are never exposed as suggestions.</p>}
              {optionQuery.error && !usesBuiltInTrigger && <p role="alert" className="mb-3 flex gap-2 rounded-[8px] border border-warning/25 bg-[var(--bg-warning)] p-3 text-[12px] text-warning"><AlertTriangle className="size-4 shrink-0" />Condition choices could not be loaded. Existing selections remain visible; close and reopen the editor to retry.</p>}
              <div className="grid gap-3 sm:grid-cols-2">
                {LIST_FIELDS.map((field) => <Field key={field.key} label={field.label}><RuleConditionSelect label={field.label} disabled={usesBuiltInTrigger} loading={optionQuery.loading} values={rule.definition[field.key] ?? []} options={conditionOptions[field.optionKey]} placeholder={field.placeholder} onChange={(values) => patchDefinition(field.key, values)} /></Field>)}
                {!usesBuiltInTrigger && <Field label="Operation matching"><select className={SELECT_CLASS} value={rule.definition.operationMatch ?? "contains"} onChange={(event) => patchDefinition("operationMatch", event.target.value)}><option value="contains">Contains any</option><option value="exact">Exact match</option></select></Field>}
              </div>
            </section>

            {(rule.detectionType === "threshold" || (usesBuiltInTrigger && (rule.definition.threshold ?? 0) > 0)) && <section><SectionTitle>Threshold</SectionTitle><div className="grid gap-3 sm:grid-cols-3"><Field label="Event count"><Input type="number" min={2} value={rule.definition.threshold ?? 5} onChange={(event) => patchDefinition("threshold", Number(event.target.value))} /></Field><Field label="Window (minutes)"><Input type="number" min={1} value={rule.definition.windowMinutes ?? 15} onChange={(event) => patchDefinition("windowMinutes", Number(event.target.value))} /></Field>{!usesBuiltInTrigger && <Field label="Group by"><select className={SELECT_CLASS} value={rule.definition.groupBy ?? "actor"} onChange={(event) => patchDefinition("groupBy", event.target.value)}>{["actor", "clientIp", "objectId", "tenant"].map((item) => <option key={item} value={item}>{item}</option>)}</select></Field>}</div></section>}

            <section>
              <div className="mb-2 flex items-center justify-between"><SectionTitle>Exclusions</SectionTitle><Button size="sm" disabled={optionQuery.loading} onClick={() => patchDefinition("exclusions", [...(rule.definition.exclusions ?? []), defaultExclusion(conditionOptions, tenants)])}>Add exclusion</Button></div>
              <div className="space-y-2">{rule.definition.exclusions?.map((exclusion, index) => {
                const choices = exclusionChoices(exclusion.field, conditionOptions, tenants, exclusion.value);
                return <div key={index} className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_2fr_auto]"><select aria-label="Exclusion field" className={SELECT_CLASS} value={exclusion.field} onChange={(event) => {
                  const field = event.target.value as SecurityRuleExclusion["field"];
                  patchExclusion(index, { field, value: exclusionChoices(field, conditionOptions, tenants)[0]?.value ?? "" });
                }}>{["actor", "clientIp", "objectId", "tenantId"].map((item) => <option key={item}>{item}</option>)}</select><select aria-label="Exclusion match" className={SELECT_CLASS} value={exclusion.match} onChange={(event) => patchExclusion(index, { match: event.target.value as typeof exclusion.match })}><option value="contains">contains</option><option value="exact">exact</option></select><select aria-label="Exclusion value" className={SELECT_CLASS} value={exclusion.value} onChange={(event) => patchExclusion(index, { value: event.target.value })}>{choices.length ? choices.map((choice) => <option key={choice.value} value={choice.value}>{choice.label}</option>) : <option value="">No observed values</option>}</select><Button variant="ghost" size="icon" className="justify-self-end sm:justify-self-auto" aria-label="Remove exclusion" onClick={() => patchDefinition("exclusions", rule.definition.exclusions?.filter((_, itemIndex) => itemIndex !== index))}><X /></Button></div>;
              })}</div>
            </section>

            {preview && <section className="rounded-[10px] border border-success/25 bg-[var(--bg-success)] p-4"><div className="flex items-center gap-2 text-[13px] font-semibold text-success"><CheckCircle2 className="size-4" /> Preview complete</div><p className="mt-2 text-[12px] text-body">{preview.matchedEvents} matches across {Object.keys(preview.tenantsMatched).length} tenants from {preview.eventsScanned} scanned events.</p>{preview.warnings.map((warning) => <p key={warning} className="mt-1 text-[11.5px] text-muted">{warning}</p>)}</section>}
            {error && <p role="alert" className="flex gap-2 rounded-[8px] border border-danger/25 bg-[var(--bg-danger)] p-3 text-[12px] text-danger"><AlertTriangle className="size-4 shrink-0" />{error}</p>}

            {revisions.length > 0 && <section><SectionTitle><span className="inline-flex items-center gap-1.5"><History className="size-3.5" /> Revision history</span></SectionTitle><div className="divide-y divide-[var(--border-card)] rounded-[10px] border border-[var(--border-card)] bg-card">{revisions.map((item) => <div key={item.revision} className="flex items-center gap-3 px-3 py-2.5"><span className="mono text-[12px] text-fg">v{item.revision}</span><span className="min-w-0 flex-1 text-[11.5px] text-muted">{item.actor} · {new Date(item.createdAt).toLocaleString()}</span>{item.revision !== rule.revision && <Button size="sm" onClick={() => void restore(item)}>Preview & restore</Button>}</div>)}</div></section>}
          </div>
        </div>

        <div className="flex flex-wrap justify-end gap-2 border-t border-[var(--border-card)] px-5 py-4">
          {!baseline && !rule.id && !rule.enabled && <Button disabled={busy} onClick={() => void saveDraft()}>{busy ? <Loader2 className="animate-spin" /> : <Save />}Save disabled draft</Button>}
          <Button disabled={busy} onClick={() => void runPreview()}>{busy ? <Loader2 className="animate-spin" /> : <Play />}Preview</Button>
          <Button variant="accent" disabled={busy || !preview} onClick={() => void applyPreviewed()}>{busy ? <Loader2 className="animate-spin" /> : <CheckCircle2 />}{baseline ? "Create override" : "Apply previewed change"}</Button>
        </div>
      </aside>
    </div>, document.body,
  );

  function patchExclusion(index: number, value: Record<string, string>) {
    patchDefinition("exclusions", rule.definition.exclusions?.map((item, itemIndex) => itemIndex === index ? { ...item, ...value } : item));
  }
}

function Field({ label, wide, children }: { label: string; wide?: boolean; children: React.ReactNode }) {
  return <label className={wide ? "sm:col-span-2" : ""}><span className="mb-1.5 block text-[11px] font-semibold text-secondary">{label}</span>{children}</label>;
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h3 className="mb-2 text-[11px] font-bold uppercase tracking-[.5px] text-faint">{children}</h3>;
}

type Choice = { value: string; label: string };

function exclusionChoices(
  field: SecurityRuleExclusion["field"],
  options: SecurityRuleConditionOptions,
  tenants: Array<{ id: string; name: string }>,
  current = "",
): Choice[] {
  const observed = field === "actor" ? options.actors
    : field === "clientIp" ? options.clientIps
      : field === "objectId" ? options.objects
        : [];
  const choices = field === "tenantId"
    ? tenants.map((tenant) => ({ value: tenant.id, label: tenant.name }))
    : observed.map((value) => ({ value, label: value }));
  if (current && !choices.some((choice) => choice.value.toLocaleLowerCase() === current.toLocaleLowerCase())) {
    choices.push({ value: current, label: current });
  }
  return choices;
}

function defaultExclusion(options: SecurityRuleConditionOptions, tenants: Array<{ id: string; name: string }>): SecurityRuleExclusion {
  if (options.actors[0]) return { field: "actor", match: "contains", value: options.actors[0] };
  return { field: "tenantId", match: "exact", value: tenants[0]?.id ?? "" };
}
