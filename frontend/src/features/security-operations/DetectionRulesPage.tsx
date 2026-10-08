import { useCallback, useMemo, useState } from "react";
import { FileLock2, Plus, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { api } from "@/api/client";
import { useRefreshingAsync } from "@/api/hooks";
import { DataTable, type Column } from "@/components/common/DataTable";
import { PageToolbar } from "@/components/common/PageToolbar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { SearchInput } from "@/components/ui/input";
import { hasPermission, useAuth } from "@/store/auth";
import { useSetPageTitle } from "@/store/page";
import type { SecurityDetectionRule } from "@/types";
import { securitySeverityTone } from "./securityOperations";
import { newSecurityRule, SELECT_CLASS, sortDetectionRules, type DetectionRuleSortKey, type SortDirection } from "./securityRules";
import { RuleEditorDrawer } from "./RuleEditorDrawer";

export function DetectionRulesPage() {
  useSetPageTitle("Detection Rules");
  const { user } = useAuth();
  const canManage = hasPermission(user, "security.manage");
  const query = useRefreshingAsync(() => api.security.rules(), [], { cacheKey: "security:rules" });
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("all");
  const [state, setState] = useState("all");
  const [sort, setSort] = useState<{ key: DetectionRuleSortKey; direction: SortDirection }>({ key: "rule", direction: "asc" });
  const [selected, setSelected] = useState<SecurityDetectionRule>();

  const rows = useMemo(() => sortDetectionRules((query.data ?? []).filter((rule) => {
    const needle = search.toLowerCase();
    return (!needle || `${rule.name} ${rule.ruleId} ${rule.description}`.toLowerCase().includes(needle)) &&
      (source === "all" || source === "built-in" && rule.builtIn || source === "custom" && !rule.builtIn || source === "override" && rule.override) &&
      (state === "all" || state === "enabled" && rule.enabled || state === "disabled" && !rule.enabled);
  }), sort.key, sort.direction), [query.data, search, source, state, sort]);

  const toggleSort = useCallback((key: DetectionRuleSortKey) => {
    setSort((current) => current.key === key
      ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
      : { key, direction: "asc" });
  }, []);

  const columns = useMemo<Column<SecurityDetectionRule>[]>(() => [
    { key: "rule", header: "Detection rule", width: "36%", sortDirection: sort.key === "rule" ? sort.direction : undefined, onSort: () => toggleSort("rule"), cell: (rule) => <div><div className="flex items-center gap-2 font-semibold text-fg"><span>{rule.name}</span>{rule.locked && <FileLock2 className="size-3.5 text-faint" />}</div><p className="mono mt-1 text-[10.5px] text-muted">{rule.ruleId} · v{rule.revision || 1}</p></div> },
    { key: "source", header: "Source", sortDirection: sort.key === "source" ? sort.direction : undefined, onSort: () => toggleSort("source"), cell: (rule) => <Badge tone={rule.override ? "warning" : rule.builtIn ? "info" : "neutral"}>{rule.override ? "Override" : rule.builtIn ? "Built-in" : "Custom"}</Badge> },
    { key: "type", header: "Evaluation", sortDirection: sort.key === "type" ? sort.direction : undefined, onSort: () => toggleSort("type"), cell: (rule) => <span className="capitalize text-secondary">{rule.detectionType}</span> },
    { key: "severity", header: "Severity", sortDirection: sort.key === "severity" ? sort.direction : undefined, onSort: () => toggleSort("severity"), cell: (rule) => <Badge tone={securitySeverityTone(rule.severity)}>{rule.severity}</Badge> },
    { key: "scope", header: "Scope", sortDirection: sort.key === "scope" ? sort.direction : undefined, onSort: () => toggleSort("scope"), cell: (rule) => <span>{rule.scope === "global" ? "All tenants" : rule.tenantName || rule.tenantId}</span> },
    { key: "status", header: "State", align: "right", sortDirection: sort.key === "status" ? sort.direction : undefined, onSort: () => toggleSort("status"), cell: (rule) => <span className="inline-flex items-center gap-1.5"><span className={`size-2 rounded-full ${rule.enabled ? "bg-success" : "bg-faint"}`} />{rule.enabled ? "Enabled" : "Disabled"}</span> },
  ], [sort, toggleSort]);

  const total = query.data?.length ?? 0;
  const enabled = query.data?.filter((rule) => rule.enabled).length ?? 0;
  const custom = query.data?.filter((rule) => !rule.builtIn).length ?? 0;
  const overrides = query.data?.filter((rule) => rule.override).length ?? 0;

  return <div className="mx-auto max-w-[1500px] px-4 py-5 sm:px-6 lg:px-8">
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div><div className="flex items-center gap-2"><ShieldCheck className="size-5 text-[var(--ac)]" /><h2 className="text-[20px] font-bold text-fg-strong">Detection rules</h2></div><p className="mt-1 text-[12.5px] text-muted">Global policy for Microsoft 365 audit detections across every managed tenant.</p></div>
      {canManage && <Button variant="accent" onClick={() => setSelected(newSecurityRule())}><Plus />Create rule</Button>}
    </div>

    <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Metric label="Rule catalog" value={total} icon={<ShieldCheck />} />
      <Metric label="Enabled" value={enabled} icon={<span className="size-2 rounded-full bg-success" />} />
      <Metric label="Custom" value={custom} icon={<Plus />} />
      <Metric label="Scoped overrides" value={overrides} icon={<SlidersHorizontal />} />
    </div>

    <details className="mb-4 rounded-[10px] border border-[var(--border-card)] bg-card px-4 py-3 text-[11.5px] text-muted">
      <summary className="cursor-pointer select-none font-semibold text-secondary">How RTM assigns native severity</summary>
      <p className="mt-2 leading-relaxed"><strong className="text-danger">Critical</strong> is reserved for high-confidence tenant-wide control, defense evasion, or broad exfiltration. <strong className="text-warning">High</strong> covers high-impact access changes and strong attack sequences. <strong className="text-info">Medium</strong> covers meaningful but commonly legitimate administration or contextual anomalies. <strong className="text-secondary">Low</strong> covers common lifecycle, hygiene, and weak context-only signals. Confidence remains a separate measure.</p>
    </details>

    <PageToolbar count={`${rows.length} of ${total} rules`}>
      <SearchInput aria-label="Search detection rules" placeholder="Search rule name or ID…" value={search} onChange={(event) => setSearch(event.target.value)} className="w-[260px]" />
      <select aria-label="Rule source" className={SELECT_CLASS + " !w-auto"} value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option><option value="built-in">Built-in</option><option value="custom">Custom</option><option value="override">Overrides</option></select>
      <select aria-label="Rule state" className={SELECT_CLASS + " !w-auto"} value={state} onChange={(event) => setState(event.target.value)}><option value="all">Any state</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select>
    </PageToolbar>
    <DataTable columns={columns} rows={rows} loading={query.loading} error={query.error} getRowId={(rule) => rule.id} onRowClick={canManage ? setSelected : undefined} emptyTitle="No rules match these filters" emptyHint="Clear the search or create a custom audit detection." />
    {!canManage && <p className="mt-3 text-[11.5px] text-muted">Your role can review the rule catalog. Creating, changing, and restoring rules requires Manage detections.</p>}
    {selected && <RuleEditorDrawer initial={selected} onClose={() => setSelected(undefined)} onSaved={() => { setSelected(undefined); query.refresh(); }} />}
  </div>;
}

function Metric({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return <Card className="flex items-center gap-3 p-4"><div className="grid size-9 place-items-center rounded-[9px] bg-[var(--acb)] text-[var(--act)] [&_svg]:size-4">{icon}</div><div><p className="text-[19px] font-bold tabular text-fg-strong">{value}</p><p className="text-[11.5px] text-muted">{label}</p></div></Card>;
}
