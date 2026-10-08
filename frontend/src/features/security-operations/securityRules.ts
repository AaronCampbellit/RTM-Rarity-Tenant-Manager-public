import type { SecurityAuditEvent, SecurityDetectionRule } from "@/types";

export type DetectionRuleSortKey = "rule" | "source" | "type" | "severity" | "scope" | "status";
export type SortDirection = "asc" | "desc";

const SEVERITY_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
};

export const SELECT_CLASS =
  "h-9 w-full rounded-[8px] border border-[var(--border-strong)] bg-control px-3 text-[12.5px] text-body outline-none focus:border-[var(--ac)]/50";

export function mergeRuleConditionOptions(options: string[], selected: string[]): string[] {
  const merged = new Map<string, string>();
  for (const value of [...options, ...selected]) {
    const trimmed = value.trim();
    if (trimmed && !merged.has(trimmed.toLocaleLowerCase())) merged.set(trimmed.toLocaleLowerCase(), trimmed);
  }
  return [...merged.values()].sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
}

export function filterRuleConditionOptions(options: string[], query: string): string[] {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return options;
  return options.filter((value) => value.toLocaleLowerCase().includes(needle));
}

export function newSecurityRule(event?: SecurityAuditEvent): SecurityDetectionRule {
  const zeroTime = new Date(0).toISOString();
  return {
    id: "", ruleId: "", name: event ? `${event.operation} observed` : "New audit detection",
    description: event ? `Created from ${event.workload} event ${event.providerRecordId}.` : "",
    builtIn: false, override: false, locked: false, detectionType: "direct",
    severity: "Medium", confidence: "medium", enabled: false, scope: "global",
    definition: {
      workloads: event?.workload ? [event.workload] : [],
      operations: event?.operation ? [event.operation] : [],
      operationMatch: "exact", exclusions: [],
    },
    revision: 0, updatedBy: "", createdAt: zeroTime, updatedAt: zeroTime,
  };
}

export function editableSecurityRule(rule: SecurityDetectionRule): SecurityDetectionRule {
  if (!rule.builtIn || rule.override) return structuredClone(rule);
  return {
    ...structuredClone(rule), id: "", baseRuleId: rule.ruleId, override: true,
    definition: { ...rule.definition, exclusions: [] },
  };
}

export function sortDetectionRules(
  rules: SecurityDetectionRule[],
  key: DetectionRuleSortKey,
  direction: SortDirection,
): SecurityDetectionRule[] {
  const multiplier = direction === "asc" ? 1 : -1;
  return [...rules].sort((left, right) => {
    let comparison: number;
    if (key === "severity") {
      comparison = (SEVERITY_RANK[left.severity] ?? Number.MAX_SAFE_INTEGER) -
        (SEVERITY_RANK[right.severity] ?? Number.MAX_SAFE_INTEGER);
    } else {
      comparison = sortValue(left, key).localeCompare(sortValue(right, key), undefined, {
        numeric: true,
        sensitivity: "base",
      });
    }
    if (comparison !== 0) return comparison * multiplier;
    return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
  });
}

function sortValue(rule: SecurityDetectionRule, key: Exclude<DetectionRuleSortKey, "severity">): string {
  switch (key) {
    case "rule": return rule.name;
    case "source": return rule.override ? "Override" : rule.builtIn ? "Built-in" : "Custom";
    case "type": return rule.detectionType;
    case "scope": return rule.scope === "global" ? "All tenants" : rule.tenantName || rule.tenantId || "";
    case "status": return rule.enabled ? "Enabled" : "Disabled";
  }
}
