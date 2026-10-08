import type { PreflightCheck } from "../../types/index.ts";

export const PREFLIGHT_CATEGORY_ORDER = [
  "Security Operations",
  "Directory & Identity",
  "Exchange",
  "SharePoint",
  "Licensing",
] as const;

export interface PreflightGroup {
  category: string;
  checks: PreflightCheck[];
  missing: number;
  attention: number;
}

export function groupPreflightChecks(checks: PreflightCheck[]): PreflightGroup[] {
  const byCategory = new Map<string, PreflightCheck[]>();
  for (const check of checks) {
    const category = check.category?.trim() || "Other RTM features";
    const group = byCategory.get(category) ?? [];
    group.push(check);
    byCategory.set(category, group);
  }
  const rank = new Map<string, number>(PREFLIGHT_CATEGORY_ORDER.map((category, index) => [category, index]));
  return [...byCategory.entries()]
    .sort(([a], [b]) => (rank.get(a) ?? 999) - (rank.get(b) ?? 999) || a.localeCompare(b))
    .map(([category, categoryChecks]) => ({
      category,
      checks: [...categoryChecks].sort((a, b) => a.area.localeCompare(b.area)),
      missing: categoryChecks.filter((check) => check.status === "missing").length,
      attention: categoryChecks.filter((check) => check.status === "error" || check.status === "not_provisioned").length,
    }));
}
