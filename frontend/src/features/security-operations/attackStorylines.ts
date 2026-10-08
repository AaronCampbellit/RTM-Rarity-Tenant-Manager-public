import type { SecurityStoryline, SecurityTriageStatus } from "@/types";

export type StorylineStatusFilter = "active" | "all" | SecurityTriageStatus;
export type StorylineSort = "risk_desc" | "activity_desc" | "activity_asc" | "title_asc";

export interface StorylineFilters {
  query: string;
  tenant: string;
  severity: string;
  status: StorylineStatusFilter;
  sort: StorylineSort;
}

function matchesStatus(status: SecurityTriageStatus, filter: StorylineStatusFilter) {
  if (filter === "all") return true;
  if (filter === "active") return status === "New" || status === "In Progress";
  return status === filter;
}

/** Filters and sorts the analyst queue without mutating the API snapshot. */
export function filterSecurityStorylines(
  storylines: SecurityStoryline[],
  filters: StorylineFilters,
) {
  const query = filters.query.trim().toLocaleLowerCase();
  const rows = storylines.filter((storyline) => {
    if (!matchesStatus(storyline.status, filters.status)) return false;
    if (filters.tenant !== "all" && !storyline.tenantIds.includes(filters.tenant)) return false;
    if (filters.severity !== "all" && storyline.severity !== filters.severity) return false;
    if (!query) return true;

    return [
      storyline.title,
      storyline.summary,
      storyline.packId,
      storyline.owner,
      ...storyline.tenantNames,
      ...storyline.entities.map((entity) => entity.label),
      ...storyline.stages,
      ...storyline.workloads,
    ].some((value) => value?.toLocaleLowerCase().includes(query));
  });

  return rows.sort((left, right) => {
    switch (filters.sort) {
      case "activity_asc":
        return left.lastSeen.localeCompare(right.lastSeen) || right.riskScore - left.riskScore;
      case "activity_desc":
        return right.lastSeen.localeCompare(left.lastSeen) || right.riskScore - left.riskScore;
      case "title_asc":
        return left.title.localeCompare(right.title) || right.riskScore - left.riskScore;
      case "risk_desc":
        return right.riskScore - left.riskScore || right.lastSeen.localeCompare(left.lastSeen);
    }
  });
}

/** Returns the analyst's active queue without mutating the API snapshot. */
export function activeSecurityStorylines(storylines: SecurityStoryline[]) {
  return filterSecurityStorylines(storylines, {
    query: "",
    tenant: "all",
    severity: "all",
    status: "active",
    sort: "risk_desc",
  });
}
