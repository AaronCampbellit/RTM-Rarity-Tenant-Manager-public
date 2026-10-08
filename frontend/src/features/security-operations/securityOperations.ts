import type {
  SecurityConnectorSummary,
  SecurityIncident,
  SecurityIncidentReference,
  SecurityTriageStatus,
  StatusTone,
} from "../../types/index.ts";

export const SECURITY_BULK_REQUEST_LIMIT = 100;
export const DEFAULT_SECURITY_INCIDENT_STATUS: SecurityTriageStatus = "New";

export function securityIncidentKey(incident: Pick<SecurityIncident, "tenantId" | "id">): string {
  return `${incident.tenantId}\u0000${incident.id}`;
}

export function chunkSecurityIncidentReferences(
  incidents: SecurityIncidentReference[],
  limit = SECURITY_BULK_REQUEST_LIMIT,
): SecurityIncidentReference[][] {
  if (!Number.isInteger(limit) || limit < 1) throw new Error("Bulk incident chunk size must be positive.");
  const chunks: SecurityIncidentReference[][] = [];
  for (let index = 0; index < incidents.length; index += limit) {
    chunks.push(incidents.slice(index, index + limit));
  }
  return chunks;
}

export interface SecurityIncidentFilters {
  query: string;
  severity: string;
  status: string;
  tenant: string;
}

export interface SecurityIncidentContext {
  subject: string;
  activity?: string;
}

const SEVERITY_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
  Unknown: 5,
};

export function securitySeverityTone(severity: string): StatusTone {
  if (severity === "Critical" || severity === "High") return "danger";
  if (severity === "Medium") return "warning";
  if (severity === "Low") return "info";
  return "neutral";
}

export function securityTriageTone(status: SecurityTriageStatus): StatusTone {
  if (status === "New") return "danger";
  if (status === "In Progress") return "warning";
  if (status === "Resolved") return "success";
  return "neutral";
}

export function securityConnectorTone(status: string): StatusTone {
  if (status === "healthy") return "success";
  if (status === "degraded" || status === "missing_permission" || status === "not_provisioned") return "danger";
  if (status === "sample") return "warning";
  return "neutral";
}

export interface ConnectorHealthMetric {
  value: string;
  detail: string;
  tone: StatusTone;
}

export function summarizeConnectorHealth(
  connectors: SecurityConnectorSummary[],
): ConnectorHealthMetric {
  const active = connectors.filter((connector) => connector.status !== "planned");
  const healthy = active.filter((connector) => connector.status === "healthy").length;
  const sample = active.filter((connector) => connector.status === "sample").length;
  const attention = active.length - healthy - sample;

  if (attention > 0) {
    return {
      value: `${healthy}/${active.length}`,
      detail: `${attention} ${attention === 1 ? "needs" : "need"} attention`,
      tone: "danger",
    };
  }
  if (sample > 0) {
    return {
      value: `${healthy}/${active.length}`,
      detail: `${sample} sample ${sample === 1 ? "source" : "sources"}`,
      tone: "warning",
    };
  }
  return {
    value: `${healthy}/${active.length}`,
    detail: active.length > 0 ? "All sources healthy" : "No active sources",
    tone: active.length > 0 ? "success" : "neutral",
  };
}

export function filterSecurityIncidents(
  incidents: SecurityIncident[],
  filters: SecurityIncidentFilters,
): SecurityIncident[] {
  const query = filters.query.trim().toLowerCase();
  return incidents
    .filter((incident) => {
      if (filters.severity !== "all" && incident.severity !== filters.severity) return false;
      if (filters.status !== "all" && incident.status !== filters.status) return false;
      if (filters.tenant !== "all" && incident.tenantId !== filters.tenant) return false;
      if (!query) return true;
      return [
        incident.title,
        incident.tenantName,
        incident.source,
        incident.owner ?? "",
        incident.detectionType ?? "",
        incident.confidence ?? "",
        incident.ruleId ?? "",
        incident.evidence?.operation ?? "",
        incident.evidence?.actor ?? "",
        incident.evidence?.target ?? "",
        incident.evidence?.relatedResource ?? "",
        ...(incident.evidence?.changes?.flatMap((change) => [change.field, change.before ?? "", change.after ?? ""]) ?? []),
        ...(incident.entities?.flatMap((entity) => [entity.type, entity.label]) ?? []),
      ].some((value) => value.toLowerCase().includes(query));
    })
    .sort((a, b) => {
      const severity =
        (SEVERITY_RANK[a.severity] ?? SEVERITY_RANK.Unknown) -
        (SEVERITY_RANK[b.severity] ?? SEVERITY_RANK.Unknown);
      if (severity !== 0) return severity;
      return securityIncidentReceivedAt(b).localeCompare(securityIncidentReceivedAt(a));
    });
}

export function securityIncidentReceivedAt(incident: Pick<SecurityIncident, "rtmReceivedAt">): string {
  return incident.rtmReceivedAt || "";
}

export function securityIncidentContext(incident: SecurityIncident): SecurityIncidentContext {
  if (incident.evidence) {
    const actor = incident.evidence.actor || readableEntity(incident, ["account", "user"]);
    const target = incident.evidence.target || readableEntity(incident, ["resource", "application", "mailbox", "group", "role"]);
    return {
      subject: actor && target ? `${actor} → ${target}` : actor || target || "Evidence available",
      activity: cleanOperation(incident.evidence.operation),
    };
  }
  const labels = (incident.entities ?? [])
    .map((entity) => friendlySecurityEntityLabel(entity.label))
    .filter((label, index, all) => label && all.indexOf(label) === index)
    .slice(0, 2);
  return { subject: labels.join(" → ") || "Open incident for details" };
}

export function friendlySecurityEntityLabel(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed.length > 180 || trimmed.split(";").length > 4) {
    const lower = trimmed.toLowerCase();
    if (lower.includes("outlook.office") || lower.includes("mail.office365")) return "Exchange Online";
    if (lower.includes("graph.microsoft")) return "Microsoft Graph";
    return "Microsoft 365 resource";
  }
  return trimmed;
}

export function securityWorkloadLabel(value?: string): string {
  switch ((value ?? "").toLowerCase()) {
    case "azureactivedirectory":
      return "Microsoft Entra ID";
    case "exchange":
      return "Exchange Online";
    case "sharepoint":
      return "SharePoint Online";
    default:
      return value || "—";
  }
}

function readableEntity(incident: SecurityIncident, types: string[]): string {
  const wanted = new Set(types);
  const entity = incident.entities?.find((item) => wanted.has(item.type.toLowerCase()));
  return entity ? friendlySecurityEntityLabel(entity.label) : "";
}

function cleanOperation(value: string): string {
  return value.trim().replace(/[.]+$/, "");
}

export function relativeSecurityTime(value: string, now = Date.now()): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "—";
  const minutes = Math.max(0, Math.round((now - timestamp) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export function connectorStatusLabel(status: string): string {
  switch (status) {
    case "healthy":
      return "Healthy";
    case "degraded":
      return "Needs attention";
    case "sample":
      return "Sample data";
    case "planned":
      return "Planned";
    case "missing_permission":
      return "Consent required";
    case "not_provisioned":
      return "Defender setup required";
    case "auditing_disabled":
      return "Enable auditing";
    default:
      return status || "Unknown";
  }
}

/** Provider URLs are external data. Only HTTPS destinations are rendered as
 * links so a malformed connector payload cannot create an active URI scheme. */
export function safeSecurityIncidentUrl(value?: string): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}
