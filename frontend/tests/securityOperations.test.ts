import assert from "node:assert/strict";
import test from "node:test";

import {
  connectorStatusLabel,
  chunkSecurityIncidentReferences,
  DEFAULT_SECURITY_INCIDENT_STATUS,
  filterSecurityIncidents,
  relativeSecurityTime,
  securityIncidentReceivedAt,
  securityIncidentContext,
  securityIncidentKey,
  friendlySecurityEntityLabel,
  safeSecurityIncidentUrl,
  securityConnectorTone,
  securitySeverityTone,
  securityTriageTone,
  summarizeConnectorHealth,
} from "../src/features/security-operations/securityOperations.ts";
import type { SecurityIncident } from "../src/types/index.ts";

const incidents: SecurityIncident[] = [
  {
    id: "low",
    tenantId: "ten_2",
    tenantName: "Fabrikam",
    title: "Risky application",
    severity: "Low",
    status: "New",
    providerStatus: "active",
    source: "App Governance",
    alertCount: 1,
    entityCount: 1,
    entities: [{ type: "Application", label: "Legacy Importer" }],
    rtmReceivedAt: "2026-08-23T11:00:00Z",
    createdAt: "2026-08-23T10:00:00Z",
    updatedAt: "2026-08-23T11:00:00Z",
  },
  {
    id: "critical",
    tenantId: "ten_1",
    tenantName: "Contoso",
    title: "Suspicious inbox rule",
    severity: "Critical",
    status: "In Progress",
    owner: "Jordan Meyer",
    providerStatus: "active",
    source: "Defender for Office 365",
    detectionType: "correlation",
    confidence: "high",
    ruleId: "failed_logins_then_success",
    alertCount: 2,
    entityCount: 1,
    entities: [{ type: "Mailbox", label: "megan@contoso.com" }],
    rtmReceivedAt: "2026-08-23T12:00:00Z",
    createdAt: "2026-08-23T09:00:00Z",
    updatedAt: "2026-08-23T12:00:00Z",
  },
];

test("incident filters search normalized evidence and keep severe rows first", () => {
  const byEntity = filterSecurityIncidents(incidents, {
    query: "megan@contoso",
    severity: "all",
    status: "all",
    tenant: "all",
  });
  assert.deepEqual(byEntity.map((item) => item.id), ["critical"]);

  const byRuleMetadata = filterSecurityIncidents(incidents, {
    query: "failed_logins_then_success",
    severity: "all",
    status: "all",
    tenant: "all",
  });
  assert.deepEqual(byRuleMetadata.map((item) => item.id), ["critical"]);

  const all = filterSecurityIncidents(incidents, {
    query: "",
    severity: "all",
    status: "all",
    tenant: "all",
  });
  assert.deepEqual(all.map((item) => item.id), ["critical", "low"]);
});

test("incident queue defaults to new work and excludes handled stages", () => {
  assert.equal(DEFAULT_SECURITY_INCIDENT_STATUS, "New");
  const newOnly = filterSecurityIncidents(incidents, {
    query: "",
    severity: "all",
    status: DEFAULT_SECURITY_INCIDENT_STATUS,
    tenant: "all",
  });
  assert.deepEqual(newOnly.map((item) => item.id), ["low"]);
});

test("security status tones distinguish urgency, workflow, and connector health", () => {
  assert.equal(securitySeverityTone("Critical"), "danger");
  assert.equal(securitySeverityTone("Medium"), "warning");
  assert.equal(securityTriageTone("Resolved"), "success");
  assert.equal(securityConnectorTone("sample"), "warning");
  assert.equal(securityConnectorTone("degraded"), "danger");
  assert.equal(securityConnectorTone("not_provisioned"), "danger");
  assert.equal(connectorStatusLabel("not_provisioned"), "Defender setup required");
  assert.equal(connectorStatusLabel("auditing_disabled"), "Enable auditing");
});

test("connector health metric excludes planned sources and prioritizes attention", () => {
  const metric = summarizeConnectorHealth([
    { key: "defender", name: "Defender", status: "degraded", healthyTenants: 0, attentionTenants: 1, sampleTenants: 0 },
    { key: "entra", name: "Entra", status: "healthy", healthyTenants: 1, attentionTenants: 0, sampleTenants: 0 },
    { key: "audit", name: "Audit", status: "healthy", healthyTenants: 1, attentionTenants: 0, sampleTenants: 0 },
    { key: "risk", name: "Risk", status: "planned", healthyTenants: 0, attentionTenants: 0, sampleTenants: 0 },
  ]);
  assert.deepEqual(metric, {
    value: "2/3",
    detail: "1 needs attention",
    tone: "danger",
  });
});

test("relative incident-time labels remain compact for the incident queue", () => {
  const now = new Date("2026-08-23T12:00:00Z").getTime();
  assert.equal(relativeSecurityTime("2026-08-23T11:43:00Z", now), "17m ago");
  assert.equal(relativeSecurityTime("2026-08-21T12:00:00Z", now), "2d ago");
  assert.equal(relativeSecurityTime("not-a-date", now), "—");
});

test("incidents with the same severity are ordered by the time RTM received them", () => {
  const sameSeverity = incidents.map((incident) => ({ ...incident, severity: "High" }));
  const ordered = filterSecurityIncidents(sameSeverity, {
    query: "",
    severity: "all",
    status: "all",
    tenant: "all",
  });
  assert.deepEqual(ordered.map((incident) => incident.id), ["critical", "low"]);
  assert.equal(securityIncidentReceivedAt(ordered[0]), "2026-08-23T12:00:00Z");
  assert.equal(
    securityIncidentReceivedAt({}),
    "",
  );
});

test("incident links only allow HTTPS provider destinations", () => {
  assert.equal(
    safeSecurityIncidentUrl("https://security.microsoft.com/incidents/42"),
    "https://security.microsoft.com/incidents/42",
  );
  assert.equal(safeSecurityIncidentUrl("javascript:alert(1)"), undefined);
  assert.equal(safeSecurityIncidentUrl("not a URL"), undefined);
});

test("incident context promotes actor, action, and target over opaque resources", () => {
  const incident: SecurityIncident = {
    ...incidents[0],
    evidence: {
      eventId: "evt-1",
      operation: "Add app role assignment to service principal.",
      actor: "admin@example.com",
      target: "Rarity Tenant Manager",
      relatedResource: "Office 365 Exchange Online",
      occurredAt: "2026-08-25T20:38:37Z",
    },
  };
  assert.deepEqual(securityIncidentContext(incident), {
    subject: "admin@example.com → Rarity Tenant Manager",
    activity: "Add app role assignment to service principal",
  });
  assert.equal(
    friendlySecurityEntityLabel("one/outlook.office365.com;two/mail.office365.com;three/outlook.com;four/*.outlook.com;five"),
    "Exchange Online",
  );
});

test("bulk incident selection keys stay tenant-scoped and requests stay bounded", () => {
  assert.notEqual(
    securityIncidentKey({ tenantId: "tenant-a", id: "same-id" }),
    securityIncidentKey({ tenantId: "tenant-b", id: "same-id" }),
  );
  const references = Array.from({ length: 205 }, (_, index) => ({
    tenantId: `tenant-${index % 3}`,
    incidentId: `incident-${index}`,
  }));
  const chunks = chunkSecurityIncidentReferences(references);
  assert.deepEqual(chunks.map((chunk) => chunk.length), [100, 100, 5]);
  assert.deepEqual(chunks.flat(), references);
  assert.throws(() => chunkSecurityIncidentReferences(references, 0));
});
