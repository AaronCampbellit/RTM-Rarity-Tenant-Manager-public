import assert from "node:assert/strict";
import test from "node:test";

import {
  activeSecurityStorylines,
  filterSecurityStorylines,
  type StorylineFilters,
} from "../src/features/security-operations/attackStorylines.ts";
import type { SecurityStoryline } from "../src/types/index.ts";

function storyline(id: string, status: SecurityStoryline["status"], riskScore: number, lastSeen: string): SecurityStoryline {
  return {
    id,
    packId: "account_takeover_bec",
    title: id,
    summary: "Connected evidence",
    severity: "High",
    riskScore,
    confidence: "high",
    status,
    firstSeen: lastSeen,
    lastSeen,
    updatedAt: lastSeen,
    tenantIds: ["ten_1"],
    tenantNames: ["Contoso"],
    entities: [],
    stages: ["Initial Access", "Persistence"],
    workloads: ["Entra ID", "Exchange"],
    detectionIds: ["det_1", "det_2"],
    eventIds: ["evt_1", "evt_2"],
    signalCount: 2,
    affectedUsers: 1,
    affectedResources: 1,
    reasons: ["Two independent rules affected the same account."],
    recommendedActions: ["Review and contain the account."],
  };
}

test("active storylines prioritize risk and do not mutate the API snapshot", () => {
  const source = [
    storyline("resolved", "Resolved", 99, "2026-08-26T13:00:00Z"),
    storyline("medium", "In Progress", 70, "2026-08-26T12:00:00Z"),
    storyline("critical", "New", 92, "2026-08-26T11:00:00Z"),
  ];
  const originalOrder = source.map((item) => item.id);
  assert.deepEqual(activeSecurityStorylines(source).map((item) => item.id), ["critical", "medium"]);
  assert.deepEqual(source.map((item) => item.id), originalOrder);
});

const DEFAULT_FILTERS: StorylineFilters = {
  query: "",
  tenant: "all",
  severity: "all",
  status: "all",
  sort: "risk_desc",
};

test("storyline queue can revisit handled work and filter across analyst context", () => {
  const resolved = storyline("Resolved mailbox persistence", "Resolved", 88, "2026-08-26T10:00:00Z");
  resolved.severity = "Critical";
  resolved.owner = "Jordan Meyer";
  resolved.tenantIds = ["ten_2"];
  resolved.tenantNames = ["Adventure Works"];
  resolved.entities = [{ type: "account", key: "account", label: "avery@adventure.example" }];
  resolved.stages = ["Persistence"];
  resolved.workloads = ["Exchange"];

  const active = storyline("Active privilege escalation", "New", 72, "2026-08-26T12:00:00Z");
  active.workloads = ["Entra"];
  const source = [active, resolved];

  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, status: "active" }).map((item) => item.id), [active.id]);
  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, status: "Resolved" }).map((item) => item.id), [resolved.id]);
  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, tenant: "ten_2" }).map((item) => item.id), [resolved.id]);
  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, severity: "Critical" }).map((item) => item.id), [resolved.id]);
  for (const query of ["Jordan", "avery@adventure", "Adventure Works", "Exchange"]) {
    assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, query }).map((item) => item.id), [resolved.id], query);
  }
});

test("storyline queue supports risk, activity, and title sorting without mutation", () => {
  const source = [
    storyline("Zulu", "New", 70, "2026-08-26T10:00:00Z"),
    storyline("Alpha", "Resolved", 92, "2026-08-26T09:00:00Z"),
    storyline("Bravo", "In Progress", 70, "2026-08-26T12:00:00Z"),
  ];
  const originalOrder = source.map((item) => item.id);

  assert.deepEqual(filterSecurityStorylines(source, DEFAULT_FILTERS).map((item) => item.id), ["Alpha", "Bravo", "Zulu"]);
  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, sort: "activity_desc" }).map((item) => item.id), ["Bravo", "Zulu", "Alpha"]);
  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, sort: "activity_asc" }).map((item) => item.id), ["Alpha", "Zulu", "Bravo"]);
  assert.deepEqual(filterSecurityStorylines(source, { ...DEFAULT_FILTERS, sort: "title_asc" }).map((item) => item.id), ["Alpha", "Bravo", "Zulu"]);
  assert.deepEqual(source.map((item) => item.id), originalOrder);
});
