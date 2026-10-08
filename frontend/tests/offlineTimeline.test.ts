import assert from "node:assert/strict";
import test from "node:test";

import { filterTimelineEvents, groupTimelineEvents } from "../src/features/offline-investigations/timeline.ts";
import type { OfflineTimelineEvent } from "../src/types/index.ts";

function event(overrides: Partial<OfflineTimelineEvent> = {}): OfflineTimelineEvent {
  return {
    id: "event-1", evidenceType: "m365_activity", source: "m365_audit", workload: "Exchange",
    operation: "MailItemsAccessed", actor: "analyst@example.test", clientIp: "198.51.100.42",
    objectId: "mailbox@example.test", resultStatus: "Succeeded", occurredAt: "2026-08-30T18:28:00Z",
    facts: [{ label: "Application", value: "Outlook" }], signals: [], ...overrides,
  };
}

test("timeline groups repetitive activity into bounded investigator bursts", () => {
  const groups = groupTimelineEvents([
    event(),
    event({ id: "event-2", occurredAt: "2026-08-30T18:20:00Z" }),
    event({ id: "event-3", occurredAt: "2026-08-30T17:59:00Z" }),
    event({ id: "event-4", clientIp: "203.0.113.9", occurredAt: "2026-08-30T18:19:00Z" }),
  ]);
  assert.equal(groups.length, 3);
  assert.equal(groups[0].events.length, 2);
  assert.equal(groups[0].newestAt, "2026-08-30T18:28:00Z");
  assert.equal(groups[0].oldestAt, "2026-08-30T18:20:00Z");
});

test("timeline filters searchable context and investigator focus", () => {
  const risky = event({
    id: "risky", resultStatus: "Failed",
    facts: [{ label: "Access", value: "External" }, { label: "Location", value: "US" }],
    signals: [{ ruleId: "mail_access_burst", title: "Unusual mailbox access", severity: "High" }],
  });
  const routine = event({ id: "routine", operation: "Send", occurredAt: "2026-08-30T18:10:00Z" });
  assert.deepEqual(filterTimelineEvents([risky, routine], { query: "unusual mailbox", focus: "signals", workload: "Exchange" }).map((item) => item.id), ["risky"]);
  assert.deepEqual(filterTimelineEvents([risky, routine], { query: "", focus: "external", workload: "" }).map((item) => item.id), ["risky"]);
  assert.deepEqual(filterTimelineEvents([risky, routine], { query: "", focus: "failures", workload: "" }).map((item) => item.id), ["risky"]);
});
