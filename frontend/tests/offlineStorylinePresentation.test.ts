import assert from "node:assert/strict";
import test from "node:test";

import {
  contributingStorylineDetections,
  primaryStorylineEntity,
  storylineDuration,
  storylineNarrative,
} from "../src/features/offline-investigations/storyline-presentation.ts";
import type { SecurityNativeDetection, SecurityStoryline } from "../src/types/index.ts";

const storyline: SecurityStoryline = {
  id: "story-1", packId: "account_takeover_bec", title: "Probable account takeover", summary: "Connected activity may indicate compromise.",
  severity: "Critical", riskScore: 91, confidence: "high", status: "New",
  firstSeen: "2026-08-19T10:00:00Z", lastSeen: "2026-08-20T12:30:00Z", updatedAt: "2026-08-20T12:31:00Z",
  tenantIds: ["offline:case-1"], tenantNames: ["Example"],
  entities: [{ type: "account", key: "account|user", label: "user@example.test", primary: true }],
  stages: ["Initial Access", "Persistence"], workloads: ["Entra", "Exchange"],
  detectionIds: ["detection-2", "detection-1"], eventIds: ["event-1", "event-2"], signalCount: 2,
  affectedUsers: 1, affectedResources: 1, reasons: ["Two independent signals."],
  recommendedActions: ["Validate recent sign-ins"],
};

function detection(id: string, title: string, occurredAt: string): SecurityNativeDetection {
  return {
    id, tenantId: "offline:case-1", eventId: `event-${id}`, ruleId: `rule-${id}`, ruleVersion: 1,
    title, description: `${title} description`, severity: "High", detectionType: "direct", confidence: "high",
    occurredAt, createdAt: occurredAt,
  };
}

test("storyline explanation uses the primary identity and ordered contributing evidence", () => {
  const detections = contributingStorylineDetections(storyline, [
    detection("detection-2", "Mailbox rule added", "2026-08-19T11:00:00Z"),
    detection("unrelated", "Unrelated signal", "2026-08-19T09:00:00Z"),
    detection("detection-1", "Suspicious sign-in", "2026-08-19T10:00:00Z"),
  ]);
  assert.deepEqual(detections.map((item) => item.id), ["detection-1", "detection-2"]);
  assert.equal(primaryStorylineEntity(storyline)?.label, "user@example.test");
  assert.match(storylineNarrative(storyline, detections), /Suspicious sign-in/);
  assert.match(storylineNarrative(storyline, detections), /Mailbox rule added/);
});

test("storyline duration stays readable for long and short investigations", () => {
  assert.equal(storylineDuration(storyline.firstSeen, storyline.lastSeen), "1d 2h 30m");
  assert.equal(storylineDuration("2026-08-19T10:00:00Z", "2026-08-19T10:00:10Z"), "Less than 1 minute");
});
