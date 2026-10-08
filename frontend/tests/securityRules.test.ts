import assert from "node:assert/strict";
import test from "node:test";

import {
  editableSecurityRule,
  filterRuleConditionOptions,
  mergeRuleConditionOptions,
  newSecurityRule,
  sortDetectionRules,
} from "../src/features/security-operations/securityRules.ts";
import type { SecurityAuditEvent, SecurityDetectionRule } from "../src/types/index.ts";

test("creates an exact-match disabled draft from inspected evidence", () => {
  const event: SecurityAuditEvent = {
    id: "evt-1", tenantId: "ten_1", tenantName: "Contoso", providerRecordId: "provider-1",
    contentType: "Audit.Exchange", workload: "Exchange", operation: "Set-Mailbox",
    occurredAt: "2026-08-25T12:00:00Z", ingestedAt: "2026-08-25T12:01:00Z",
  };
  const rule = newSecurityRule(event);
  assert.equal(rule.enabled, false);
  assert.deepEqual(rule.definition.workloads, ["Exchange"]);
  assert.deepEqual(rule.definition.operations, ["Set-Mailbox"]);
  assert.equal(rule.definition.operationMatch, "exact");
});

test("turns a locked built-in into a scoped override without mutating it", () => {
  const builtIn: SecurityDetectionRule = {
    id: "builtin:password_reset", ruleId: "password_reset", name: "Password reset",
    description: "Built-in", builtIn: true, override: false, locked: true,
    detectionType: "direct", severity: "Medium", confidence: "high", enabled: true,
    scope: "global", definition: { triggerMode: "builtIn" }, revision: 1, updatedBy: "System", createdAt: "", updatedAt: "",
  };
  const editable = editableSecurityRule(builtIn);
  assert.equal(editable.id, "");
  assert.equal(editable.baseRuleId, "password_reset");
  assert.equal(editable.override, true);
  assert.equal(editable.definition.triggerMode, "builtIn");
  assert.equal(builtIn.baseRuleId, undefined);
});

test("condition choices preserve legacy selections and deduplicate case-insensitively", () => {
  assert.deepEqual(
    mergeRuleConditionOptions(["Set-Mailbox", "FileDownloaded"], ["set-mailbox", "Legacy-Operation"]),
    ["FileDownloaded", "Legacy-Operation", "Set-Mailbox"],
  );
});

test("condition choices can be searched without requiring exact capitalization", () => {
  assert.deepEqual(filterRuleConditionOptions(["New-InboxRule", "Set-Mailbox", "UserLoggedIn"], "mail"), ["Set-Mailbox"]);
});

function rule(name: string, severity: SecurityDetectionRule["severity"], enabled = true): SecurityDetectionRule {
  return {
    id: name, ruleId: name, name, description: "", builtIn: true, override: false, locked: true,
    detectionType: "direct", severity, confidence: "high", enabled, scope: "global",
    definition: {}, revision: 1, updatedBy: "System", createdAt: "", updatedAt: "",
  };
}

test("sorts detection rules by name without mutating the source list", () => {
  const original = [rule("Zulu", "Low"), rule("Alpha", "High")];
  assert.deepEqual(sortDetectionRules(original, "rule", "asc").map((item) => item.name), ["Alpha", "Zulu"]);
  assert.deepEqual(original.map((item) => item.name), ["Zulu", "Alpha"]);
});

test("sorts severity from most urgent to least urgent and reverses it", () => {
  const rules = [rule("Medium", "Medium"), rule("Critical", "Critical"), rule("Low", "Low")];
  assert.deepEqual(sortDetectionRules(rules, "severity", "asc").map((item) => item.severity), ["Critical", "Medium", "Low"]);
  assert.deepEqual(sortDetectionRules(rules, "severity", "desc").map((item) => item.severity), ["Low", "Medium", "Critical"]);
});

test("sorts rule state by its displayed label", () => {
  const rules = [rule("Enabled", "Medium"), rule("Disabled", "Medium", false)];
  assert.deepEqual(sortDetectionRules(rules, "status", "asc").map((item) => item.enabled), [false, true]);
});
