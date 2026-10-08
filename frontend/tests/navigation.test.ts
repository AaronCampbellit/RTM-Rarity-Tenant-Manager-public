import assert from "node:assert/strict";
import test from "node:test";

import { NAV } from "../src/components/layout/nav.ts";

test("navigation separates global and tenant-scoped workspaces", () => {
  const sections = new Map(NAV.map((section) => [section.label, section.items]));

  assert.deepEqual(
    sections.get("Global")?.map((item) => item.label),
    ["Dashboard", "Security Operations", "Offline Investigations", "ThreatLocker"],
  );
  assert.deepEqual(
    sections.get("Tenant Tools")?.map((item) => item.label),
    ["Users", "Groups", "Licensing", "Exchange", "SharePoint"],
  );
});

test("raw events nest under security operations and system tools stay grouped", () => {
  const allItems = NAV.flatMap((section) => section.items);
  const securityOperations = allItems.find((item) => item.key === "security");
  const system = NAV.find((section) => section.label === "System");

  assert.equal(allItems.some((item) => item.key === "security-events"), false);
  assert.deepEqual(securityOperations?.match, ["/security-events"]);
  assert.deepEqual(
    system?.items.map((item) => item.label),
    ["Tenants", "Detection Rules", "Admin Settings", "Documentation"],
  );
});
