import assert from "node:assert/strict";
import test from "node:test";

import { groupPreflightChecks } from "../src/features/tenants/preflight.ts";
import type { PreflightCheck } from "../src/types/index.ts";

function check(category: string, area: string, status: PreflightCheck["status"]): PreflightCheck {
  return {
    category,
    area,
    resource: "Microsoft Graph",
    permission: `${area}.Read.All`,
    status,
  };
}

test("preflight groups follow RTM navigation order and summarize attention", () => {
  const groups = groupPreflightChecks([
    check("Licensing", "License inventory", "ok"),
    check("SharePoint", "Sites", "missing"),
    check("Security Operations", "Audit ingestion", "error"),
    check("Exchange", "Mailboxes", "ok"),
    check("Directory & Identity", "Users", "ok"),
  ]);

  assert.deepEqual(groups.map((group) => group.category), [
    "Security Operations",
    "Directory & Identity",
    "Exchange",
    "SharePoint",
    "Licensing",
  ]);
  assert.equal(groups[0].attention, 1);
  assert.equal(groups[3].missing, 1);
});

test("preflight grouping does not mutate provider result order", () => {
  const checks = [
    check("Exchange", "Zeta", "ok"),
    check("Exchange", "Alpha", "ok"),
  ];
  const groups = groupPreflightChecks(checks);
  assert.deepEqual(checks.map((item) => item.area), ["Zeta", "Alpha"]);
  assert.deepEqual(groups[0].checks.map((item) => item.area), ["Alpha", "Zeta"]);
});
