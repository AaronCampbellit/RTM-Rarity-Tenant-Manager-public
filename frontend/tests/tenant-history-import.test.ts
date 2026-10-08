import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const modalPath = new URL("../src/features/tenants/AddTenantModal.tsx", import.meta.url);
const securityPath = new URL("../src/features/security-operations/SecurityOperationsPage.tsx", import.meta.url);
const explorerPath = new URL("../src/features/security-operations/RawEventExplorerPage.tsx", import.meta.url);

test("tenant onboarding offers bounded history and safe incident choices", async () => {
  const source = await readFile(modalPath, "utf8");
  assert.match(source, /Past 7 days/);
  assert.match(source, /Recommended/);
  assert.match(source, /Maximum available/);
  assert.match(source, /open incidents only from the latest 24 hours/);
  assert.match(source, /Baseline only/);
  assert.match(source, /historyWindow/);
  assert.match(source, /historicalIncidentMode/);
});

test("security operations reports import progress and raw evidence marks history", async () => {
  const [security, explorer] = await Promise.all([
    readFile(securityPath, "utf8"),
    readFile(explorerPath, "utf8"),
  ]);
  assert.match(security, /Historical evidence/);
  assert.match(security, /history\.progress/);
  assert.match(explorer, /Historical ·/);
  assert.match(explorer, /historicalImport/);
});
