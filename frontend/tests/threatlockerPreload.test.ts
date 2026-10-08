import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  runThreatLockerPreload,
  type ThreatLockerPreloadLoaders,
} from "../src/features/threatlocker/preload.ts";
import { threatLockerReadPath } from "../src/features/threatlocker/threatlockerPaths.ts";

test("preloads all ThreatLocker datasets with concurrency two", async () => {
  let active = 0;
  let maximum = 0;
  const started: string[] = [];
  const loader = (name: string) => async () => {
    started.push(name);
    active += 1;
    maximum = Math.max(maximum, active);
    await Promise.resolve();
    active -= 1;
  };
  const loaders: ThreatLockerPreloadLoaders = {
    apps: loader("apps"),
    devices: loader("devices"),
    policies: loader("policies"),
    approvals: loader("approvals"),
    cleanupOperations: loader("cleanup-operations"),
    cleanupCandidates: loader("cleanup-candidates"),
  };

  await runThreatLockerPreload(loaders);

  assert.deepEqual(started.slice(0, 2), ["apps", "devices"]);
  assert.equal(maximum, 2);
  assert.deepEqual(started.sort(), [
    "approvals",
    "apps",
    "cleanup-candidates",
    "cleanup-operations",
    "devices",
    "policies",
  ]);
});

test("a rejected preload does not prevent later datasets", async () => {
  const started: string[] = [];
  const loader = (name: string, fails = false) => async () => {
    started.push(name);
    if (fails) throw new Error(`${name} unavailable`);
  };

  await runThreatLockerPreload({
    apps: loader("apps", true),
    devices: loader("devices"),
    policies: loader("policies"),
    approvals: loader("approvals"),
    cleanupOperations: loader("cleanup-operations"),
    cleanupCandidates: loader("cleanup-candidates"),
  });

  assert.equal(started.length, 6);
  assert.ok(started.includes("cleanup-candidates"));
});

test("technician preload skips admin-only cleanup datasets", async () => {
  const started: string[] = [];
  const loader = (name: string) => async () => { started.push(name); };

  await runThreatLockerPreload({
    apps: loader("apps"),
    devices: loader("devices"),
    policies: loader("policies"),
    approvals: loader("approvals"),
    cleanupOperations: loader("cleanup-operations"),
    cleanupCandidates: loader("cleanup-candidates"),
  }, 2, false);

  assert.deepEqual(started.sort(), ["approvals", "apps", "devices", "policies"]);
});

test("forced ThreatLocker reads request a fresh backend snapshot", () => {
  assert.equal(threatLockerReadPath("/apps"), "/threatlocker/apps");
  assert.equal(
    threatLockerReadPath("/apps", { refresh: true }),
    "/threatlocker/apps?refresh=true",
  );
  assert.equal(
    threatLockerReadPath("/apps/cleanup-candidates", { refresh: true }),
    "/threatlocker/apps/cleanup-candidates?refresh=true",
  );
});

test("the authenticated app does not preload ThreatLocker from unrelated pages", async () => {
  const appSource = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(appSource, /ThreatLockerPreloader/);
});
