import assert from "node:assert/strict";
import test from "node:test";

import {
  clearSessionQueries,
  loadSessionQuery,
  readSessionQuery,
  subscribeSessionQuery,
} from "../src/api/sessionQueryStore.ts";

test.beforeEach(() => clearSessionQueries());

test("deduplicates concurrent consumers and publishes the value", async () => {
  let calls = 0;
  let release!: (value: string[]) => void;
  const loader = () => {
    calls += 1;
    return new Promise<string[]>((resolve) => {
      release = resolve;
    });
  };
  let notifications = 0;
  const unsubscribe = subscribeSessionQuery("threatlocker:apps", () => {
    notifications += 1;
  });

  const first = loadSessionQuery("threatlocker:apps", loader);
  const second = loadSessionQuery("threatlocker:apps", loader);
  release(["app-1"]);

  assert.deepEqual(await first, ["app-1"]);
  assert.deepEqual(await second, ["app-1"]);
  assert.equal(calls, 1);
  assert.deepEqual(readSessionQuery<string[]>("threatlocker:apps").data, ["app-1"]);
  assert.equal(readSessionQuery("threatlocker:apps").loading, false);
  assert.ok(notifications >= 2);
  unsubscribe();
});

test("force reloads while retaining visible data", async () => {
  await loadSessionQuery("threatlocker:apps", async () => ["app-1"]);
  let release!: (value: string[]) => void;
  const refresh = loadSessionQuery(
    "threatlocker:apps",
    () => new Promise<string[]>((resolve) => {
      release = resolve;
    }),
    { force: true },
  );

  const refreshing = readSessionQuery<string[]>("threatlocker:apps");
  assert.deepEqual(refreshing.data, ["app-1"]);
  assert.equal(refreshing.refreshing, true);
  release(["app-2"]);
  await refresh;
  assert.deepEqual(readSessionQuery<string[]>("threatlocker:apps").data, ["app-2"]);
});

test("failed requests are retryable and do not replace successful data", async () => {
  await loadSessionQuery("threatlocker:apps", async () => ["app-1"]);
  await assert.rejects(
    loadSessionQuery(
      "threatlocker:apps",
      async () => {
        throw new Error("portal unavailable");
      },
      { force: true },
    ),
    /portal unavailable/,
  );

  const failed = readSessionQuery<string[]>("threatlocker:apps");
  assert.deepEqual(failed.data, ["app-1"]);
  assert.match(failed.error?.message ?? "", /portal unavailable/);

  await loadSessionQuery("threatlocker:apps", async () => ["app-2"], { force: true });
  assert.deepEqual(readSessionQuery<string[]>("threatlocker:apps").data, ["app-2"]);
  assert.equal(readSessionQuery("threatlocker:apps").error, undefined);
});

test("failure TTL suppresses repeated background requests until an explicit refresh", async () => {
  let calls = 0;
  const failingLoader = async () => {
    calls += 1;
    throw new Error("connector offline");
  };

  await assert.rejects(
    loadSessionQuery("threatlocker:devices", failingLoader, { failureTtlMs: 60_000 }),
    /connector offline/,
  );
  await assert.rejects(
    loadSessionQuery("threatlocker:devices", failingLoader, { failureTtlMs: 60_000 }),
    /connector offline/,
  );
  assert.equal(calls, 1);

  await assert.rejects(
    loadSessionQuery("threatlocker:devices", failingLoader, { force: true, failureTtlMs: 60_000 }),
    /connector offline/,
  );
  assert.equal(calls, 2);
});

test("clear prevents an earlier session promise from repopulating data", async () => {
  let release!: (value: string[]) => void;
  const pending = loadSessionQuery(
    "threatlocker:apps",
    () => new Promise<string[]>((resolve) => {
      release = resolve;
    }),
  );

  clearSessionQueries("threatlocker:");
  release(["old-session-app"]);
  await pending;

  assert.equal(readSessionQuery("threatlocker:apps").data, undefined);
});
