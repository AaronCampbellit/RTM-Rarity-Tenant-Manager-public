import assert from "node:assert/strict";
import test from "node:test";
import { groupTimelineActivity } from "../src/features/security-operations/storylineTimeline.ts";

test("activity groups dates and hours chronologically without changing input or combining tenants", () => {
  const items = [
    { id: "a", tenant: "one", time: new Date(2026, 8, 24, 14, 30).toISOString() },
    { id: "b", tenant: "two", time: new Date(2026, 8, 22, 9).toISOString() },
    { id: "a", tenant: "two", time: new Date(2026, 8, 24, 14, 10).toISOString() },
    { id: "bad", tenant: "one", time: "invalid" },
  ];
  const original = [...items];
  const result = groupTimelineActivity(items, (item) => item.time);
  assert.equal(result.days.length, 2);
  assert.equal(result.days[0].start.getDate(), 22);
  assert.equal(result.days[1].count, 2);
  assert.deepEqual(result.days[1].hours[14].map((item) => item.tenant), ["two", "one"]);
  assert.equal(result.undated, 1);
  assert.deepEqual(items, original);
});

test("empty and filtered activity have no stale date groups", () => {
  assert.deepEqual(groupTimelineActivity([], () => ""), { days: [], undated: 0 });
  const result = groupTimelineActivity([{ time: new Date(2026, 8, 24, 23, 59).toISOString() }], (item) => item.time);
  assert.equal(result.days.length, 1);
  assert.equal(result.days[0].hours[23].length, 1);
});

test("repeated daylight-saving hours retain both signals on their local day", () => {
  const previous = process.env.TZ;
  process.env.TZ = "America/New_York";
  try {
    const result = groupTimelineActivity(["2026-11-01T01:30:00-05:00", "2026-11-01T01:30:00-04:00"], (time) => time);
    assert.equal(result.days.length, 1);
    assert.deepEqual(result.days[0].hours[1], ["2026-11-01T01:30:00-04:00", "2026-11-01T01:30:00-05:00"]);
  } finally { if (previous === undefined) delete process.env.TZ; else process.env.TZ = previous; }
});
