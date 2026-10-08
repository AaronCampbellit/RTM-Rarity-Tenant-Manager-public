import assert from "node:assert/strict";
import test from "node:test";
import { timelineDays, timelineDaySearch } from "../src/features/security-operations/eventTimeline.ts";

test("timeline includes empty calendar dates and clips edge days to applied filters", () => {
  const search = { from: new Date(2026, 8, 20, 12).toISOString(), to: new Date(2026, 8, 22, 9).toISOString(), actor: "alice", offset: 50 };
  const days = timelineDays(search);
  assert.equal(days.length, 3);
  const first = timelineDaySearch(search, days[0]);
  const last = timelineDaySearch(search, days[2]);
  assert.equal(first.from, search.from);
  assert.equal(last.to, search.to);
  assert.equal(first.actor, "alice");
  assert.equal(first.offset, 0);
  assert.equal(first.limit, 100);
  assert.equal(days[0].end.getTime() + 1, days[1].start.getTime());
});

test("calendar days respect daylight saving transitions", () => {
  const previous = process.env.TZ;
  process.env.TZ = "America/New_York";
  try {
    const days = timelineDays({ from: "2026-03-08T00:00:00-05:00", to: "2026-03-09T00:00:00-04:00" });
    assert.equal(days.length, 2);
    assert.equal(days[0].end.getTime() - days[0].start.getTime() + 1, 23 * 3600000);
  } finally { if (previous === undefined) delete process.env.TZ; else process.env.TZ = previous; }
});
