import assert from "node:assert/strict";
import test from "node:test";

import { normalizeEventSearch } from "../src/features/security-operations/eventSearch.ts";

test("normalizes local search dates and resets pagination", () => {
  const result = normalizeEventSearch({
    query: "aaron campbell",
    from: "2026-08-24T07:47",
    to: "2026-08-25T07:47",
    offset: 50,
    limit: 50,
  });
  assert.equal(result.from, new Date("2026-08-24T07:47").toISOString());
  assert.equal(result.to, new Date("2026-08-25T07:47").toISOString());
  assert.equal(result.offset, 0);
});

test("rejects incomplete, reversed, and excessive event windows", () => {
  assert.throws(() => normalizeEventSearch({ from: "", to: "2026-08-25T07:47" }), /both a start and end/i);
  assert.throws(() => normalizeEventSearch({ from: "2026-08-26T07:47", to: "2026-08-25T07:47" }), /after the start/i);
  assert.throws(() => normalizeEventSearch({ from: "2026-01-01T00:00", to: "2026-08-25T00:00" }), /180-day/i);
});
