import assert from "node:assert/strict";
import test from "node:test";

import { normalizeSecurityEventDetail } from "../src/api/securityEventDetail.ts";
import type { SecurityAuditEventDetail } from "../src/types/index.ts";

test("normalizes nullable event detail collections and evidence", () => {
  const partial = {
    id: "evt-1",
    sources: null,
    sourceEvidence: null,
    relatedDetections: null,
    raw: null,
    rawTruncated: null,
  } as unknown as SecurityAuditEventDetail;

  const detail = normalizeSecurityEventDetail(partial);
  assert.deepEqual(detail.sources, []);
  assert.deepEqual(detail.sourceEvidence, []);
  assert.deepEqual(detail.relatedDetections, []);
  assert.deepEqual(detail.raw, {});
  assert.equal(detail.rawTruncated, false);
});

test("normalizes each retained source payload independently", () => {
  const partial = {
    id: "evt-1",
    sources: ["entra_graph", "m365_audit"],
    sourceEvidence: [{ source: "entra_graph", raw: null, rawTruncated: null }],
    relatedDetections: [],
    raw: {},
    rawTruncated: false,
  } as unknown as SecurityAuditEventDetail;

  const detail = normalizeSecurityEventDetail(partial);
  assert.deepEqual(detail.sourceEvidence[0].raw, {});
  assert.equal(detail.sourceEvidence[0].rawTruncated, false);
});

test("rejects an empty successful response instead of crashing the route", () => {
  assert.throws(() => normalizeSecurityEventDetail(null), /response was empty/i);
});
