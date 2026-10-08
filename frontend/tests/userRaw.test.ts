import assert from "node:assert/strict";
import test from "node:test";
import {
  attributeSummary,
  formatUserDate,
  humanizeUserAttribute,
  isPopulatedAttribute,
  stringList,
} from "../src/features/users/userRaw.ts";

test("raw user attributes are presented with technician-friendly labels", () => {
  assert.equal(humanizeUserAttribute("userPrincipalName"), "User principal name");
  assert.equal(humanizeUserAttribute("onPremisesLastSyncDateTime"), "Last directory sync");
  assert.equal(humanizeUserAttribute("customSecurityValue"), "Custom Security Value");
});

test("raw user values summarize complex data without dumping JSON", () => {
  assert.equal(attributeSummary([{ skuId: "one" }]), "1 item");
  assert.equal(attributeSummary({ extensionAttribute1: "IT" }), "1 field");
  assert.equal(attributeSummary(false), "No");
  assert.equal(attributeSummary([]), "Not set");
});

test("overview helpers omit empty Graph properties and retain scalar list values", () => {
  assert.equal(isPopulatedAttribute([]), false);
  assert.equal(isPopulatedAttribute({}), false);
  assert.equal(isPopulatedAttribute(false), true);
  assert.deepEqual(stringList(["one", 2, { hidden: true }, null]), ["one", "2"]);
});

test("Graph timestamps become readable while invalid values remain inspectable", () => {
  assert.match(formatUserDate("2026-07-10T04:16:57Z"), /2026/);
  assert.equal(formatUserDate("not-a-date"), "not-a-date");
});
