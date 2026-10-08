import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "../src/types/index.ts";
import {
  DEFAULT_USER_COLUMNS,
  filterAndSortUsers,
  lastSignInText,
  normalizeVisibleUserColumns,
} from "../src/features/users/userDirectory.ts";

const base: User = {
  id: "u1",
  name: "Ada Active",
  givenName: "Ada",
  surname: "Active",
  upn: "ada@contoso.com",
  mail: "ada@contoso.com",
  userType: "Member",
  department: "Engineering",
  jobTitle: "Principal Engineer",
  companyName: "Contoso",
  officeLocation: "Seattle HQ",
  employeeId: "CT-100",
  employeeType: "Employee",
  businessPhones: ["+1 555 0100"],
  mobilePhone: "+1 555 0200",
  streetAddress: "1 Contoso Way",
  city: "Seattle",
  state: "WA",
  postalCode: "98101",
  country: "United States",
  usageLocation: "US",
  preferredLanguage: "en-US",
  createdDateTime: "2024-01-01T00:00:00Z",
  onPremisesSamAccountName: "",
  onPremisesLastSyncDateTime: "",
  license: "Microsoft 365 E5",
  licenses: ["Microsoft 365 E5"],
  mfa: "Enabled",
  status: "Active",
  lastSignIn: "2026-08-26T09:15:00Z",
  lastSignInAvailable: true,
  sourceOfAuthority: "cloud",
};

test("visible user columns are schema-checked and keep display name", () => {
  assert.deepEqual(normalizeVisibleUserColumns(["mail", "bogus", "status"]), ["name", "mail", "status"]);
  assert.deepEqual(normalizeVisibleUserColumns(null), DEFAULT_USER_COLUMNS);
});

test("global and per-column filters cover optional directory attributes", () => {
  const bo = { ...base, id: "u2", name: "Bo Baker", upn: "bo@contoso.com", jobTitle: "Accountant", department: "Finance" };
  assert.deepEqual(filterAndSortUsers([base, bo], "principal engineer", {}, { column: "name", direction: "asc" }).map((user) => user.id), ["u1"]);
  assert.deepEqual(filterAndSortUsers([base, bo], "", { department: "fin" }, { column: "name", direction: "asc" }).map((user) => user.id), ["u2"]);
});

test("every directory column can sort and sign-in availability is explicit", () => {
  const older = { ...base, id: "u2", name: "Bo", lastSignIn: "2026-01-01T00:00:00Z" };
  assert.deepEqual(filterAndSortUsers([base, older], "", {}, { column: "lastSignIn", direction: "asc" }).map((user) => user.id), ["u2", "u1"]);
  assert.equal(lastSignInText({ ...base, lastSignIn: "" }), "Never");
  assert.equal(lastSignInText({ ...base, lastSignIn: "", lastSignInAvailable: false }), "Unavailable");
});
