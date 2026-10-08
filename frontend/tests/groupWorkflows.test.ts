import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const createPath = new URL("../src/features/groups/CreateGroupModal.tsx", import.meta.url);
const membersPath = new URL("../src/features/groups/GroupMembersPage.tsx", import.meta.url);
const addPath = new URL("../src/features/groups/AddGroupMembersDialog.tsx", import.meta.url);

test("group creation clearly requires a purpose description", async () => {
  const source = await readFile(createPath, "utf8");
  assert.match(source, /htmlFor="group-description"/);
  assert.match(source, /id="group-description"/);
  assert.match(source, /Required so technicians can understand why the group exists/);
  assert.match(source, /required/);
  assert.match(source, /!description\.trim\(\)/);
  assert.doesNotMatch(source, /placeholder="Optional"/);
});

test("assigned Graph groups add selected users through What-If", async () => {
  const [members, add] = await Promise.all([
    readFile(membersPath, "utf8"),
    readFile(addPath, "utf8"),
  ]);
  assert.match(members, /membershipEditable = group\?\.membership === "Assigned" && group\?\.service !== "Exchange"/);
  assert.match(members, /Add users/);
  assert.match(members, /<AddGroupMembersDialog/);
  assert.match(add, /action: "add_to_group"/);
  assert.match(add, /await api\.changes\.preview\(body\)/);
  assert.match(add, /api\.changes\.execute\(body, result\.approvalToken\)/);
  assert.match(add, /existing\.has\(user\.id\)/);
  assert.match(add, /Generate What-If/);
});
