import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeWorkingSetUserIds } from "../src/features/working-sets/workingSet.ts";

const modalPath = new URL("../src/components/modals/SaveWorkingSetModal.tsx", import.meta.url);
const clientPath = new URL("../src/api/client.ts", import.meta.url);
const pagePath = new URL("../src/features/working-sets/WorkingSetsPage.tsx", import.meta.url);
const detailPath = new URL("../src/features/working-sets/WorkingSetDetailDialog.tsx", import.meta.url);
const usersPath = new URL("../src/features/users/UsersPage.tsx", import.meta.url);

test("working-set target normalization removes empty and duplicate IDs", () => {
  assert.deepEqual(
    normalizeWorkingSetUserIds(["usr_1", " usr_2 ", "usr_1", ""]),
    ["usr_1", "usr_2"],
  );
});

test("save dialog persists through the working-set API and confirms success", async () => {
  const [modal, client] = await Promise.all([
    readFile(modalPath, "utf8"),
    readFile(clientPath, "utf8"),
  ]);
  assert.match(modal, /await api\.workingSets\.create/);
  assert.match(modal, /tenantId: workingSet\.tenantId/);
  assert.match(modal, /setCreated\(saved\)/);
  assert.match(modal, /View Working Sets/);
  assert.match(modal, /htmlFor="working-set-name"/);
  assert.match(modal, /id="working-set-name"/);
  assert.match(client, /create: \(body: NewWorkingSet\): Promise<WorkingSet>/);
});

test("working sets open, persist edits, and can load their users", async () => {
  const [page, detail, client, users] = await Promise.all([
    readFile(pagePath, "utf8"),
    readFile(detailPath, "utf8"),
    readFile(clientPath, "utf8"),
    readFile(usersPath, "utf8"),
  ]);
  assert.match(page, /onRowClick=\{\(workingSet\) => setSelectedId\(workingSet\.id\)\}/);
  assert.match(page, /<WorkingSetDetailDialog/);
  assert.match(detail, /await api\.workingSets\.update/);
  assert.match(detail, /Save changes/);
  assert.match(detail, /Open in Users/);
  assert.match(detail, /memberIds\.size === 0/);
  assert.match(client, /get: \(id: string\): Promise<WorkingSet>/);
  assert.match(client, /update: \(id: string, body: WorkingSetUpdate\): Promise<WorkingSet>/);
  assert.match(users, /Loaded Working Set/);
  assert.match(users, /setSelected\(new Set\(workingSet\.userIds\)\)/);
});
