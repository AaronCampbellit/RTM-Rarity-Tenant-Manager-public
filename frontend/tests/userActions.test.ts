import assert from "node:assert/strict";
import test from "node:test";
import { USER_ACTIONS } from "../src/features/users/userActions.ts";

test("user actions expose password reset and compromised-account containment", () => {
  const values = USER_ACTIONS.map((action) => action.value);
  assert.ok(values.includes("reset_password"));
  assert.ok(values.includes("revoke_user_access"));
  assert.ok(!values.includes("revoke_sessions"));
});
