import type { ChangeRequest } from "../../types/index.ts";

export const USER_ACTIONS: { value: ChangeRequest["action"]; label: string }[] = [
  { value: "add_to_group", label: "Add to group" },
  { value: "remove_from_group", label: "Remove from group" },
  { value: "block_signin", label: "Block sign-in" },
  { value: "unblock_signin", label: "Unblock sign-in" },
  { value: "assign_license", label: "Assign license" },
  { value: "remove_license", label: "Remove license" },
  { value: "reset_password", label: "Reset password" },
  { value: "revoke_user_access", label: "Revoke user access (compromised account)" },
];
