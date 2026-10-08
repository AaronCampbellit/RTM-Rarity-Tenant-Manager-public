import type { User } from "@/types";

export type UserColumnId =
  | "name"
  | "upn"
  | "mail"
  | "userType"
  | "department"
  | "jobTitle"
  | "companyName"
  | "officeLocation"
  | "employeeId"
  | "employeeType"
  | "businessPhones"
  | "mobilePhone"
  | "streetAddress"
  | "city"
  | "state"
  | "postalCode"
  | "country"
  | "usageLocation"
  | "preferredLanguage"
  | "license"
  | "mfa"
  | "source"
  | "status"
  | "lastSignIn"
  | "createdDateTime"
  | "onPremisesSamAccountName"
  | "onPremisesLastSyncDateTime";

export interface UserColumnDefinition {
  id: UserColumnId;
  label: string;
  width?: string;
  date?: boolean;
}

export const USER_COLUMN_DEFINITIONS: UserColumnDefinition[] = [
  { id: "name", label: "Display name", width: "210px" },
  { id: "upn", label: "UPN", width: "230px" },
  { id: "mail", label: "Primary email", width: "220px" },
  { id: "userType", label: "User type", width: "110px" },
  { id: "department", label: "Department", width: "140px" },
  { id: "jobTitle", label: "Job title", width: "170px" },
  { id: "companyName", label: "Company", width: "160px" },
  { id: "officeLocation", label: "Office", width: "130px" },
  { id: "employeeId", label: "Employee ID", width: "130px" },
  { id: "employeeType", label: "Employee type", width: "140px" },
  { id: "businessPhones", label: "Business phone", width: "160px" },
  { id: "mobilePhone", label: "Mobile phone", width: "150px" },
  { id: "streetAddress", label: "Street address", width: "200px" },
  { id: "city", label: "City", width: "130px" },
  { id: "state", label: "State", width: "120px" },
  { id: "postalCode", label: "Postal code", width: "120px" },
  { id: "country", label: "Country", width: "130px" },
  { id: "usageLocation", label: "Usage location", width: "130px" },
  { id: "preferredLanguage", label: "Language", width: "120px" },
  { id: "license", label: "Licenses", width: "190px" },
  { id: "mfa", label: "MFA", width: "120px" },
  { id: "source", label: "Source", width: "130px" },
  { id: "status", label: "Status", width: "110px" },
  { id: "lastSignIn", label: "Last sign-in", width: "175px", date: true },
  { id: "createdDateTime", label: "Created", width: "175px", date: true },
  { id: "onPremisesSamAccountName", label: "SAM account name", width: "160px" },
  { id: "onPremisesLastSyncDateTime", label: "Last directory sync", width: "175px", date: true },
];

export const DEFAULT_USER_COLUMNS: UserColumnId[] = [
  "name",
  "upn",
  "department",
  "license",
  "mfa",
  "source",
  "status",
  "lastSignIn",
];

const USER_COLUMN_IDS = new Set(USER_COLUMN_DEFINITIONS.map((column) => column.id));

export function normalizeVisibleUserColumns(value: unknown): UserColumnId[] {
  if (!Array.isArray(value)) return DEFAULT_USER_COLUMNS;
  const columns = value.filter(
    (candidate): candidate is UserColumnId => typeof candidate === "string" && USER_COLUMN_IDS.has(candidate as UserColumnId),
  );
  if (!columns.includes("name")) columns.unshift("name");
  return columns.length > 0 ? Array.from(new Set(columns)) : DEFAULT_USER_COLUMNS;
}

export function userColumnText(user: User, column: UserColumnId): string {
  switch (column) {
    case "name": return user.name;
    case "upn": return user.upn;
    case "mail": return user.mail ?? "";
    case "userType": return user.userType ?? "";
    case "department": return user.department ?? "";
    case "jobTitle": return user.jobTitle ?? "";
    case "companyName": return user.companyName ?? "";
    case "officeLocation": return user.officeLocation ?? "";
    case "employeeId": return user.employeeId ?? "";
    case "employeeType": return user.employeeType ?? "";
    case "businessPhones": return user.businessPhones?.join(", ") ?? "";
    case "mobilePhone": return user.mobilePhone ?? "";
    case "streetAddress": return user.streetAddress ?? "";
    case "city": return user.city ?? "";
    case "state": return user.state ?? "";
    case "postalCode": return user.postalCode ?? "";
    case "country": return user.country ?? "";
    case "usageLocation": return user.usageLocation ?? "";
    case "preferredLanguage": return user.preferredLanguage ?? "";
    case "license": return user.license || (user.licenses?.length ? user.licenses.join(", ") : "Unlicensed");
    case "mfa": return user.mfa;
    case "source": return user.sourceOfAuthority === "on_prem" ? "On-prem sync" : user.sourceOfAuthority === "cloud" ? "Cloud" : "Unknown";
    case "status": return user.status;
    case "lastSignIn": return lastSignInText(user);
    case "createdDateTime": return formatDirectoryDate(user.createdDateTime ?? "");
    case "onPremisesSamAccountName": return user.onPremisesSamAccountName ?? "";
    case "onPremisesLastSyncDateTime": return formatDirectoryDate(user.onPremisesLastSyncDateTime ?? "");
  }
}

export function lastSignInText(user: User): string {
  if (!user.lastSignInAvailable) return "Unavailable";
  if (!user.lastSignIn) return "Never";
  return formatDirectoryDate(user.lastSignIn);
}

export function formatDirectoryDate(value: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

export interface UserDirectorySort {
  column: UserColumnId;
  direction: "asc" | "desc";
}

export function filterAndSortUsers(
  users: User[],
  query: string,
  filters: Partial<Record<UserColumnId, string>>,
  sort: UserDirectorySort,
): User[] {
  const globalNeedle = query.trim().toLocaleLowerCase();
  const activeFilters = Object.entries(filters).filter((entry): entry is [UserColumnId, string] => Boolean(entry[1]?.trim()));
  const filtered = users.filter((user) => {
    if (globalNeedle && !USER_COLUMN_DEFINITIONS.some(({ id }) => userColumnText(user, id).toLocaleLowerCase().includes(globalNeedle))) {
      return false;
    }
    return activeFilters.every(([column, value]) => userColumnText(user, column).toLocaleLowerCase().includes(value.trim().toLocaleLowerCase()));
  });

  const definition = USER_COLUMN_DEFINITIONS.find(({ id }) => id === sort.column);
  return [...filtered].sort((left, right) => {
    const leftValue = sortValue(left, sort.column, definition?.date === true);
    const rightValue = sortValue(right, sort.column, definition?.date === true);
    const compared = typeof leftValue === "number" && typeof rightValue === "number"
      ? leftValue - rightValue
      : String(leftValue).localeCompare(String(rightValue), undefined, { numeric: true, sensitivity: "base" });
    return sort.direction === "asc" ? compared : -compared;
  });
}

function sortValue(user: User, column: UserColumnId, date: boolean): string | number {
  if (date) {
    const raw = column === "lastSignIn" ? user.lastSignIn : column === "createdDateTime" ? user.createdDateTime : user.onPremisesLastSyncDateTime;
    const timestamp = Date.parse(raw);
    return Number.isNaN(timestamp) ? -1 : timestamp;
  }
  return userColumnText(user, column);
}
