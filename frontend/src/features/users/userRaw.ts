const LABELS: Record<string, string> = {
  accountEnabled: "Account enabled",
  assignedLicenses: "Assigned licenses",
  businessPhones: "Business phone",
  companyName: "Company",
  createdDateTime: "Created",
  employeeHireDate: "Hire date",
  employeeId: "Employee ID",
  employeeType: "Employee type",
  externalUserState: "Guest invitation status",
  externalUserStateChangeDateTime: "Guest status changed",
  id: "Directory object ID",
  imAddresses: "IM addresses",
  identities: "Sign-in identities",
  jobTitle: "Job title",
  mail: "Primary email",
  mailNickname: "Mail alias",
  mobilePhone: "Mobile phone",
  officeLocation: "Office",
  onPremisesDistinguishedName: "Distinguished name",
  onPremisesDomainName: "AD domain",
  onPremisesImmutableId: "Immutable ID",
  onPremisesLastSyncDateTime: "Last directory sync",
  onPremisesSamAccountName: "SAM account name",
  onPremisesSyncEnabled: "On-premises sync",
  onPremisesUserPrincipalName: "On-premises UPN",
  otherMails: "Alternate email",
  postalCode: "Postal code",
  preferredLanguage: "Preferred language",
  proxyAddresses: "Email aliases",
  securityIdentifier: "Security identifier",
  showInAddressList: "Visible in address list",
  signInSessionsValidFromDateTime: "Sessions valid from",
  streetAddress: "Street address",
  usageLocation: "Usage location",
  userPrincipalName: "User principal name",
  userType: "User type",
};

export function humanizeUserAttribute(key: string): string {
  if (LABELS[key]) return LABELS[key];
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : key;
}

export function isPopulatedAttribute(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

export function attributeSummary(value: unknown): string {
  if (!isPopulatedAttribute(value)) return "Not set";
  if (Array.isArray(value)) return `${value.length} ${value.length === 1 ? "item" : "items"}`;
  if (typeof value === "object" && value !== null) {
    const count = Object.keys(value).length;
    return `${count} ${count === 1 ? "field" : "fields"}`;
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

export function stringList(value: unknown[]): string[] {
  return value.flatMap((item) => {
    if (typeof item === "string" || typeof item === "number") return [String(item)];
    return [];
  });
}

export function formatUserDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: value.includes("T") ? "numeric" : undefined,
    minute: value.includes("T") ? "2-digit" : undefined,
  });
}
