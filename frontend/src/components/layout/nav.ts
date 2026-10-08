import {
  LayoutGrid,
  Building2,
  Users,
  UsersRound,
  KeyRound,
  Mail,
  Share2,
  ShieldCheck,
  Layers,
  ListChecks,
  History,
  Globe,
  ScrollText,
  Settings,
  ShieldAlert,
  ListFilter,
  BookOpen,
  FileArchive,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  key: string;
  label: string;
  to: string;
  icon: LucideIcon;
  /** Routes (besides `to`) that should keep this item highlighted. */
  match?: string[];
  badge?: string;
}

export interface NavSection {
  label: string | null;
  items: NavItem[];
}

/** Destinations grouped by operating scope — matches RTM UI-UX Specification. */
export const NAV: NavSection[] = [
  {
    label: "Global",
    items: [
      { key: "dashboard", label: "Dashboard", to: "/dashboard", icon: LayoutGrid },
      {
        key: "security",
        label: "Security Operations",
        to: "/security",
        icon: ShieldAlert,
        match: ["/security-events"],
      },
      { key: "offline-investigations", label: "Offline Investigations", to: "/offline-investigations", icon: FileArchive, match: ["/offline-investigations/"] },
      { key: "threatlocker", label: "ThreatLocker", to: "/threatlocker", icon: ShieldCheck },
    ],
  },
  {
    label: "Tenant Tools",
    items: [
      { key: "users", label: "Users", to: "/users", icon: Users },
      { key: "groups", label: "Groups", to: "/groups", icon: UsersRound, match: ["/groups/"] },
      { key: "licensing", label: "Licensing", to: "/licensing", icon: KeyRound },
      { key: "exchange", label: "Exchange", to: "/exchange", icon: Mail },
      { key: "sharepoint", label: "SharePoint", to: "/sharepoint", icon: Share2 },
    ],
  },
  {
    label: "Operations",
    items: [
      { key: "working-sets", label: "Working Sets", to: "/working-sets", icon: Layers },
      { key: "jobs", label: "Jobs", to: "/jobs", icon: ListChecks },
      { key: "history", label: "Change History", to: "/changes", icon: History, match: ["/changes/"] },
    ],
  },
  {
    label: "Governance",
    items: [
      { key: "global-reports", label: "Global Reports", to: "/global-reports", icon: Globe },
      { key: "audit", label: "Audit Logs", to: "/audit", icon: ScrollText },
    ],
  },
  {
    label: "System",
    items: [
      { key: "tenants", label: "Tenants", to: "/tenants", icon: Building2, match: ["/tenants/"] },
      { key: "detection-rules", label: "Detection Rules", to: "/detection-rules", icon: ListFilter },
      { key: "admin", label: "Admin Settings", to: "/admin", icon: Settings },
      { key: "documentation", label: "Documentation", to: "/documentation", icon: BookOpen },
    ],
  },
];
