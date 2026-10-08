import { Network } from "lucide-react";
import { identityModeLabel } from "./status";

/**
 * Impossible-to-miss notice that a tenant carries on-prem-synced identity.
 * States the source-of-authority boundary directly: cloud actions stay usable
 * in RTM, on-prem-mastered identity must change in Active Directory. Shown on
 * the tenant detail page and, in compact form, on the user/group inventories.
 */
export function HybridNotice({
  mode,
  syncedUsers,
  cloudUsers,
  syncedGroups,
  cloudGroups,
  compact = false,
}: {
  mode?: string;
  syncedUsers?: number;
  cloudUsers?: number;
  syncedGroups?: number;
  cloudGroups?: number;
  compact?: boolean;
}) {
  const hasCounts =
    syncedUsers !== undefined ||
    syncedGroups !== undefined ||
    cloudUsers !== undefined ||
    cloudGroups !== undefined;

  return (
    <div className="rounded-[12px] border border-[rgba(210,161,6,.4)] bg-[rgba(210,161,6,.09)] px-4 py-3.5">
      <div className="flex items-start gap-3">
        <div className="grid size-9 shrink-0 place-items-center rounded-[9px] bg-[rgba(210,161,6,.16)]">
          <Network className="size-[18px] text-[#e3b341]" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-[13.5px] font-bold text-[#e3b341]">
            {identityModeLabel(mode)} tenant — some objects are synced from on-prem Active Directory
          </p>
          <p className="mt-1 text-[12.5px] leading-relaxed text-body">
            On-prem AD is the source of authority for synced users and groups.{" "}
            <span className="font-semibold text-fg">
              Display name, sign-in block/unblock, and synced-group membership must be changed in
              Active Directory
            </span>{" "}
            — RTM blocks those writes so a change can't be rejected or reverted at the next sync.
            Everything cloud-authoritative still works here: licensing, session revocation, MFA,
            cloud-only group membership, and all Exchange &amp; SharePoint actions.
          </p>

          {!compact && hasCounts && (
            <div className="mt-3 flex flex-wrap gap-2">
              <CountChip label="Synced users" value={syncedUsers} accent />
              <CountChip label="Cloud users" value={cloudUsers} />
              <CountChip label="Synced groups" value={syncedGroups} accent />
              <CountChip label="Cloud groups" value={cloudGroups} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CountChip({ label, value, accent }: { label: string; value?: number; accent?: boolean }) {
  if (value === undefined) return null;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-[7px] border px-2.5 py-1 text-[12px] font-medium ${
        accent
          ? "border-[rgba(210,161,6,.35)] bg-[rgba(210,161,6,.08)] text-[#e3b341]"
          : "border-[var(--border-strong)] bg-control text-body"
      }`}
    >
      <span className="font-bold">{value.toLocaleString()}</span>
      {label}
    </span>
  );
}
