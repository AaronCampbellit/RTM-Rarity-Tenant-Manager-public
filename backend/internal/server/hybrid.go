package server

import (
	"context"

	"github.com/rarity/rtm/internal/model"
)

// Hybrid AD / Entra source-of-authority awareness.
//
// RTM treats Entra ID as the cloud management surface but respects when an
// object is mastered on-premises. For a synced (on-prem) object, the directory
// identity core (display name, sign-in enable/disable, synced-group membership)
// lives in Active Directory — RTM must not fire a cloud write that AD would
// reject or overwrite at the next sync. Cloud-authoritative facets (licensing,
// session revocation, MFA, cloud-only group membership, and everything in
// Exchange Online / SharePoint) stay fully usable, so only the on-prem-mastered
// actions are refused. See hybrid-ad-entra-sync-framework.md.

// onPremResolution is the standard technician-facing instruction shown on a
// blocked action (framework §52).
const onPremResolution = "Make this change in on-prem Active Directory, then allow Entra sync to update Microsoft 365."

// userOnPrem reports whether a user's directory identity is mastered on-prem.
func userOnPrem(u model.User) bool { return u.SourceOfAuthority == model.SourceOnPrem }

// blockUserDirectory reports whether a user-target directory action is
// on-prem-mastered for a synced user. Only sign-in enable/disable is refused;
// licensing, session revocation, and every cloud/Exchange/SharePoint action
// remain allowed for synced users because those facets are cloud-authoritative.
func blockUserDirectory(action string) bool {
	return action == "block_signin" || action == "unblock_signin"
}

// tenantIdentity computes a tenant's hybrid identity summary. The
// authoritative signal is the tenant-level Entra Connect flag
// (organization.onPremisesSyncEnabled): false/never-configured means cloud
// regardless of object counts, and true means hybrid even when no synced
// objects appear in the first page of users/groups. Per-object counts refine
// hybrid into "mixed" (both synced and cloud objects) and provide the numbers
// for the detail view. It is tolerant of Graph errors (a partial or failed
// read yields zero counts / "unknown") so the tenant detail view always
// renders.
func (s *Server) tenantIdentity(ctx context.Context, tenantID string) (mode string, syncedUsers, cloudUsers, syncedGroups, cloudGroups int) {
	usersErr, groupsErr := true, true

	// Tenant-level flag first — it decides cloud vs hybrid; objects only
	// refine. orgKnown is false when Graph couldn't answer (fall back to
	// counts alone, as before).
	var orgSync, orgKnown bool
	if enabled, err := s.graph.DirectorySyncEnabled(ctx, tenantID); err == nil {
		orgKnown = true
		orgSync = enabled != nil && *enabled
	} else {
		s.log.Warn("tenant identity: organization sync flag unavailable", "tenant", tenantID, "error", err)
	}

	if users, err := s.graph.Users(ctx, tenantID); err == nil {
		usersErr = false
		for _, u := range users {
			switch u.SourceOfAuthority {
			case model.SourceOnPrem:
				syncedUsers++
			case model.SourceCloud:
				cloudUsers++
			}
		}
	} else {
		s.log.Warn("tenant identity: users unavailable", "tenant", tenantID, "error", err)
	}

	if groups, err := s.graph.Groups(ctx, tenantID); err == nil {
		groupsErr = false
		for _, g := range groups {
			if g.Source == "On-prem sync" {
				syncedGroups++
			} else {
				cloudGroups++
			}
		}
	} else {
		s.log.Warn("tenant identity: groups unavailable", "tenant", tenantID, "error", err)
	}

	synced := syncedUsers + syncedGroups
	cloud := cloudUsers + cloudGroups
	switch {
	case orgKnown && !orgSync:
		// Entra Connect is off / never configured — the tenant is cloud even
		// if stale sync flags linger on individual objects.
		mode = model.IdentityCloud
	case orgKnown && orgSync:
		if synced > 0 && cloud > 0 {
			mode = model.IdentityMixed
		} else {
			// Sync is on tenant-wide: hybrid even when the sampled objects
			// don't include a synced one.
			mode = model.IdentityHybrid
		}
	case usersErr && groupsErr:
		mode = model.IdentityUnknown
	case synced > 0 && cloud > 0:
		mode = model.IdentityMixed
	case synced > 0:
		mode = model.IdentityHybrid
	case cloud > 0:
		mode = model.IdentityCloud
	default:
		mode = model.IdentityUnknown
	}
	return mode, syncedUsers, cloudUsers, syncedGroups, cloudGroups
}
