package graph

import (
	"context"
	"fmt"

	"github.com/rarity/rtm/internal/model"
)

// Sample implementations of the Share Detective reads/writes. Fixtures line
// up with the seeded directory: Ivan Petrov (the guest) has direct shares on
// Project Falcon content, Bianca appears on a specific-people link, and the
// wide-open Customer Files site carries an anonymous link — one of each
// classification the scanner distinguishes.

// UserGroupIDs approximates transitive membership from the seeded member list
// (which mirrors grp_1's roster) plus the on-prem IT Admins group for the IT
// staff, so group-based classification is exercisable offline.
func (sampleProvider) UserGroupIDs(_ context.Context, _ string, userID string) ([]string, error) {
	ids := []string{}
	for _, m := range sampleGroupMembers {
		if m.ID == userID {
			ids = append(ids, "grp_1")
			break
		}
	}
	if userID == "usr_3" || userID == "usr_10" {
		ids = append(ids, "grp_4") // IT Admins
	}
	if userID == "usr_9" {
		ids = append(ids, "grp_5") // Ivan collaborates in Project Falcon
	}
	return ids, nil
}

var sampleSharedItems = map[string][]model.SharedItem{
	"site_3": { // Project Falcon — the guest-collaboration hot spot
		{
			ItemID: "item_31", DriveID: "drive_3", Name: "Falcon-Contract.docx",
			Path: "/Shared Documents/Contracts/Falcon-Contract.docx", WebURL: "/sites/falcon/Shared%20Documents/Contracts/Falcon-Contract.docx", Type: "file",
			Permissions: []model.ItemPermission{
				{ID: "perm_311", GranteeID: "usr_9", GranteeName: "Ivan Petrov", GranteeUPN: "ivan.petrov@partner.com", GranteeType: "user", Roles: []string{"write"}},
				{ID: "perm_312", GranteeID: "grp_5", GranteeName: "Project Falcon", GranteeType: "group", Roles: []string{"write"}, Inherited: true},
			},
		},
		{
			ItemID: "item_32", DriveID: "drive_3", Name: "Design", Path: "/Shared Documents/Design",
			WebURL: "/sites/falcon/Shared%20Documents/Design", Type: "folder",
			Permissions: []model.ItemPermission{
				{ID: "perm_321", GranteeType: "link", LinkScope: "anonymous", Roles: []string{"read"}},
				{ID: "perm_322", GranteeID: "usr_9", GranteeName: "Ivan Petrov", GranteeUPN: "ivan.petrov@partner.com", GranteeType: "user", Roles: []string{"read"}},
			},
		},
	},
	"site_1": { // Sales Team — a specific-people link
		{
			ItemID: "item_11", DriveID: "drive_1", Name: "Q3-Pipeline.xlsx",
			Path: "/Shared Documents/Q3-Pipeline.xlsx", WebURL: "/sites/sales/Shared%20Documents/Q3-Pipeline.xlsx", Type: "file",
			Permissions: []model.ItemPermission{
				{ID: "perm_111", GranteeID: "usr_2", GranteeName: "Bianca Lopez", GranteeUPN: "bianca.lopez@contoso.com", GranteeType: "link", LinkScope: "users", Roles: []string{"read"}},
			},
		},
	},
	"site_5": { // Customer Files — broad anonymous link
		{
			ItemID: "item_51", DriveID: "drive_5", Name: "Client Uploads",
			Path: "/Shared Documents/Client Uploads", WebURL: "/sites/customers/Shared%20Documents/Client%20Uploads", Type: "folder",
			Permissions: []model.ItemPermission{
				{ID: "perm_511", GranteeType: "link", LinkScope: "anonymous", Roles: []string{"write"}},
			},
		},
	},
}

func (s sampleProvider) SharedItems(_ context.Context, tenantID, siteID string) ([]model.SharedItem, error) {
	items := make([]model.SharedItem, 0, len(sampleSharedItems[siteID]))
	s.writes.mu.Lock()
	deleted := s.writes.permDeletes[tenantID]
	for _, item := range sampleSharedItems[siteID] {
		copied := item
		copied.Permissions = nil
		for _, p := range item.Permissions {
			if deleted[item.DriveID+"|"+item.ItemID+"|"+p.ID] {
				continue
			}
			copied.Permissions = append(copied.Permissions, p)
		}
		items = append(items, copied)
	}
	s.writes.mu.Unlock()
	return items, nil
}

func (w *sampleWrites) markDeleted(tenantID, key string) {
	if w.permDeletes[tenantID] == nil {
		w.permDeletes[tenantID] = map[string]bool{}
	}
	w.permDeletes[tenantID][key] = true
}

// DeleteSitePermission removes one grant from the site's permission list (the
// same overlay SetSiteAccess writes, so the SharePoint page reflects it too).
func (s sampleProvider) DeleteSitePermission(_ context.Context, tenantID, siteID, permissionID string) error {
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	perms, ok := s.writes.sitePerms[tenantID][siteID]
	if !ok {
		perms = append([]model.SitePermission(nil), sampleSitePerms[siteID]...)
	}
	next := perms[:0]
	found := false
	for _, p := range perms {
		if p.ID == permissionID {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		return fmt.Errorf("sample: unknown site permission %s on %s", permissionID, siteID)
	}
	if s.writes.sitePerms[tenantID] == nil {
		s.writes.sitePerms[tenantID] = map[string][]model.SitePermission{}
	}
	s.writes.sitePerms[tenantID][siteID] = next
	return nil
}

func (s sampleProvider) DeleteItemPermission(_ context.Context, tenantID, siteID, driveID, itemID, permissionID string) error {
	for _, item := range sampleSharedItems[siteID] {
		if item.DriveID != driveID || item.ItemID != itemID {
			continue
		}
		for _, p := range item.Permissions {
			if p.ID == permissionID {
				s.writes.mu.Lock()
				s.writes.markDeleted(tenantID, driveID+"|"+itemID+"|"+permissionID)
				s.writes.mu.Unlock()
				return nil
			}
		}
	}
	return fmt.Errorf("sample: unknown item permission %s on %s/%s", permissionID, siteID, itemID)
}
