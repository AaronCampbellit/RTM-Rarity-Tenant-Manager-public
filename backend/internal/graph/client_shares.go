package graph

import (
	"context"
	"net/http"
	"net/url"

	"github.com/rarity/rtm/internal/model"
)

// Live implementations of the Share Detective reads/writes.

// Traversal bounds for SharedItems. Share Detective reports coverage, so a
// truncated walk is a visible "partial" — never a silent miss. The caps keep
// one site's scan to a few hundred Graph calls at most.
const (
	sharedItemsMaxPerSite = 400 // drive items inspected per site
	sharedItemsMaxDepth   = 4   // folder depth below each drive root
)

// UserGroupIDs lists the subject's transitive group memberships
// (GroupMember.Read.All / Directory.Read.All), used to classify group-based
// access.
func (c *graphClient) UserGroupIDs(ctx context.Context, tenantID, userID string) ([]string, error) {
	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/users/"+url.PathEscape(userID)+"/transitiveMemberOf?$select=id&$top=200", &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Value))
	for _, g := range out.Value {
		ids = append(ids, g.ID)
	}
	return ids, nil
}

// driveItemRow is the subset of Graph's driveItem the scanner needs. The
// `shared` facet is present only on items that carry their own sharing state —
// that's the signal to read permissions.
type driveItemRow struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	WebURL string `json:"webUrl"`
	Folder *struct {
		ChildCount int `json:"childCount"`
	} `json:"folder"`
	Shared          *struct{} `json:"shared"`
	ParentReference struct {
		Path string `json:"path"`
	} `json:"parentReference"`
}

// SharedItems walks a site's document libraries breadth-first (bounded by the
// caps above) and returns every item with its own sharing state plus that
// item's permission entries (Sites.Read.All; Files.Read.All is implied).
func (c *graphClient) SharedItems(ctx context.Context, tenantID, siteID string) ([]model.SharedItem, error) {
	var drives struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/sites/"+url.PathEscape(siteID)+"/drives?$select=id", &drives); err != nil {
		return nil, err
	}

	items := []model.SharedItem{}
	inspected := 0
	for _, drive := range drives.Value {
		type folderRef struct {
			itemID string
			depth  int
		}
		queue := []folderRef{{itemID: "root", depth: 0}}
		for len(queue) > 0 && inspected < sharedItemsMaxPerSite {
			f := queue[0]
			queue = queue[1:]
			path := "/drives/" + url.PathEscape(drive.ID) + "/items/" + url.PathEscape(f.itemID) + "/children" +
				"?$select=id,name,webUrl,folder,shared,parentReference&$top=200"
			if f.itemID == "root" {
				path = "/drives/" + url.PathEscape(drive.ID) + "/root/children?$select=id,name,webUrl,folder,shared,parentReference&$top=200"
			}
			var children struct {
				Value []driveItemRow `json:"value"`
			}
			if err := c.get(ctx, tenantID, path, &children); err != nil {
				return nil, err
			}
			for _, child := range children.Value {
				if inspected >= sharedItemsMaxPerSite {
					break
				}
				inspected++
				if child.Folder != nil && f.depth+1 < sharedItemsMaxDepth {
					queue = append(queue, folderRef{itemID: child.ID, depth: f.depth + 1})
				}
				if child.Shared == nil {
					continue
				}
				perms, err := c.itemPermissions(ctx, tenantID, drive.ID, child.ID)
				if err != nil {
					return nil, err
				}
				typ := "file"
				if child.Folder != nil {
					typ = "folder"
				}
				items = append(items, model.SharedItem{
					ItemID: child.ID, DriveID: drive.ID, Name: child.Name,
					Path: itemPath(child), WebURL: child.WebURL, Type: typ, Permissions: perms,
				})
			}
		}
	}
	return items, nil
}

// itemPath renders a human-readable path from the parent reference ("…/root:"
// prefix trimmed).
func itemPath(item driveItemRow) string {
	p := item.ParentReference.Path
	if idx := indexAfterRoot(p); idx >= 0 {
		p = p[idx:]
	}
	if p == "" {
		return "/" + item.Name
	}
	return p + "/" + item.Name
}

func indexAfterRoot(p string) int {
	const marker = "/root:"
	for i := 0; i+len(marker) <= len(p); i++ {
		if p[i:i+len(marker)] == marker {
			return i + len(marker)
		}
	}
	return -1
}

// itemPermissions reads one drive item's permission entries and normalizes
// them: direct user/group grants, links (broad or specific-people — the
// latter emits one entry per grantee so subject matching stays uniform), and
// whether the entry is inherited from a parent.
func (c *graphClient) itemPermissions(ctx context.Context, tenantID, driveID, itemID string) ([]model.ItemPermission, error) {
	var out struct {
		Value []struct {
			ID            string   `json:"id"`
			Roles         []string `json:"roles"`
			InheritedFrom *struct {
				ID string `json:"id"`
			} `json:"inheritedFrom"`
			Link *struct {
				Scope string `json:"scope"` // anonymous | organization | users
			} `json:"link"`
			GrantedToV2         *permGrantee  `json:"grantedToV2"`
			GrantedToIdentities []permGrantee `json:"grantedToIdentitiesV2"`
		} `json:"value"`
	}
	if err := c.get(ctx, tenantID, "/drives/"+url.PathEscape(driveID)+"/items/"+url.PathEscape(itemID)+"/permissions", &out); err != nil {
		return nil, err
	}
	perms := []model.ItemPermission{}
	for _, p := range out.Value {
		roles := p.Roles
		if roles == nil {
			roles = []string{}
		}
		inherited := p.InheritedFrom != nil
		base := model.ItemPermission{ID: p.ID, Roles: roles, Inherited: inherited}
		switch {
		case p.Link != nil:
			base.GranteeType, base.LinkScope = "link", p.Link.Scope
			if len(p.GrantedToIdentities) == 0 {
				perms = append(perms, base)
				continue
			}
			for _, g := range p.GrantedToIdentities {
				entry := base
				g.fill(&entry)
				entry.GranteeType, entry.LinkScope = "link", p.Link.Scope
				perms = append(perms, entry)
			}
		case p.GrantedToV2 != nil:
			entry := base
			p.GrantedToV2.fill(&entry)
			perms = append(perms, entry)
		case len(p.GrantedToIdentities) > 0:
			for _, g := range p.GrantedToIdentities {
				entry := base
				g.fill(&entry)
				perms = append(perms, entry)
			}
		default:
			base.GranteeType = "app"
			perms = append(perms, base)
		}
	}
	return perms, nil
}

// permGrantee is Graph's sharePointIdentitySet — one of the facets is set.
type permGrantee struct {
	User *struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
	} `json:"user"`
	Group *struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	} `json:"group"`
	Application *struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	} `json:"application"`
}

func (g permGrantee) fill(p *model.ItemPermission) {
	switch {
	case g.User != nil:
		p.GranteeType = "user"
		p.GranteeID, p.GranteeName, p.GranteeUPN = g.User.ID, g.User.DisplayName, g.User.Email
	case g.Group != nil:
		p.GranteeType = "group"
		p.GranteeID, p.GranteeName = g.Group.ID, g.Group.DisplayName
	case g.Application != nil:
		p.GranteeType = "app"
		p.GranteeID, p.GranteeName = g.Application.ID, g.Application.DisplayName
	default:
		p.GranteeType = "app"
	}
}

// DeleteSitePermission removes one site-level permission entry
// (Sites.FullControl.All).
func (c *graphClient) DeleteSitePermission(ctx context.Context, tenantID, siteID, permissionID string) error {
	return c.send(ctx, http.MethodDelete, tenantID,
		"/sites/"+url.PathEscape(siteID)+"/permissions/"+url.PathEscape(permissionID), nil)
}

// DeleteItemPermission removes one drive-item permission entry
// (Sites.FullControl.All). Only non-inherited entries are addressable this way
// — the revoke planner never selects inherited ones.
func (c *graphClient) DeleteItemPermission(ctx context.Context, tenantID, _ /*siteID*/, driveID, itemID, permissionID string) error {
	return c.send(ctx, http.MethodDelete, tenantID,
		"/drives/"+url.PathEscape(driveID)+"/items/"+url.PathEscape(itemID)+"/permissions/"+url.PathEscape(permissionID), nil)
}
