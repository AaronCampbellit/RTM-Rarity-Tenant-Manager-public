package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// SharePointInventoryProvider is the richer inventory surface implemented by
// RTM's built-in Microsoft providers. It is optional so report/test providers
// that only need the core Graph contract remain small.
type SharePointInventoryProvider interface {
	SharePointInventory(ctx context.Context, tenantID string, request SharePointInventoryRequest) ([]model.SharePointInventoryNode, []string, error)
}

type inventorySiteRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	WebURL      string `json:"webUrl"`
}

type inventoryDriveRow struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	WebURL string `json:"webUrl"`
}

type inventoryItemRow struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	WebURL          string           `json:"webUrl"`
	Size            int64            `json:"size"`
	Folder          *json.RawMessage `json:"folder"`
	File            *json.RawMessage `json:"file"`
	Shared          *json.RawMessage `json:"shared"`
	ParentReference struct {
		Path string `json:"path"`
	} `json:"parentReference"`
}

type graphPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

func graphNextPath(next string) string {
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	if u.RawQuery == "" {
		return u.Path
	}
	return u.Path + "?" + u.RawQuery
}

func graphPages[T any](ctx context.Context, c *graphClient, tenantID, path string) ([]T, error) {
	var out []T
	for path != "" {
		var page graphPage[T]
		if err := c.sharePointGraphGet(ctx, tenantID, path, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		path = graphNextPath(page.NextLink)
	}
	return out, nil
}

// SharePointInventory discovers every site/library/folder and enumerates file
// metadata to compute exact aggregate sizes. Baseline snapshots do not persist
// file rows. Graph identifies modern direct sharing; the warning keeps classic
// SharePoint role-assignment coverage honest until the certificate REST client
// is available for the tenant.
func (c *graphClient) SharePointInventory(ctx context.Context, tenantID string, request SharePointInventoryRequest) ([]model.SharePointInventoryNode, []string, error) {
	includePersonal := request.Scope == "onedrive"
	sitePath := "/sites/getAllSites?$select=id,name,displayName,webUrl&$top=200"
	if includePersonal {
		sitePath += "&includePersonalSite=true"
	}
	sites, err := graphPages[inventorySiteRow](ctx, c, tenantID, sitePath)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	nodes := []model.SharePointInventoryNode{}
	for _, site := range sites {
		personal := strings.Contains(strings.ToLower(site.WebURL), "-my.sharepoint.com/personal/")
		if personal != includePersonal && request.Scope != "file_permissions" {
			continue
		}
		if request.SiteID != "" && site.ID != request.SiteID {
			continue
		}
		name := site.DisplayName
		if name == "" {
			name = site.Name
		}
		siteNode := model.SharePointInventoryNode{
			ID: site.ID, TenantID: tenantID, SiteID: site.ID, Kind: "site",
			Name: name, Path: "/", WebURL: site.WebURL, LastScannedAt: now,
		}
		if personal {
			siteNode.ExternalSharing = "OneDrive"
		}
		drives, err := graphPages[inventoryDriveRow](ctx, c, tenantID,
			"/sites/"+url.PathEscape(site.ID)+"/drives?$select=id,name,webUrl&$top=200")
		if err != nil {
			return nil, nil, err
		}
		siteNodes := []model.SharePointInventoryNode{}
		for _, drive := range drives {
			libraryID := "spnode:" + drive.ID
			library := model.SharePointInventoryNode{
				ID: libraryID, TenantID: tenantID, ParentID: site.ID, SiteID: site.ID,
				DriveID: drive.ID, Kind: "library", Name: drive.Name, Path: "/" + drive.Name,
				WebURL: drive.WebURL, LastScannedAt: now,
			}
			children, totalSize, totalFiles, err := c.walkInventoryFolder(ctx, tenantID, site.ID, drive, "root", libraryID, library.Path, now, true)
			if err != nil {
				return nil, nil, err
			}
			library.SizeBytes = totalSize
			library.FileCount = totalFiles
			siteNodes = append(siteNodes, children...)
			siteNode.SizeBytes += library.SizeBytes
			siteNode.FileCount += library.FileCount
			siteNodes = append([]model.SharePointInventoryNode{library}, siteNodes...)
		}
		nodes = append(nodes, siteNode)
		nodes = append(nodes, siteNodes...)
	}

	warnings := []string{}
	if c.sharePointConfigured() {
		siteURLs := map[string]string{}
		for _, node := range nodes {
			if node.Kind == "site" {
				siteURLs[node.SiteID] = node.WebURL
			}
		}
		for i := range nodes {
			if nodes[i].Kind != "folder" {
				continue
			}
			unique, err := c.sharePointFolderHasUnique(ctx, tenantID, siteURLs[nodes[i].SiteID], nodes[i].WebURL)
			if err != nil {
				warnings = append(warnings, "Could not verify unique permissions for "+nodes[i].Path+": "+err.Error())
				continue
			}
			nodes[i].HasUniquePermissions = unique
		}
	} else {
		warnings = append(warnings, "Classic SharePoint role-assignment coverage requires the certificate-backed SharePoint REST connection.")
	}

	if request.Scope == "file_permissions" {
		nodes = filterOnDemandNodes(nodes, request.NodeID)
	} else {
		filtered := nodes[:0]
		for _, node := range nodes {
			if node.Kind != "file" {
				filtered = append(filtered, node)
			}
		}
		nodes = filtered
	}
	return nodes, warnings, nil
}

func (c *graphClient) walkInventoryFolder(ctx context.Context, tenantID, siteID string, drive inventoryDriveRow, itemID, parentID, parentPath, now string, root bool) ([]model.SharePointInventoryNode, int64, int, error) {
	path := "/drives/" + url.PathEscape(drive.ID) + "/root/children?$select=id,name,webUrl,size,folder,file,shared,parentReference&$top=200"
	if !root {
		path = "/drives/" + url.PathEscape(drive.ID) + "/items/" + url.PathEscape(itemID) +
			"/children?$select=id,name,webUrl,size,folder,file,shared,parentReference&$top=200"
	}
	items, err := graphPages[inventoryItemRow](ctx, c, tenantID, path)
	if err != nil {
		return nil, 0, 0, err
	}
	out := []model.SharePointInventoryNode{}
	var totalSize int64
	totalFiles := 0
	for _, item := range items {
		itemPath := strings.TrimSuffix(parentPath, "/") + "/" + item.Name
		if item.Folder == nil {
			out = append(out, model.SharePointInventoryNode{
				ID: "spnode:" + drive.ID + ":" + item.ID, TenantID: tenantID, ParentID: parentID,
				SiteID: siteID, DriveID: drive.ID, ItemID: item.ID, Kind: "file",
				Name: item.Name, Path: itemPath, WebURL: item.WebURL, SizeBytes: item.Size,
				FileCount: 1, LastScannedAt: now,
			})
			totalSize += item.Size
			totalFiles++
			continue
		}
		nodeID := "spnode:" + drive.ID + ":" + item.ID
		children, childSize, childFiles, err := c.walkInventoryFolder(ctx, tenantID, siteID, drive, item.ID, nodeID, itemPath, now, false)
		if err != nil {
			return nil, 0, 0, err
		}
		folder := model.SharePointInventoryNode{
			ID: nodeID, TenantID: tenantID, ParentID: parentID, SiteID: siteID,
			DriveID: drive.ID, ItemID: item.ID, Kind: "folder", Name: item.Name,
			Path: itemPath, WebURL: item.WebURL, SizeBytes: childSize,
			FileCount: childFiles, LastScannedAt: now,
		}
		if item.Shared != nil {
			if permissions, err := c.itemPermissions(ctx, tenantID, drive.ID, item.ID); err == nil {
				for _, permission := range permissions {
					if !permission.Inherited {
						folder.HasUniquePermissions = true
						break
					}
				}
			}
		}
		out = append(out, folder)
		out = append(out, children...)
		totalSize += childSize
		totalFiles += childFiles
	}
	return out, totalSize, totalFiles, nil
}

func filterOnDemandNodes(nodes []model.SharePointInventoryNode, nodeID string) []model.SharePointInventoryNode {
	if nodeID == "" {
		return nodes
	}
	targetPath := ""
	for _, node := range nodes {
		if node.ID == nodeID || node.ItemID == nodeID {
			targetPath = strings.TrimSuffix(node.Path, "/")
			break
		}
	}
	if targetPath == "" {
		return []model.SharePointInventoryNode{}
	}
	out := []model.SharePointInventoryNode{}
	for _, node := range nodes {
		if node.Path == targetPath || strings.HasPrefix(node.Path, targetPath+"/") {
			out = append(out, node)
		}
	}
	return out
}

type SharePointInventoryRequest struct {
	Scope                  string
	SiteID                 string
	NodeID                 string
	IncludeFilePermissions bool
}

// SharePointPermissionManager is the full-scope management surface used by the
// SharePoint workspace. Implementations must snapshot the previous role
// assignments before mutating them.
type SharePointPermissionManager interface {
	SharePointScopePermissions(ctx context.Context, tenantID string, target model.SharePointPermissionTarget) ([]model.SharePointScopePermission, error)
	SetSharePointScopePermission(ctx context.Context, tenantID string, change model.SharePointPermissionChange) error
}

// SharePointInventory supplies a complete, navigable sample hierarchy. Files
// are intentionally omitted from baseline scans and returned only for the
// explicit file-permission scope.
func (s sampleProvider) SharePointInventory(_ context.Context, tenantID string, request SharePointInventoryRequest) ([]model.SharePointInventoryNode, []string, error) {
	scope := request.Scope
	if scope != "sites" && scope != "onedrive" && scope != "file_permissions" {
		return nil, nil, fmt.Errorf("unsupported SharePoint inventory scope %q", scope)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if scope == "onedrive" {
		return []model.SharePointInventoryNode{
			{
				ID: "od_usr_3", TenantID: tenantID, SiteID: "od_usr_3", Kind: "site",
				Name: "Caleb Stone", Path: "/", WebURL: "https://contoso-my.sharepoint.com/personal/caleb_contoso_com",
				SizeBytes: 734003200, FileCount: 128, ExternalSharing: "OneDrive", LastScannedAt: now,
			},
			{
				ID: "od_docs_usr_3", TenantID: tenantID, ParentID: "od_usr_3", SiteID: "od_usr_3",
				DriveID: "od_drive_usr_3", Kind: "library", Name: "Files", Path: "/Files",
				SizeBytes: 734003200, FileCount: 128, LastScannedAt: now,
			},
			{
				ID: "od_shared_usr_3", TenantID: tenantID, ParentID: "od_docs_usr_3", SiteID: "od_usr_3",
				DriveID: "od_drive_usr_3", ItemID: "od_folder_shared", Kind: "folder", Name: "Shared externally",
				Path: "/Files/Shared externally", SizeBytes: 52428800, FileCount: 9,
				HasUniquePermissions: true, LastScannedAt: now,
			},
		}, nil, nil
	}

	nodes := make([]model.SharePointInventoryNode, 0, len(sampleSites)*3)
	for i, site := range sampleSites {
		if request.SiteID != "" && site.ID != request.SiteID {
			continue
		}
		size := int64((i + 1) * 512 * 1024 * 1024)
		files := (i + 1) * 240
		siteNode := model.SharePointInventoryNode{
			ID: site.ID, TenantID: tenantID, SiteID: site.ID, Kind: "site",
			Name: site.Name, Path: "/", WebURL: site.URL, SizeBytes: size,
			FileCount: files, ExternalSharing: site.ExternalSharing, LastScannedAt: now,
		}
		libraryID := site.ID + "_documents"
		library := model.SharePointInventoryNode{
			ID: libraryID, TenantID: tenantID, ParentID: site.ID, SiteID: site.ID,
			DriveID: "drive_" + site.ID, Kind: "library", Name: "Documents",
			Path: "/Documents", WebURL: site.URL + "/Shared Documents", SizeBytes: size,
			FileCount: files, LastScannedAt: now,
		}
		folder := model.SharePointInventoryNode{
			ID: site.ID + "_restricted", TenantID: tenantID, ParentID: libraryID,
			SiteID: site.ID, DriveID: "drive_" + site.ID, ItemID: "item_" + site.ID + "_restricted",
			Kind: "folder", Name: "Restricted", Path: "/Documents/Restricted",
			WebURL: site.URL + "/Shared Documents/Restricted", SizeBytes: size / 4,
			FileCount: files / 4, HasUniquePermissions: i%2 == 0, LastScannedAt: now,
		}
		nodes = append(nodes, siteNode, library, folder)
		if request.IncludeFilePermissions || scope == "file_permissions" {
			nodes = append(nodes, model.SharePointInventoryNode{
				ID: site.ID + "_budget.xlsx", TenantID: tenantID, ParentID: folder.ID,
				SiteID: site.ID, DriveID: library.DriveID, ItemID: "file_" + site.ID + "_budget",
				Kind: "file", Name: "Budget.xlsx", Path: folder.Path + "/Budget.xlsx",
				WebURL: folder.WebURL + "/Budget.xlsx", SizeBytes: 262144, FileCount: 1,
				HasUniquePermissions: i%2 == 0, LastScannedAt: now,
			})
		}
	}
	return nodes, nil, nil
}

func (s sampleProvider) SharePointScopePermissions(_ context.Context, tenantID string, target model.SharePointPermissionTarget) ([]model.SharePointScopePermission, error) {
	perms, err := s.SitePermissions(context.Background(), tenantID, target.SiteID)
	if err != nil {
		return nil, err
	}
	out := make([]model.SharePointScopePermission, 0, len(perms))
	for _, permission := range perms {
		typ := permission.Type
		switch typ {
		case "Group":
			typ = "Security Group"
		case "External":
			typ = "Guest"
		}
		row := model.SharePointScopePermission{
			ID: permission.ID, PrincipalID: permission.PrincipalUPN,
			Principal: permission.Principal, PrincipalUPN: permission.PrincipalUPN,
			Type: typ, Role: permission.Role, Source: "Direct",
			Expandable: permission.Type == "Group",
		}
		if target.Kind != "site" && permission.Source != "Direct" {
			source := model.SharePointPermissionTarget{SiteID: target.SiteID, Kind: "site", Path: "/"}
			row.Inherited = true
			row.Source = "Inherited from site"
			row.SourceTarget = &source
		}
		out = append(out, row)
	}
	return out, nil
}

func (s sampleProvider) SetSharePointScopePermission(_ context.Context, tenantID string, change model.SharePointPermissionChange) error {
	if change.Operation == "restore_inheritance" {
		return nil
	}
	if change.Target.SiteID == "" || change.PrincipalID == "" {
		return fmt.Errorf("sample: site and principal are required")
	}
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	perms, ok := s.writes.sitePerms[tenantID][change.Target.SiteID]
	if !ok {
		perms = append([]model.SitePermission(nil), sampleSitePerms[change.Target.SiteID]...)
	}
	next := make([]model.SitePermission, 0, len(perms)+1)
	for _, permission := range perms {
		if permission.PrincipalUPN == change.PrincipalID || (change.PrincipalUPN != "" && permission.PrincipalUPN == change.PrincipalUPN) {
			continue
		}
		next = append(next, permission)
	}
	if change.Operation == "grant" {
		name, upn := sampleUserName(change.PrincipalID)
		if change.PrincipalUPN != "" {
			upn = change.PrincipalUPN
		}
		if name == "" {
			name = change.PrincipalID
		}
		next = append(next, model.SitePermission{
			ID: fmt.Sprintf("sp_%d", time.Now().UnixNano()&0xffffff), Principal: name,
			PrincipalUPN: upn, Type: "User", Role: change.Role, Source: "Direct",
		})
	}
	if s.writes.sitePerms[tenantID] == nil {
		s.writes.sitePerms[tenantID] = map[string][]model.SitePermission{}
	}
	s.writes.sitePerms[tenantID][change.Target.SiteID] = next
	return nil
}
