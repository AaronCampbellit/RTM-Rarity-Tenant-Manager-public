package graph

import (
	"context"
	"testing"

	"github.com/rarity/rtm/internal/model"
)

func TestSampleSharePointInventorySeparatesSitesAndOneDrive(t *testing.T) {
	p := newSampleProvider()
	inventory, ok := any(p).(SharePointInventoryProvider)
	if !ok {
		t.Fatal("sample provider does not implement SharePointInventoryProvider")
	}

	sites, warnings, err := inventory.SharePointInventory(context.Background(), "ten_1", SharePointInventoryRequest{Scope: "sites"})
	if err != nil || len(warnings) != 0 {
		t.Fatalf("sites inventory warnings=%v err=%v", warnings, err)
	}
	if len(sites) == 0 {
		t.Fatal("sites inventory is empty")
	}
	var hasSite, hasLibrary, hasUniqueFolder, hasFile bool
	for _, node := range sites {
		switch node.Kind {
		case "site":
			hasSite = true
		case "library":
			hasLibrary = true
		case "folder":
			hasUniqueFolder = hasUniqueFolder || node.HasUniquePermissions
		case "file":
			hasFile = true
		}
	}
	if !hasSite || !hasLibrary || !hasUniqueFolder {
		t.Fatalf("sites inventory missing required hierarchy: %+v", sites)
	}
	if hasFile {
		t.Fatal("baseline inventory included file rows")
	}

	oneDrive, _, err := inventory.SharePointInventory(context.Background(), "ten_1", SharePointInventoryRequest{Scope: "onedrive"})
	if err != nil || len(oneDrive) == 0 {
		t.Fatalf("onedrive inventory = %d nodes, %v", len(oneDrive), err)
	}
	for _, node := range oneDrive {
		if node.Kind == "site" && node.ExternalSharing != "OneDrive" {
			t.Fatalf("onedrive site marker = %q", node.ExternalSharing)
		}
	}
}

func TestGraphSharePointInventoryAggregatesFolderSizesWithoutPersistingFiles(t *testing.T) {
	f := newFakeGraph(t)
	f.responses["/sites/getAllSites"] = `{"value":[
		{"id":"s1","name":"ops","displayName":"Operations","webUrl":"https://contoso.sharepoint.com/sites/ops"}
	]}`
	f.responses["/sites/s1/drives"] = `{"value":[
		{"id":"d1","name":"Documents","webUrl":"https://contoso.sharepoint.com/sites/ops/Shared Documents"}
	]}`
	f.responses["/drives/d1/root/children"] = `{"value":[
		{"id":"f1","name":"Restricted","webUrl":"https://contoso.sharepoint.com/sites/ops/Shared Documents/Restricted","size":0,
		 "folder":{"childCount":1},"shared":{},"parentReference":{"path":"/drives/d1/root:"}},
		{"id":"doc1","name":"Readme.txt","webUrl":"https://contoso.sharepoint.com/sites/ops/Shared Documents/Readme.txt","size":10,
		 "file":{},"parentReference":{"path":"/drives/d1/root:"}}
	]}`
	f.responses["/drives/d1/items/f1/children"] = `{"value":[
		{"id":"doc2","name":"Budget.xlsx","webUrl":"https://contoso.sharepoint.com/sites/ops/Shared Documents/Restricted/Budget.xlsx","size":20,
		 "file":{},"parentReference":{"path":"/drives/d1/root:/Restricted"}}
	]}`
	f.responses["/drives/d1/items/f1/permissions"] = `{"value":[
		{"id":"p1","roles":["read"],"grantedToV2":{"user":{"id":"u1","displayName":"Ada","email":"ada@contoso.com"}}}
	]}`
	c := newTestClient(f, nil)

	nodes, warnings, err := c.SharePointInventory(context.Background(), "", SharePointInventoryRequest{Scope: "sites"})
	if err != nil {
		t.Fatalf("SharePointInventory: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatal("inventory did not report missing SharePoint REST coverage")
	}
	var site, library, folder *model.SharePointInventoryNode
	for i := range nodes {
		switch nodes[i].Kind {
		case "site":
			site = &nodes[i]
		case "library":
			library = &nodes[i]
		case "folder":
			folder = &nodes[i]
		case "file":
			t.Fatalf("baseline inventory returned a file row: %+v", nodes[i])
		}
	}
	if site == nil || library == nil || folder == nil {
		t.Fatalf("hierarchy = %+v", nodes)
	}
	if site.SizeBytes != 30 || site.FileCount != 2 || library.SizeBytes != 30 || library.FileCount != 2 {
		t.Fatalf("aggregate totals site=%+v library=%+v", site, library)
	}
	if folder.SizeBytes != 20 || folder.FileCount != 1 || !folder.HasUniquePermissions {
		t.Fatalf("folder = %+v", folder)
	}
}

func TestSampleFilePermissionScanIncludesOnlyRequestedTree(t *testing.T) {
	p := newSampleProvider()
	inventory := any(p).(SharePointInventoryProvider)

	nodes, _, err := inventory.SharePointInventory(context.Background(), "ten_1", SharePointInventoryRequest{
		Scope: "file_permissions", SiteID: "site_1", NodeID: "site_1_restricted",
		IncludeFilePermissions: true,
	})
	if err != nil {
		t.Fatalf("file inventory: %v", err)
	}
	files := 0
	for _, node := range nodes {
		if node.SiteID != "site_1" {
			t.Fatalf("on-demand scan returned another site: %+v", node)
		}
		if node.Kind == "file" {
			files++
		}
	}
	if files == 0 {
		t.Fatal("on-demand inventory did not include file rows")
	}
}
