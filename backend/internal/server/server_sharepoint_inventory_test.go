package server_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func TestSharePointInventoryScanPersistsSnapshotAndHistory(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	var scan model.SharePointScan
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/scans", admin,
		`{"scope":"sites"}`, &scan)
	if rec.Code != http.StatusAccepted || scan.ID == "" || scan.Scope != "sites" {
		t.Fatalf("start scan = %d %+v", rec.Code, scan)
	}

	var inventory model.SharePointInventory
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/sharepoint/inventory?scope=sites", admin, "", &inventory)
		if rec.Code == http.StatusOK && inventory.Scan.Status != "running" && inventory.Scan.Status != "queued" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("inventory did not complete: %d %+v", rec.Code, inventory)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if inventory.Scan.Coverage != "complete" || inventory.Scan.SiteCount == 0 || len(inventory.Nodes) == 0 {
		t.Fatalf("inventory = %+v", inventory)
	}
	for _, node := range inventory.Nodes {
		if node.Kind == "file" {
			t.Fatalf("baseline scan persisted file row: %+v", node)
		}
	}

	var history []model.SharePointScan
	rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/sharepoint/scans", admin, "", &history)
	if rec.Code != http.StatusOK || len(history) != 1 || history[0].ID != scan.ID {
		t.Fatalf("history = %d %+v", rec.Code, history)
	}
}

func TestSharePointScanRequiresAdminAndValidScope(t *testing.T) {
	h, _ := newTestAPI(t)
	tech := login(t, h, techEmail, "RtmDemo!2026").AccessToken

	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/scans", tech,
		`{"scope":"sites"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("technician scan status = %d", rec.Code)
	}

	admin := adminToken(t, h)
	rec = call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/scans", admin,
		`{"scope":"everything"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid scope status = %d", rec.Code)
	}
}

func TestSharePointOnDemandFileScanIncludesFiles(t *testing.T) {
	h, _ := newTestAPI(t)
	admin := adminToken(t, h)

	var scan model.SharePointScan
	rec := call(t, h, http.MethodPost, "/api/v1/tenants/ten_1/sharepoint/scans", admin,
		`{"scope":"file_permissions","siteId":"site_1","nodeId":"site_1_restricted"}`, &scan)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start file scan = %d %s", rec.Code, rec.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		var inventory model.SharePointInventory
		rec = call(t, h, http.MethodGet, "/api/v1/tenants/ten_1/sharepoint/inventory?scope=file_permissions", admin, "", &inventory)
		if rec.Code == http.StatusOK && inventory.Scan.Status == "completed" {
			files := 0
			for _, node := range inventory.Nodes {
				if node.Kind == "file" {
					files++
				}
			}
			if files == 0 {
				t.Fatal("completed on-demand scan had no files")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("file scan did not complete: %d", rec.Code)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
