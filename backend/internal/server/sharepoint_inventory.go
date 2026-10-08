package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

const sharePointScanTimeout = 30 * time.Minute
const sharePointScanFreshness = 24 * time.Hour

// StartSharePointScheduler runs due site and OneDrive inventories at startup
// and then hourly. The persisted history is the lease: a recent or running
// scan prevents duplicate work in the normal single-API deployment.
func (s *Server) StartSharePointScheduler(ctx context.Context) {
	go func() {
		s.runDueSharePointScans(ctx, time.Now().UTC())
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				s.runDueSharePointScans(ctx, now.UTC())
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) runDueSharePointScans(ctx context.Context, now time.Time) {
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		s.log.Error("sharepoint scheduler: tenants", "error", err)
		return
	}
	for _, tenant := range tenants {
		scans, err := s.store.SharePointScans(ctx, tenant.ID)
		if err != nil {
			s.log.Error("sharepoint scheduler: history", "tenant", tenant.ID, "error", err)
			continue
		}
		for _, scope := range []string{"sites", "onedrive"} {
			if !sharePointScopeDue(scans, scope, now) {
				continue
			}
			scan, err := s.store.CreateSharePointScan(ctx, model.SharePointScan{
				TenantID: tenant.ID, Scope: scope, Status: "queued", Trigger: "nightly",
				StartedBy: "System", StartedAt: now.Format(time.RFC3339), Coverage: "pending",
			})
			if err != nil {
				s.log.Error("sharepoint scheduler: create", "tenant", tenant.ID, "scope", scope, "error", err)
				continue
			}
			go s.runSharePointInventoryScan(scan)
		}
	}
}

func sharePointScopeDue(scans []model.SharePointScan, scope string, now time.Time) bool {
	for _, scan := range scans {
		if scan.Scope != scope {
			continue
		}
		if scan.Status == "queued" || scan.Status == "running" {
			return false
		}
		started, err := time.Parse(time.RFC3339, scan.StartedAt)
		if err == nil && now.Sub(started) < sharePointScanFreshness {
			return false
		}
		// History is newest first; the newest matching stale row is enough.
		return true
	}
	return true
}

func (s *Server) getSharePointInventory(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "sites"
	}
	if !validSharePointScope(scope) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Scope must be sites, onedrive, or file_permissions.")
		return
	}
	inventory, err := s.store.SharePointInventory(r.Context(), tenantID, scope)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, inventory)
}

func (s *Server) listSharePointScans(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	scans, err := s.store.SharePointScans(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if scans == nil {
		scans = []model.SharePointScan{}
	}
	httpx.WriteJSON(w, http.StatusOK, scans)
}

func (s *Server) startSharePointScan(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	tenant, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var body struct {
		Scope  string `json:"scope"`
		SiteID string `json:"siteId"`
		NodeID string `json:"nodeId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	body.Scope = strings.ToLower(strings.TrimSpace(body.Scope))
	if !validSharePointScope(body.Scope) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Scope must be sites, onedrive, or file_permissions.")
		return
	}
	if body.Scope == "file_permissions" && (strings.TrimSpace(body.SiteID) == "" || strings.TrimSpace(body.NodeID) == "") {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"File-permission scans require a siteId and nodeId.")
		return
	}
	principal := auth.UserFromContext(r.Context())
	scan, err := s.store.CreateSharePointScan(r.Context(), model.SharePointScan{
		TenantID: tenantID, Scope: body.Scope, SiteID: strings.TrimSpace(body.SiteID),
		NodeID: strings.TrimSpace(body.NodeID), Status: "queued", Trigger: scanTrigger(body.Scope),
		StartedBy: principal.Name, Coverage: "pending",
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: principal.Name, Action: "sharepoint.scan_start",
		Resource: tenant.Name + " — " + body.Scope, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	go s.runSharePointInventoryScan(scan)
	httpx.WriteJSON(w, http.StatusAccepted, scan)
}

func scanTrigger(scope string) string {
	if scope == "file_permissions" {
		return "on_demand"
	}
	return "manual"
}

func validSharePointScope(scope string) bool {
	return scope == "sites" || scope == "onedrive" || scope == "file_permissions"
}

func (s *Server) runSharePointInventoryScan(scan model.SharePointScan) {
	ctx, cancel := context.WithTimeout(context.Background(), sharePointScanTimeout)
	defer cancel()

	provider, ok := s.graph.(graph.SharePointInventoryProvider)
	if !ok {
		s.finishSharePointScan(scan, nil, nil, graph.ErrLiveNotImplemented)
		return
	}
	nodes, warnings, err := provider.SharePointInventory(ctx, scan.TenantID, graph.SharePointInventoryRequest{
		Scope: scan.Scope, SiteID: scan.SiteID, NodeID: scan.NodeID,
		IncludeFilePermissions: scan.Scope == "file_permissions",
	})
	s.finishSharePointScan(scan, nodes, warnings, err)
}

func (s *Server) finishSharePointScan(scan model.SharePointScan, nodes []model.SharePointInventoryNode, warnings []string, scanErr error) {
	now := time.Now().UTC().Format(time.RFC3339)
	scan.CompletedAt = now
	scan.Warnings = append([]string(nil), warnings...)
	scan.Status, scan.Coverage = "completed", "complete"
	if len(warnings) > 0 {
		scan.Status, scan.Coverage = "partial", "partial"
	}
	if scanErr != nil {
		scan.Status, scan.Coverage, scan.Error = "failed", "failed", scanErr.Error()
		nodes = nil
	}
	for i := range nodes {
		nodes[i].TenantID = scan.TenantID
		nodes[i].ScanID = scan.ID
		if nodes[i].LastScannedAt == "" {
			nodes[i].LastScannedAt = now
		}
		switch nodes[i].Kind {
		case "site":
			scan.SiteCount++
			if scan.Scope != "file_permissions" {
				scan.TotalBytes += nodes[i].SizeBytes
			}
		case "library":
			scan.LibraryCount++
		case "folder":
			scan.FolderCount++
		case "file":
			if scan.Scope == "file_permissions" {
				scan.TotalBytes += nodes[i].SizeBytes
			}
		}
		if nodes[i].HasUniquePermissions {
			scan.UniquePermissionCount++
		}
	}
	// FileCount is an aggregate, not the number of persisted file rows in a
	// baseline scan. Site totals avoid double-counting nested folders.
	if scan.Scope == "file_permissions" {
		for _, node := range nodes {
			if node.Kind == "file" {
				scan.FileCount++
			}
		}
	} else {
		for _, node := range nodes {
			if node.Kind == "site" {
				scan.FileCount += node.FileCount
			}
		}
	}
	if err := s.store.CompleteSharePointScan(context.Background(), scan, nodes); err != nil {
		s.log.Error("sharepoint scan persistence failed", "scan_id", scan.ID, "error", err)
	}
}
