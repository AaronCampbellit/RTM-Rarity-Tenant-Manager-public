package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

// Share Detective: a tenant-wide investigation of everything shared with one
// user or guest, built for offboarding and access reviews. The scan is
// read-only and coverage-honest (skipped sites are reported, never silent);
// revoking findings goes through the standard What-If preview → approval →
// execute pipeline and is audited plus recorded in change history.
//
// Investigations are ephemeral operational state kept in memory (like pending
// approvals and policy templates): findings that matter are exported or acted
// on, and a fresh scan is always cheaper than trusting a stale one.

const (
	// sdScanTimeout bounds one tenant-wide scan.
	sdScanTimeout = 10 * time.Minute
	// sdMaxInvestigations caps retained investigations; the oldest finished
	// ones are evicted first.
	sdMaxInvestigations = 20
)

// startShareInvestigation validates the subject and launches the scan in the
// background; the client polls the investigation until it completes.
func (s *Server) startShareInvestigation(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	var body struct {
		SubjectID string `json:"subjectId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SubjectID) == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A subjectId (user or guest) is required.")
		return
	}
	t, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	users, err := s.graph.Users(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var subject model.ShareSubject
	for _, u := range users {
		if u.ID == body.SubjectID {
			typ := "Member"
			if u.Status == "Guest" {
				typ = "Guest"
			}
			subject = model.ShareSubject{ID: u.ID, Name: u.Name, UPN: u.UPN, Type: typ}
			break
		}
	}
	if subject.ID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Unknown user for this tenant.")
		return
	}

	user := auth.UserFromContext(r.Context())
	inv := &model.ShareInvestigation{
		ID:         fmt.Sprintf("sdi_%d", time.Now().UnixNano()),
		TenantID:   tenantID,
		TenantName: t.Name,
		Subject:    subject,
		Status:     "running",
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		StartedBy:  user.Name,
		Coverage:   []model.ShareCoverage{},
		Findings:   []model.ShareFinding{},
	}
	s.sdMu.Lock()
	if s.sdInvestigations == nil {
		s.sdInvestigations = map[string]*model.ShareInvestigation{}
	}
	s.evictOldInvestigationsLocked()
	s.sdInvestigations[inv.ID] = inv
	s.sdMu.Unlock()

	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "share_detective.start",
		Resource: fmt.Sprintf("%s — %s", t.Name, subject.UPN), Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})

	go s.runShareScan(inv.ID, tenantID, subject)
	httpx.WriteJSON(w, http.StatusAccepted, s.investigationSnapshot(inv.ID))
}

// evictOldInvestigationsLocked drops the oldest finished investigations once
// the cap is reached (running ones are never evicted). Caller holds sdMu.
func (s *Server) evictOldInvestigationsLocked() {
	if len(s.sdInvestigations) < sdMaxInvestigations {
		return
	}
	finished := make([]*model.ShareInvestigation, 0, len(s.sdInvestigations))
	for _, inv := range s.sdInvestigations {
		if inv.Status != "running" {
			finished = append(finished, inv)
		}
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].StartedAt < finished[j].StartedAt })
	for i := 0; i < len(finished) && len(s.sdInvestigations) >= sdMaxInvestigations; i++ {
		delete(s.sdInvestigations, finished[i].ID)
	}
}

// runShareScan performs the tenant-wide scan. It runs detached from the
// request (the operator polls), with its own timeout.
func (s *Server) runShareScan(invID, tenantID string, subject model.ShareSubject) {
	ctx, cancel := context.WithTimeout(context.Background(), sdScanTimeout)
	defer cancel()

	// The subject's transitive groups classify group-based access. Best-effort:
	// without it (missing permission) group grants degrade to "unknown via".
	groupIDs, err := s.graph.UserGroupIDs(ctx, tenantID, subject.ID)
	if err != nil {
		s.log.Warn("share detective: group membership unavailable", "subject", subject.ID, "error", err)
	}
	memberOf := make(map[string]bool, len(groupIDs))
	for _, id := range groupIDs {
		memberOf[id] = true
	}
	groupNames := map[string]string{}
	if groups, err := s.graph.Groups(ctx, tenantID); err == nil {
		for _, g := range groups {
			groupNames[g.ID] = g.Name
		}
	}

	sites, err := s.graph.Sites(ctx, tenantID)
	if err != nil {
		s.finishInvestigation(invID, func(inv *model.ShareInvestigation) {
			inv.Status = "failed"
			inv.Error = "Could not enumerate SharePoint sites: " + err.Error()
		})
		return
	}
	s.updateInvestigation(invID, func(inv *model.ShareInvestigation) {
		inv.Summary.SitesDiscovered = len(sites)
	})

	findingSeq := 0
	nextID := func() string {
		findingSeq++
		return fmt.Sprintf("f_%d", findingSeq)
	}

	for _, site := range sites {
		coverage := model.ShareCoverage{SiteID: site.ID, SiteName: site.Name, Status: "scanned"}
		findings := []model.ShareFinding{}

		// Site-level permissions: direct grants and site membership.
		perms, err := s.graph.SitePermissions(ctx, tenantID, site.ID)
		if err != nil {
			coverage.Status = "skipped"
			coverage.Reason = scanReason(err)
			s.updateInvestigation(invID, func(inv *model.ShareInvestigation) {
				inv.Coverage = append(inv.Coverage, coverage)
				inv.Summary.SitesSkipped++
			})
			continue
		}
		for _, p := range perms {
			f, ok := classifySitePermission(site, p, subject, memberOf, groupNames)
			if !ok {
				continue
			}
			f.ID = nextID()
			findings = append(findings, f)
		}

		// Item-level permissions: files/folders with their own sharing state.
		items, err := s.graph.SharedItems(ctx, tenantID, site.ID)
		if err != nil {
			coverage.Status = "partial"
			coverage.Reason = "Site permissions scanned; drive items unavailable: " + scanReason(err)
		} else {
			coverage.ItemsScanned = len(items)
			for _, item := range items {
				for _, p := range item.Permissions {
					f, ok := classifyItemPermission(site, item, p, subject, memberOf, groupNames)
					if !ok {
						continue
					}
					f.ID = nextID()
					findings = append(findings, f)
				}
			}
		}

		s.updateInvestigation(invID, func(inv *model.ShareInvestigation) {
			inv.Coverage = append(inv.Coverage, coverage)
			inv.Findings = append(inv.Findings, findings...)
			inv.Summary.SitesScanned++
			inv.Summary.ItemsScanned += coverage.ItemsScanned
		})
	}

	s.finishInvestigation(invID, func(inv *model.ShareInvestigation) {
		inv.Status = "completed"
		inv.Summary.Findings = len(inv.Findings)
		for _, f := range inv.Findings {
			if f.Revocable {
				inv.Summary.Revocable++
			}
		}
	})
}

// scanReason renders a provider error for the coverage table without leaking
// anything the operator shouldn't see (provider errors never carry secrets).
func scanReason(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

// matchesSubject reports whether a grantee id/UPN identifies the subject.
// Guests often have rewritten UPNs, so both the object id and the email/UPN
// forms are compared case-insensitively.
func matchesSubject(subject model.ShareSubject, granteeID, granteeUPN string) bool {
	if granteeID != "" && granteeID == subject.ID {
		return true
	}
	return granteeUPN != "" && strings.EqualFold(granteeUPN, subject.UPN)
}

// classifySitePermission maps one site-level permission row to a finding (or
// none when it doesn't concern the subject).
func classifySitePermission(site model.Site, p model.SitePermission, subject model.ShareSubject, memberOf map[string]bool, groupNames map[string]string) (model.ShareFinding, bool) {
	base := model.ShareFinding{
		SiteID: site.ID, SiteName: site.Name,
		ItemPath: site.URL, ItemType: "site", WebURL: site.URL, Role: p.Role,
	}
	switch {
	case (p.Type == "User" || p.Type == "External") && matchesSubject(subject, p.PrincipalUPN, p.PrincipalUPN):
		if p.Source == "Direct" {
			base.Classification = model.ShareDirectUser
			base.PermissionID = p.ID
			base.Revocable = true
			base.Detail = "Direct site grant — revocable for this subject only."
			return base, true
		}
		base.Classification = model.ShareSiteMembership
		base.Via = p.Source
		base.Detail = fmt.Sprintf("Access via the site's %s group — remove the site membership instead of a permission entry.", p.Source)
		return base, true
	case p.Type == "Group" && memberOf[p.PrincipalUPN]:
		base.Classification = model.ShareGroupBased
		base.Via = groupLabel(p.PrincipalUPN, p.Principal, groupNames)
		base.Detail = "Access via group membership — use the remove-from-group action to revoke."
		return base, true
	}
	return model.ShareFinding{}, false
}

// classifyItemPermission maps one drive-item permission entry to a finding.
// Broad links are reported even though they don't name the subject — they are
// exactly what an investigation needs eyes on, and deleting one affects
// everyone with the link (manual review).
func classifyItemPermission(site model.Site, item model.SharedItem, p model.ItemPermission, subject model.ShareSubject, memberOf map[string]bool, groupNames map[string]string) (model.ShareFinding, bool) {
	base := model.ShareFinding{
		SiteID: site.ID, SiteName: site.Name,
		DriveID: item.DriveID, ItemID: item.ItemID,
		ItemPath: item.Path, ItemType: item.Type, WebURL: item.WebURL,
		Role: strings.Join(p.Roles, ", "), PermissionID: p.ID,
	}
	switch {
	case p.GranteeType == "user" && matchesSubject(subject, p.GranteeID, p.GranteeUPN):
		if p.Inherited {
			base.Classification = model.ShareInherited
			base.PermissionID = ""
			base.Detail = "Inherited from a parent folder — revoke at the parent."
			return base, true
		}
		base.Classification = model.ShareDirectUser
		base.Revocable = true
		base.Detail = "Direct permission — revocable for this subject only."
		return base, true
	case p.GranteeType == "link" && p.LinkScope == "users" && matchesSubject(subject, p.GranteeID, p.GranteeUPN):
		base.Classification = model.ShareSpecificLink
		base.Revocable = !p.Inherited
		base.Detail = "Specific-people sharing link that includes the subject."
		if p.Inherited {
			base.PermissionID = ""
			base.Detail += " Inherited from a parent folder — revoke at the parent."
		}
		return base, true
	case p.GranteeType == "link" && (p.LinkScope == "anonymous" || p.LinkScope == "organization"):
		base.Classification = model.ShareBroadLink
		base.PermissionID = ""
		base.Via = p.LinkScope + " link"
		base.Detail = "Broad sharing link — the subject may use it, but deleting it affects everyone with the link. Manual review."
		return base, true
	case p.GranteeType == "group" && memberOf[p.GranteeID]:
		base.Classification = model.ShareGroupBased
		base.PermissionID = ""
		base.Via = groupLabel(p.GranteeID, p.GranteeName, groupNames)
		base.Detail = "Access via group membership — use the remove-from-group action to revoke."
		return base, true
	}
	return model.ShareFinding{}, false
}

func groupLabel(id, fallback string, names map[string]string) string {
	if n, ok := names[id]; ok && n != "" {
		return n
	}
	if fallback != "" {
		return fallback
	}
	return id
}

func (s *Server) updateInvestigation(id string, fn func(*model.ShareInvestigation)) {
	s.sdMu.Lock()
	defer s.sdMu.Unlock()
	if inv, ok := s.sdInvestigations[id]; ok {
		fn(inv)
	}
}

func (s *Server) finishInvestigation(id string, fn func(*model.ShareInvestigation)) {
	s.updateInvestigation(id, func(inv *model.ShareInvestigation) {
		fn(inv)
		inv.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	})
}

// investigationSnapshot deep-copies an investigation so handlers never hand
// out memory the scan goroutine is still appending to.
func (s *Server) investigationSnapshot(id string) *model.ShareInvestigation {
	s.sdMu.Lock()
	defer s.sdMu.Unlock()
	inv, ok := s.sdInvestigations[id]
	if !ok {
		return nil
	}
	copied := *inv
	// Non-nil empty slices so the JSON is always arrays, never null.
	copied.Coverage = append([]model.ShareCoverage{}, inv.Coverage...)
	copied.Findings = append([]model.ShareFinding{}, inv.Findings...)
	return &copied
}

func (s *Server) listShareInvestigations(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	s.sdMu.Lock()
	ids := make([]string, 0, len(s.sdInvestigations))
	for id, inv := range s.sdInvestigations {
		if inv.TenantID == tenantID {
			ids = append(ids, id)
		}
	}
	s.sdMu.Unlock()
	out := make([]*model.ShareInvestigation, 0, len(ids))
	for _, id := range ids {
		if snap := s.investigationSnapshot(id); snap != nil {
			out = append(out, snap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt > out[j].StartedAt })
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) getShareInvestigation(w http.ResponseWriter, r *http.Request) {
	inv := s.tenantInvestigation(w, r)
	if inv == nil {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, inv)
}

// tenantInvestigation resolves the investigation in the URL, enforcing that it
// belongs to the tenant in the URL (tenant isolation applies to scan results
// too). Writes the error response itself when it returns nil.
func (s *Server) tenantInvestigation(w http.ResponseWriter, r *http.Request) *model.ShareInvestigation {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return nil
	}
	inv := s.investigationSnapshot(chi.URLParam(r, "invId"))
	if inv == nil || inv.TenantID != tenantID {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeObjectNotFound, "The requested investigation was not found.")
		return nil
	}
	return inv
}

// shareRevokeRequest selects findings to revoke. The same body shape feeds
// preview and execute so the approval token binds to exactly what was
// previewed.
type shareRevokeRequest struct {
	ApprovalToken string   `json:"approvalToken,omitempty"`
	FindingIDs    []string `json:"findingIds"`
}

// revokePayload is the canonical payload the approval token binds to.
func revokePayload(invID string, findingIDs []string) any {
	ids := append([]string(nil), findingIDs...)
	sort.Strings(ids)
	return struct {
		Investigation string   `json:"investigation"`
		FindingIDs    []string `json:"findingIds"`
	}{invID, ids}
}

// previewShareRevoke builds the What-If plan for revoking selected findings:
// what can be deleted per subject, and what needs another path.
func (s *Server) previewShareRevoke(w http.ResponseWriter, r *http.Request) {
	inv := s.tenantInvestigation(w, r)
	if inv == nil {
		return
	}
	var body shareRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.FindingIDs) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "At least one findingId is required.")
		return
	}
	preview, errMsg := s.buildRevokePreview(inv, body.FindingIDs)
	if errMsg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, errMsg)
		return
	}
	preview.ApprovalToken = s.issueApproval(r, revokePayload(inv.ID, body.FindingIDs))
	httpx.WriteJSON(w, http.StatusOK, preview)
}

func (s *Server) buildRevokePreview(inv *model.ShareInvestigation, findingIDs []string) (model.ShareRevokePreview, string) {
	if inv.Status != "completed" {
		return model.ShareRevokePreview{}, "The investigation has not completed."
	}
	byID := make(map[string]model.ShareFinding, len(inv.Findings))
	for _, f := range inv.Findings {
		byID[f.ID] = f
	}
	preview := model.ShareRevokePreview{
		Subject:  inv.Subject,
		Tenant:   inv.TenantName,
		Actions:  []model.ShareRevokeAction{},
		Warnings: []string{},
	}
	for _, id := range findingIDs {
		f, ok := byID[id]
		if !ok {
			return model.ShareRevokePreview{}, fmt.Sprintf("Unknown finding %q for this investigation.", id)
		}
		action := model.ShareRevokeAction{FindingID: f.ID, SiteName: f.SiteName, ItemPath: f.ItemPath}
		switch {
		case f.Revoked:
			action.Action, action.Reason = "manual_review", "Already revoked."
		case f.Revocable && f.PermissionID != "":
			action.Action = "delete_permission"
			action.Reason = "Confirmed direct grant — deleting affects only " + inv.Subject.Name + "."
			preview.RevocableCount++
		default:
			action.Action = "manual_review"
			action.Reason = f.Detail
		}
		preview.Actions = append(preview.Actions, action)
	}
	if preview.RevocableCount == 0 {
		preview.Warnings = append(preview.Warnings, "Nothing to do — none of the selected findings can be revoked directly.")
	}
	if manual := len(preview.Actions) - preview.RevocableCount; manual > 0 {
		preview.Warnings = append(preview.Warnings,
			fmt.Sprintf("%d selected finding(s) need another path (group membership, parent folder, or broad-link review) and will not be changed.", manual))
	}
	preview.Warnings = append(preview.Warnings,
		"Deleted permissions and sharing links cannot be recreated exactly — this cannot be reverted.")
	preview.Risk = "Medium"
	if preview.RevocableCount >= 10 {
		preview.Risk = "High"
	}
	return preview, ""
}

// executeShareRevoke deletes the confirmed direct grants selected in the
// preview. It follows the ThreatLocker cleanup pattern: synchronous execution
// behind a consumed approval token, partial-failure tolerant, audited, and
// recorded in change history (not revertible — deleted grants cannot be
// recreated faithfully).
func (s *Server) executeShareRevoke(w http.ResponseWriter, r *http.Request) {
	inv := s.tenantInvestigation(w, r)
	if inv == nil {
		return
	}
	var body shareRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.FindingIDs) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "At least one findingId is required.")
		return
	}
	if !s.consumeApproval(w, r, body.ApprovalToken, revokePayload(inv.ID, body.FindingIDs)) {
		return
	}
	preview, errMsg := s.buildRevokePreview(inv, body.FindingIDs)
	if errMsg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, errMsg)
		return
	}

	byID := make(map[string]model.ShareFinding, len(inv.Findings))
	for _, f := range inv.Findings {
		byID[f.ID] = f
	}
	result := model.ShareRevokeResult{Revoked: []string{}, Failed: []string{}}
	log := []string{}
	before := []string{}
	after := []string{}
	for _, action := range preview.Actions {
		if action.Action != "delete_permission" {
			continue
		}
		f := byID[action.FindingID]
		var err error
		if f.ItemID != "" {
			err = s.graph.DeleteItemPermission(r.Context(), inv.TenantID, f.SiteID, f.DriveID, f.ItemID, f.PermissionID)
		} else {
			err = s.graph.DeleteSitePermission(r.Context(), inv.TenantID, f.SiteID, f.PermissionID)
		}
		if err != nil {
			result.Failed = append(result.Failed, f.ID)
			log = append(log, fmt.Sprintf("FAILED %s — %s: %v", f.SiteName, f.ItemPath, err))
			continue
		}
		result.Revoked = append(result.Revoked, f.ID)
		before = append(before, fmt.Sprintf("%s: %s had %s (%s)", f.SiteName, f.ItemPath, inv.Subject.Name, f.Role))
		after = append(after, fmt.Sprintf("%s: %s — access removed", f.SiteName, f.ItemPath))
		log = append(log, fmt.Sprintf("Revoked %s — %s (%s)", f.SiteName, f.ItemPath, f.Classification))
		s.updateInvestigation(inv.ID, func(live *model.ShareInvestigation) {
			for i := range live.Findings {
				if live.Findings[i].ID == f.ID {
					live.Findings[i].Revoked = true
				}
			}
		})
	}
	switch {
	case len(result.Failed) == 0 && len(result.Revoked) > 0:
		result.Status = "Completed"
	case len(result.Revoked) > 0:
		result.Status = "Partial"
	default:
		result.Status = "Failed"
	}

	user := auth.UserFromContext(r.Context())
	auditResult := "Success"
	if result.Status != "Completed" {
		auditResult = "Failed"
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "share_detective.revoke",
		Resource: fmt.Sprintf("%s — %s (%d revoked, %d failed)", inv.TenantName, inv.Subject.UPN, len(result.Revoked), len(result.Failed)),
		Result:   auditResult, CorrelationID: httpx.CorrelationID(r.Context()),
	})
	if len(result.Revoked) > 0 || len(result.Failed) > 0 {
		status := "Completed"
		if result.Status != "Completed" {
			status = "Partial"
		}
		_ = s.store.AppendChange(r.Context(), model.ChangeDetail{
			Change: model.Change{
				ID:         fmt.Sprintf("chg_sd_%d", time.Now().UnixNano()),
				Timestamp:  time.Now().UTC().Format("2006-01-02 15:04:05"),
				Technician: user.Name,
				Tenant:     inv.TenantName,
				Action:     "Revoke shared access",
				Target:     inv.Subject.UPN,
				Status:     status,
				Revert:     "Not supported",
			},
			RevertEligible: false,
			Before:         before,
			After:          after,
			ExecutionLog:   log,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}
