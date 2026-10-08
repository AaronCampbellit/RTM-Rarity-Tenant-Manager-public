package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
)

type sharePointRevertPayload struct {
	TenantID string                           `json:"tenantId"`
	Change   model.SharePointPermissionChange `json:"change"`
}

func (s *Server) sharePointPermissionManager(w http.ResponseWriter, r *http.Request) graph.SharePointPermissionManager {
	manager, ok := s.graph.(graph.SharePointPermissionManager)
	if !ok {
		httpx.WriteError(w, r, http.StatusNotImplemented, httpx.CodeNotImplemented,
			"The active Microsoft provider does not support SharePoint permission management.")
		return nil
	}
	return manager
}

func targetFromQuery(r *http.Request) model.SharePointPermissionTarget {
	q := r.URL.Query()
	return model.SharePointPermissionTarget{
		SiteID: q.Get("siteId"), DriveID: q.Get("driveId"), ItemID: q.Get("itemId"),
		Kind: q.Get("kind"), Path: q.Get("path"),
	}
}

func validPermissionTarget(target model.SharePointPermissionTarget) bool {
	if target.SiteID == "" || target.Kind == "" || target.Path == "" {
		return false
	}
	switch target.Kind {
	case "site":
		return true
	case "library", "folder", "file":
		return target.DriveID != ""
	default:
		return false
	}
}

func (s *Server) getSharePointScopePermissions(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	target := targetFromQuery(r)
	if !validPermissionTarget(target) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"A valid site/library/folder/file target is required.")
		return
	}
	manager := s.sharePointPermissionManager(w, r)
	if manager == nil {
		return
	}
	permissions, err := manager.SharePointScopePermissions(r.Context(), tenantID, target)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if permissions == nil {
		permissions = []model.SharePointScopePermission{}
	}
	httpx.WriteJSON(w, http.StatusOK, permissions)
}

func validateSharePointPermissionRequest(body model.SharePointPermissionRequest) string {
	if !validPermissionTarget(body.Target) {
		return "A valid site/library/folder/file target is required."
	}
	switch body.Operation {
	case "grant":
		if body.PrincipalID == "" || (body.Role != graph.SiteRoleRead && body.Role != graph.SiteRoleEdit && body.Role != graph.SiteRoleFullControl) {
			return "Grant requires a principal and a Read, Edit, or Full Control role."
		}
	case "revoke":
		if body.PrincipalID == "" {
			return "Revoke requires a principal."
		}
	case "restore_inheritance":
		if body.Target.Kind == "site" {
			return "A site cannot inherit permissions from a parent."
		}
	default:
		return "Operation must be grant, revoke, or restore_inheritance."
	}
	return ""
}

func permissionApprovalPayload(body model.SharePointPermissionRequest) model.SharePointPermissionRequest {
	body.ApprovalToken = ""
	return body
}

func (s *Server) buildSharePointPermissionPreview(r *http.Request, tenantID string, body model.SharePointPermissionRequest) (model.SharePointPermissionPreview, model.SharePointPermissionChange, string, error) {
	preview := model.SharePointPermissionPreview{
		Target: body.Target, Principal: body.PrincipalUPN, Operation: body.Operation,
		Role: body.Role, Risk: "Medium", Warnings: []string{}, Blocked: []string{},
	}
	if msg := validateSharePointPermissionRequest(body); msg != "" {
		return preview, model.SharePointPermissionChange{}, msg, nil
	}
	manager, ok := s.graph.(graph.SharePointPermissionManager)
	if !ok {
		return preview, model.SharePointPermissionChange{}, "", graph.ErrSharePointOnly
	}
	before, err := manager.SharePointScopePermissions(r.Context(), tenantID, body.Target)
	if err != nil {
		return preview, model.SharePointPermissionChange{}, "", err
	}
	preview.Before = before
	effective := body.Target
	if body.Operation == "revoke" {
		var matched *model.SharePointScopePermission
		for i := range before {
			if before[i].PrincipalID == body.PrincipalID || (body.PrincipalUPN != "" && strings.EqualFold(before[i].PrincipalUPN, body.PrincipalUPN)) {
				matched = &before[i]
				break
			}
		}
		if matched == nil {
			return preview, model.SharePointPermissionChange{}, "The selected principal does not have access at this scope.", nil
		}
		if preview.Principal == "" {
			preview.Principal = matched.Principal
		}
		if body.Role == "" {
			body.Role, preview.Role = matched.Role, matched.Role
		}
		if matched.Inherited {
			if body.BreakInheritance {
				preview.BreaksInheritance = true
				preview.Risk = "High"
				preview.Warnings = append(preview.Warnings,
					"This breaks inheritance locally, copies the current assignments, then removes the principal. Future parent changes will no longer flow to this scope.")
			} else if matched.SourceTarget != nil {
				effective = *matched.SourceTarget
				preview.Warnings = append(preview.Warnings,
					"Access is inherited. RTM will change the source assignment instead of silently breaking inheritance here.")
			}
		}
	}
	if body.Operation == "restore_inheritance" {
		preview.Risk = "High"
		preview.Warnings = append(preview.Warnings,
			"Restoring inheritance removes every unique assignment at this scope and cannot be reconstructed exactly.")
	}
	preview.EffectiveTarget = &effective
	change := model.SharePointPermissionChange{
		Target: effective, PrincipalID: body.PrincipalID, PrincipalUPN: body.PrincipalUPN,
		PrincipalType: body.PrincipalType, Role: body.Role, Operation: body.Operation, BreakInheritance: body.BreakInheritance,
		CopyAssignments: body.CopyAssignments,
	}
	return preview, change, "", nil
}

func (s *Server) previewSharePointPermission(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	if _, err := s.store.Tenant(r.Context(), tenantID); err != nil {
		s.writeErr(w, r, err)
		return
	}
	var body model.SharePointPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	preview, _, msg, err := s.buildSharePointPermissionPreview(r, tenantID, body)
	if msg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, msg)
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	preview.ApprovalToken = s.issueApproval(r, permissionApprovalPayload(body))
	httpx.WriteJSON(w, http.StatusOK, preview)
}

func (s *Server) executeSharePointPermission(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	tenant, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var body model.SharePointPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if !s.consumeApproval(w, r, body.ApprovalToken, permissionApprovalPayload(body)) {
		return
	}
	preview, change, msg, err := s.buildSharePointPermissionPreview(r, tenantID, body)
	if msg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, msg)
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	manager := s.sharePointPermissionManager(w, r)
	if manager == nil {
		return
	}
	if err := manager.SetSharePointScopePermission(r.Context(), tenantID, change); err != nil {
		s.writeErr(w, r, err)
		return
	}
	changeID := fmt.Sprintf("chg_sp_%d", time.Now().UnixNano())
	revertEligible := body.Operation != "restore_inheritance"
	revertPayload := ""
	if revertEligible {
		inverse := change
		switch {
		case body.Operation == "grant":
			inverse.Operation = "revoke"
		case preview.BreaksInheritance:
			inverse.Operation = "restore_inheritance"
			inverse.PrincipalID, inverse.PrincipalUPN, inverse.Role = "", "", ""
		default:
			inverse.Operation = "grant"
		}
		raw, _ := json.Marshal(sharePointRevertPayload{TenantID: tenantID, Change: inverse})
		revertPayload = string(raw)
	}
	user := auth.UserFromContext(r.Context())
	revertState := "Not supported"
	if revertEligible {
		revertState = "Available"
	}
	_ = s.store.AppendChange(r.Context(), model.ChangeDetail{
		Change: model.Change{
			ID: changeID, Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05"),
			Technician: user.Name, Tenant: tenant.Name,
			Action: "SharePoint permission " + body.Operation, Target: body.Target.Path,
			Status: "Completed", Revert: revertState,
		},
		RevertEligible: revertEligible, RevertPayload: revertPayload,
		Before:       []string{fmt.Sprintf("%s assignments: %d", body.Target.Path, len(preview.Before))},
		After:        []string{fmt.Sprintf("%s %s for %s", body.Operation, body.Role, preview.Principal)},
		ExecutionLog: []string{"SharePoint permission change completed."},
	})
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "sharepoint.permission_" + body.Operation,
		Resource: tenant.Name + " — " + body.Target.Path, Result: "Success",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, model.SharePointPermissionResult{Status: "Completed", ChangeID: changeID})
}

func (s *Server) revertSharePointPermission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChangeID string `json:"changeId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ChangeID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A changeId is required.")
		return
	}
	detail, err := s.store.Change(r.Context(), body.ChangeID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !detail.RevertEligible || detail.RevertPayload == "" || detail.Revert == "Reverted" {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict, "This change cannot be reverted.")
		return
	}
	var payload sharePointRevertPayload
	if err := json.Unmarshal([]byte(detail.RevertPayload), &payload); err != nil {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict, "The revert snapshot is unreadable.")
		return
	}
	if payload.TenantID != chi.URLParam(r, "tenantId") {
		httpx.WriteError(w, r, http.StatusForbidden, httpx.CodeAuthorizationDenied, "The change belongs to another tenant.")
		return
	}
	manager := s.sharePointPermissionManager(w, r)
	if manager == nil {
		return
	}
	if err := manager.SetSharePointScopePermission(r.Context(), payload.TenantID, payload.Change); err != nil {
		s.writeErr(w, r, err)
		return
	}
	if err := s.store.UpdateChangeRevert(r.Context(), body.ChangeID, "Reverted"); err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "sharepoint.permission_revert",
		Resource: detail.Target, Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, model.SharePointPermissionResult{Status: "Completed", ChangeID: body.ChangeID})
}
