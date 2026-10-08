package server

// ThreatLocker module handlers: the global MSP workspace endpoints plus the
// change-pipeline resolution for ThreatLocker write actions. A deployment
// without the global parent connection gets NOT_CONNECTED.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
	"github.com/rarity/rtm/internal/worker"
)

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	v, err := s.tl.Devices(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v == nil {
		v = []model.Device{}
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	v, err := s.tl.Device(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "deviceId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listDeviceGroups(w http.ResponseWriter, r *http.Request) {
	v, err := s.tl.DeviceGroups(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v == nil {
		v = []model.DeviceGroup{}
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listApprovalRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status") // "" = pending
	v, err := s.tl.ApprovalRequests(r.Context(), chi.URLParam(r, "tenantId"), status)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v == nil {
		v = []model.ApprovalRequest{}
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) getApprovalRequest(w http.ResponseWriter, r *http.Request) {
	v, err := s.tl.ApprovalRequest(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "requestId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listTLPolicies(w http.ResponseWriter, r *http.Request) {
	v, err := s.tl.Policies(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v == nil {
		v = []model.TLPolicy{}
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listTLApps(w http.ResponseWriter, r *http.Request) {
	req := threatlocker.AppSearchRequest{
		SearchText:                strings.TrimSpace(r.URL.Query().Get("search")),
		SearchBy:                  strings.TrimSpace(r.URL.Query().Get("searchBy")),
		Source:                    strings.TrimSpace(r.URL.Query().Get("source")),
		IncludeChildOrganizations: true,
		IncludeUnused:             true,
	}
	var (
		v   []model.TLApplication
		err error
	)
	if req.SearchText == "" && req.SearchBy == "" && req.Source == "" {
		v, err = s.tlApplicationInventory(r.Context(), strings.EqualFold(r.URL.Query().Get("refresh"), "true"))
	} else {
		v, err = s.tl.Applications(r.Context(), chi.URLParam(r, "tenantId"), req)
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if v == nil {
		v = []model.TLApplication{}
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) listTLAppCleanupCandidates(w http.ResponseWriter, r *http.Request) {
	apps, err := s.tlApplicationInventory(r.Context(), strings.EqualFold(r.URL.Query().Get("refresh"), "true"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	parent, _, err := s.globalThreatLockerAuth(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rankTLAppCleanupCandidates(apps, parent.OrgID))
}

func rankTLAppCleanupCandidates(apps []model.TLApplication, parentOrgID string) []model.TLAppCleanupCandidate {
	groups := map[string][]model.TLApplication{}
	for _, app := range apps {
		family := tlCleanupFamilyName(app.Name)
		if app.ID == "" || family == "" || app.BuiltIn {
			continue
		}
		key := fmt.Sprintf("%d:%s", app.OSType, family)
		groups[key] = append(groups[key], app)
	}
	candidates := []model.TLAppCleanupCandidate{}
	for key, familyApps := range groups {
		orgs := map[string]bool{}
		exactNames := map[string]map[string]bool{}
		var parentApp model.TLApplication
		totalFiles, totalPolicies := 0, 0
		for _, app := range familyApps {
			orgID := strings.ToLower(strings.TrimSpace(app.OrganizationID))
			if orgID != "" {
				orgs[orgID] = true
			}
			exact := normalizeTLPolicyText(app.Name)
			if exactNames[exact] == nil {
				exactNames[exact] = map[string]bool{}
			}
			exactNames[exact][orgID] = true
			if strings.EqualFold(strings.TrimSpace(app.OrganizationID), strings.TrimSpace(parentOrgID)) {
				parentApp = app
			}
			totalFiles += app.FileCount
			totalPolicies += app.PolicyCount
		}
		if len(familyApps) < 2 || len(orgs) < 2 {
			continue
		}
		exactAcrossOrganizations := false
		for _, nameOrgs := range exactNames {
			if len(nameOrgs) >= 2 {
				exactAcrossOrganizations = true
				break
			}
		}
		sort.Slice(familyApps, func(i, j int) bool {
			if familyApps[i].Source != familyApps[j].Source {
				return familyApps[i].Source == "parent"
			}
			if len(familyApps[i].Name) != len(familyApps[j].Name) {
				return len(familyApps[i].Name) < len(familyApps[j].Name)
			}
			return familyApps[i].Name < familyApps[j].Name
		})
		score := 35 + min(15, (len(orgs)-1)*8) + min(15, (len(familyApps)-2)*5)
		reasons := []string{fmt.Sprintf("%d application records span %d organizations.", len(familyApps), len(orgs))}
		if parentApp.ID != "" {
			score += 25
			reasons = append(reasons, "A parent-owned canonical application is ready.")
		}
		if exactAcrossOrganizations {
			score += 10
			reasons = append(reasons, "The same application name appears in multiple organizations.")
		} else {
			reasons = append(reasons, "Names match after conservative family normalization; deep review is required.")
		}
		if score > 100 {
			score = 100
		}
		confidence := "review"
		if parentApp.ID != "" && exactAcrossOrganizations {
			confidence = "high"
		}
		candidates = append(candidates, model.TLAppCleanupCandidate{
			ID: key, Name: familyApps[0].Name, OSType: familyApps[0].OSType, OS: familyApps[0].OS,
			Score: score, Confidence: confidence, ParentReady: parentApp.ID != "",
			RecommendedRetainedAppID: parentApp.ID, OrganizationCount: len(orgs),
			TotalFileRules: totalFiles, TotalPolicies: totalPolicies,
			Applications: familyApps, Reasons: reasons,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Name < candidates[j].Name
	})
	return candidates
}

func tlCleanupFamilyName(name string) string {
	fields := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(name)), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	ignored := map[string]bool{
		"x64": true, "x86": true, "64bit": true, "32bit": true,
		"windows": true, "macos": true, "linux": true,
		"helper": true, "updater": true, "update": true,
	}
	kept := fields[:0]
	for _, field := range fields {
		if ignored[field] || tlVersionToken(field) {
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " ")
}

func tlVersionToken(value string) bool {
	if value == "" {
		return false
	}
	hasDigit := false
	for _, r := range value {
		if unicode.IsDigit(r) {
			hasDigit = true
			continue
		}
		if r != 'v' && r != 'r' {
			return false
		}
	}
	return hasDigit
}

func (s *Server) getTLApp(w http.ResponseWriter, r *http.Request) {
	v, err := s.tl.Application(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "appId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	files, err := s.tl.ApplicationFiles(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "appId"), v.OSType)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	v.Files = files
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) updateTLApp(w http.ResponseWriter, r *http.Request) {
	tenantID, appID := chi.URLParam(r, "tenantId"), chi.URLParam(r, "appId")
	scopeName, err := s.threatLockerScopeName(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var patch model.TLApplicationPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	patch.ID = appID
	token := patch.ApprovalToken
	patch.ApprovalToken = ""
	if !s.consumeApproval(w, r, token, patch) {
		return
	}
	updated, err := s.tl.UpdateApplication(r.Context(), tenantID, patch)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.app.update", Resource: scopeName + " / " + updated.Name,
		Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, updated)
}

func (s *Server) previewTLAppUpdate(w http.ResponseWriter, r *http.Request) {
	var patch model.TLApplicationPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	patch.ID = chi.URLParam(r, "appId")
	patch.ApprovalToken = ""
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"approvalToken": s.issueApproval(r, patch), "summary": "Update ThreatLocker application " + patch.ID})
}

func (s *Server) previewTLAppCleanup(w http.ResponseWriter, r *http.Request) {
	var body model.TLAppCleanupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	preview, msg, err := s.buildTLAppCleanupPreview(r.Context(), chi.URLParam(r, "tenantId"), body)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if msg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, msg)
		return
	}
	preview.Fingerprint = tlAppCleanupFingerprint(body, preview)
	if operation, err := s.store.ActiveTLAppCleanupOperation(r.Context(), preview.Fingerprint); err == nil {
		preview.Blocked = append(preview.Blocked,
			"Equivalent cleanup operation "+operation.ID+" is "+strings.ReplaceAll(operation.Status, "_", " ")+
				"; reconcile it before submitting again.")
	}
	preview.ApprovalToken = s.issueApproval(r, body)
	if preview.ParentPromotion != nil && preview.ParentPromotion.DestinationGroupID != "" {
		proposal := *preview.ParentPromotion
		proposal.ApprovalToken = ""
		preview.ParentPromotion.ApprovalToken = s.issueApproval(r, proposal)
	}
	httpx.WriteJSON(w, http.StatusOK, preview)
}

func (s *Server) promoteTLAppCleanupParent(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	var proposal model.TLAppParentPromotion
	if err := json.NewDecoder(r.Body).Decode(&proposal); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	token := proposal.ApprovalToken
	proposal.ApprovalToken = ""
	if !s.consumeApproval(w, r, token, proposal) {
		return
	}
	parent, _, err := s.globalThreatLockerAuth(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !completeThreatLockerAuth(parent) ||
		!strings.EqualFold(strings.TrimSpace(proposal.ParentOrganizationID), strings.TrimSpace(parent.OrgID)) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"The proposed parent organization no longer matches the configured ThreatLocker parent.")
		return
	}
	global, err := s.tl.GlobalComputerGroup(r.Context(), parent)
	if err != nil || global.ID != proposal.DestinationGroupID || !strings.EqualFold(strings.TrimSpace(global.Name), "Global") {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"The exact Global destination changed. Refresh the cleanup preview before promoting the policy.")
		return
	}
	apps, err := s.tl.Applications(r.Context(), tenantID, threatlocker.AppSearchRequest{
		SearchText: " ", SearchBy: "app", IncludeChildOrganizations: true, IncludeUnused: true,
	})
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var source model.TLApplication
	for _, app := range apps {
		if app.ID == proposal.ApplicationID {
			source = app
			break
		}
	}
	if source.ID == "" || !strings.EqualFold(strings.TrimSpace(source.OrganizationID), strings.TrimSpace(proposal.SourceOrganizationID)) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"The proposed child application no longer exists in its reviewed organization. Refresh the cleanup preview.")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(source.OrganizationID), strings.TrimSpace(proposal.ApplicationOrganizationID)) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"The proposed application organization changed. Refresh the cleanup preview.")
		return
	}
	sourceAuth := parent
	sourceAuth.OrgID = source.OrganizationID
	policies, err := s.tl.PoliciesForApplicationForAuth(r.Context(), sourceAuth, source.ID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var selectedPolicy model.TLPolicy
	for _, policy := range policies {
		if policy.ID == proposal.PolicyID &&
			strings.EqualFold(strings.TrimSpace(policy.OrganizationID), strings.TrimSpace(proposal.SourceOrganizationID)) {
			selectedPolicy = policy
			break
		}
	}
	if selectedPolicy.ID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"The proposed child policy is no longer attached to the reviewed application. Refresh the cleanup preview.")
		return
	}
	fingerprint := tlParentPromotionFingerprint(proposal)
	user := auth.UserFromContext(r.Context())
	operation, err := s.store.CreateTLAppCleanupOperation(r.Context(), model.TLAppCleanupOperation{
		TenantID: tenantID, Status: model.TLCleanupSubmitted, RequestedBy: user.Name,
		Fingerprint: fingerprint,
		Request: model.TLAppCleanupRequest{
			AppIDs: []string{proposal.ApplicationID}, RetainedPolicyID: proposal.PolicyID,
			Name: proposal.ApplicationName,
		},
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict,
				"An equivalent parent promotion is already active and must be verified or reconciled before it can be submitted again.")
			return
		}
		s.writeErr(w, r, err)
		return
	}
	result := model.TLAppCleanupResult{
		Status: "Completed", Stage: "parent_promotion", OperationID: operation.ID,
		VerificationStatus: model.TLCleanupVerificationPending,
		Verification:       model.TLAppCleanupVerification{Checks: []model.TLAppCleanupVerificationCheck{}},
		PreservedPolicies:  []model.TLPolicy{selectedPolicy},
		PromotedPolicyIDs:  []string{proposal.PolicyID},
		ParentPromotion:    &proposal,
		RetainedAppName:    proposal.ApplicationName,
		RetainedAppOSType:  proposal.OSType,
		DeletedAppIDs:      []string{},
		DeletedPolicyIDs:   []string{},
		Failed:             []string{},
	}
	scopeName, scopeErr := s.threatLockerScopeName(r.Context(), tenantID)
	if scopeErr != nil {
		s.writeErr(w, r, scopeErr)
		return
	}
	if err := s.tl.PromoteApplicationPolicy(r.Context(), parent, proposal); err != nil {
		s.failTLAppCleanupOperation(w, r, operation, scopeName, result, err)
		return
	}
	if err := s.store.UpdateTLAppCleanupOperation(r.Context(), operation.ID,
		model.TLCleanupVerificationPending, result, ""); err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.app.cleanup.parent_promote",
		Resource: scopeName + " / " + proposal.ApplicationName,
		Result:   "Verification pending", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) executeTLAppCleanup(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	scopeName, err := s.threatLockerScopeName(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var body model.TLAppCleanupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	token := body.ApprovalToken
	body.ApprovalToken = ""
	if !s.consumeApproval(w, r, token, body) {
		return
	}
	preview, msg, err := s.buildTLAppCleanupPreview(r.Context(), tenantID, body)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if msg != "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, msg)
		return
	}
	if len(preview.Blocked) > 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, strings.Join(preview.Blocked, " "))
		return
	}
	preview.Fingerprint = tlAppCleanupFingerprint(body, preview)
	parent, _, err := s.globalThreatLockerAuth(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if !completeThreatLockerAuth(parent) {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"ThreatLocker parent organization ID is not configured.")
		return
	}

	user := auth.UserFromContext(r.Context())
	operation, err := s.store.CreateTLAppCleanupOperation(r.Context(), model.TLAppCleanupOperation{
		TenantID: tenantID, Status: model.TLCleanupSubmitted, RequestedBy: user.Name,
		Fingerprint: preview.Fingerprint, Request: body,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict,
				"An equivalent ThreatLocker cleanup is already active and must be reconciled before it can be submitted again.")
			return
		}
		s.writeErr(w, r, err)
		return
	}
	result := model.TLAppCleanupResult{
		Status:            "Completed",
		Stage:             "application_merge",
		OperationID:       operation.ID,
		RetainedAppID:     preview.RetainedApp.ID,
		RetainedPolicyID:  preview.RetainedPolicy.ID,
		RetainedAppName:   preview.RetainedApp.Name,
		RetainedAppOSType: preview.RetainedApp.OSType,
		ExpectedFileRules: preview.FileRuleCount,
		DeletedAppIDs:     append([]string{}, preview.DeleteAppIDs...),
		DeletedPolicyIDs:  []string{},
		PreservedPolicies: append([]model.TLPolicy{}, preview.PreservedPolicies...),
		PromotedPolicyIDs: []string{},
		Verification:      model.TLAppCleanupVerification{Checks: []model.TLAppCleanupVerificationCheck{}},
		Failed:            []string{},
	}
	if result.RetainedAppID == "" || preview.RetainedApp.Source != "parent" {
		s.failTLAppCleanupOperation(w, r, operation, scopeName, result,
			fmt.Errorf("threatlocker: a verified parent-owned application is required before merge"))
		return
	}
	sources := make([]model.TLApplication, 0, len(preview.SourceApps))
	for _, app := range preview.SourceApps {
		if app.ID != result.RetainedAppID {
			sources = append(sources, app)
		}
	}
	merged, err := s.tl.MergeApplications(
		r.Context(), parent, preview.RetainedApp, sources, strings.TrimSpace(body.Name),
	)
	if err != nil {
		s.failTLAppCleanupOperation(w, r, operation, scopeName, result, err)
		return
	}
	result.RetainedAppID = merged.ID
	result.RetainedAppName = merged.Name
	result.RetainedAppOSType = merged.OSType

	for _, policy := range preview.PreservedPolicies {
		alreadyGlobal := strings.EqualFold(strings.TrimSpace(policy.OrganizationID), strings.TrimSpace(parent.OrgID)) &&
			(strings.EqualFold(strings.TrimSpace(policy.AppliesTo), "Global") ||
				strings.EqualFold(strings.TrimSpace(policy.AppliesTo), "Entire Organization"))
		if alreadyGlobal {
			result.PromotedPolicyIDs = append(result.PromotedPolicyIDs, policy.ID)
			if result.RetainedPolicyID == "" {
				result.RetainedPolicyID = policy.ID
			}
			continue
		}
		promotion := model.TLAppParentPromotion{
			ApplicationID:             result.RetainedAppID,
			ApplicationName:           result.RetainedAppName,
			ApplicationOrganizationID: parent.OrgID,
			SourceOrganizationID:      policy.OrganizationID,
			PolicyID:                  policy.ID,
			PolicyName:                policy.Name,
			DestinationGroupID:        preview.GlobalDestination.ID,
			DestinationGroupName:      preview.GlobalDestination.Name,
			ParentOrganizationID:      parent.OrgID,
			OSType:                    result.RetainedAppOSType,
		}
		if err := s.tl.PromoteApplicationPolicy(r.Context(), parent, promotion); err != nil {
			s.failTLAppCleanupOperation(w, r, operation, scopeName, result, err)
			return
		}
		result.PromotedPolicyIDs = append(result.PromotedPolicyIDs, policy.ID)
		if result.RetainedPolicyID == "" {
			result.RetainedPolicyID = policy.ID
		}
	}
	result.Stage = "policy_review"
	verificationStatus := model.TLCleanupVerificationPending
	result.VerificationStatus = verificationStatus
	if err := s.store.UpdateTLAppCleanupOperation(r.Context(), operation.ID, verificationStatus, result, strings.Join(result.Failed, "; ")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.app.cleanup", Resource: scopeName + " / " + preview.RetainedApp.Name,
		Result: result.Status, CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) failTLAppCleanupOperation(
	w http.ResponseWriter,
	r *http.Request,
	operation model.TLAppCleanupOperation,
	scopeName string,
	result model.TLAppCleanupResult,
	err error,
) {
	result.Status = "Failed"
	result.VerificationStatus = model.TLCleanupNeedsReconciliation
	result.Failed = append(result.Failed, err.Error())
	_ = s.store.UpdateTLAppCleanupOperation(
		r.Context(), operation.ID, model.TLCleanupNeedsReconciliation, result, err.Error(),
	)
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: operation.RequestedBy, Action: "threatlocker.app.cleanup",
		Resource: scopeName, Result: "Needs reconciliation",
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	s.writeErr(w, r, err)
}

func (s *Server) listTLAppCleanupOperations(w http.ResponseWriter, r *http.Request) {
	operations, err := s.store.TLAppCleanupOperations(r.Context(), chi.URLParam(r, "tenantId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if operations == nil {
		operations = []model.TLAppCleanupOperation{}
	}
	httpx.WriteJSON(w, http.StatusOK, operations)
}

func (s *Server) verifyTLAppCleanupOperation(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantId")
	operations, err := s.store.TLAppCleanupOperations(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	operationID := chi.URLParam(r, "operationId")
	var operation *model.TLAppCleanupOperation
	for i := range operations {
		if operations[i].ID == operationID {
			operation = &operations[i]
			break
		}
	}
	if operation == nil {
		s.writeErr(w, r, store.ErrNotFound)
		return
	}
	if operation.Status == model.TLCleanupFailed || operation.Status == model.TLCleanupSubmitted {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict,
			"This cleanup operation is not ready for portal verification.")
		return
	}

	result := operation.Result
	if result.Stage == "parent_promotion" {
		apps, appsErr := s.tl.Applications(r.Context(), tenantID, threatlocker.AppSearchRequest{
			SearchText: result.RetainedAppName, SearchBy: "app", Source: "parent",
			OSType: result.RetainedAppOSType, IncludeUnused: true,
		})
		var retained model.TLApplication
		for _, app := range apps {
			if app.Source == "parent" &&
				normalizeTLPolicyText(app.Name) == normalizeTLPolicyText(result.RetainedAppName) &&
				(result.RetainedAppOSType == 0 || app.OSType == result.RetainedAppOSType) {
				retained = app
				break
			}
		}
		passed := appsErr == nil && retained.ID != ""
		status := model.TLCleanupVerificationPending
		details := "The promoted parent application is not visible yet. Refresh after ThreatLocker finishes the queue."
		if passed {
			status = model.TLCleanupVerified
			details = "The policy promotion created the parent-owned application."
			result.RetainedAppID = retained.ID
		}
		result.VerificationStatus = status
		result.Verification = model.TLAppCleanupVerification{
			Passed:    passed,
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
			Checks: []model.TLAppCleanupVerificationCheck{{
				Key: "parent_application_created", Label: "Parent application created",
				Passed: passed, Details: tlVerificationDetails(appsErr, passed, details, details),
			}},
		}
		if err := s.store.UpdateTLAppCleanupOperation(r.Context(), operation.ID, status, result, ""); err != nil {
			s.writeErr(w, r, err)
			return
		}
		scopeName, scopeErr := s.threatLockerScopeName(r.Context(), tenantID)
		if scopeErr != nil {
			s.writeErr(w, r, scopeErr)
			return
		}
		user := auth.UserFromContext(r.Context())
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
			Actor: user.Name, Action: "threatlocker.app.cleanup.parent_verify",
			Resource: scopeName + " / " + operation.ID, Result: status,
			CorrelationID: httpx.CorrelationID(r.Context()),
		})
		operation.Status = status
		operation.Result = result
		operation.Error = ""
		operation.UpdatedAt = time.Now().UTC()
		httpx.WriteJSON(w, http.StatusOK, operation)
		return
	}
	checks := []model.TLAppCleanupVerificationCheck{}
	addCheck := func(key, label string, passed bool, details string) {
		checks = append(checks, model.TLAppCleanupVerificationCheck{
			Key: key, Label: label, Passed: passed, Details: details,
		})
	}
	apps, appsErr := s.tl.Applications(r.Context(), tenantID, threatlocker.AppSearchRequest{
		SearchText: " ", SearchBy: "app", IncludeChildOrganizations: true, IncludeUnused: true,
	})
	appByID := map[string]model.TLApplication{}
	for _, app := range apps {
		appByID[app.ID] = app
	}
	retained, retainedFound := appByID[result.RetainedAppID]
	addCheck("retained_app", "Parent application exists", appsErr == nil && retainedFound && retained.Source == "parent",
		tlVerificationDetails(appsErr, retainedFound && retained.Source == "parent",
			"Retained parent application is present.", "Retained parent application is missing or is not parent-owned."))

	removedApps := appsErr == nil
	for _, id := range result.DeletedAppIDs {
		if _, exists := appByID[id]; exists {
			removedApps = false
			break
		}
	}
	addCheck("source_apps_removed", "Duplicate applications removed", removedApps,
		tlVerificationDetails(appsErr, removedApps, "All planned duplicate applications are absent.", "One or more duplicate applications still exist."))

	parent, _, parentErr := s.globalThreatLockerAuth(r.Context())
	fileRulesOK := false
	var fileErr error
	actualFileRules := 0
	if retainedFound && parentErr == nil {
		var files []model.TLApplicationFile
		retainedAuth := parent
		retainedAuth.OrgID = retained.OrganizationID
		files, fileErr = s.tl.ApplicationFilesForAuth(r.Context(), retainedAuth, result.RetainedAppID, retained.OSType)
		actualFileRules = len(files)
		fileRulesOK = fileErr == nil && actualFileRules >= result.ExpectedFileRules
	}
	addCheck("file_rules", "File rules retained", fileRulesOK,
		tlVerificationDetails(fileErr, fileRulesOK,
			fmt.Sprintf("%d file rules are present; expected at least %d.", actualFileRules, result.ExpectedFileRules),
			fmt.Sprintf("%d file rules are present; expected at least %d.", actualFileRules, result.ExpectedFileRules)))

	preservedByID := map[string]model.TLPolicy{}
	for _, policy := range result.PreservedPolicies {
		preservedByID[policy.ID] = policy
	}
	globalPoliciesOK := parentErr == nil && len(result.PromotedPolicyIDs) > 0
	verifiedPolicies := 0
	var policyErr error = parentErr
	for _, policyID := range result.PromotedPolicyIDs {
		source := preservedByID[policyID]
		policy, err := s.tl.PolicyForAuth(r.Context(), parent, policyID, source.OrganizationID)
		if err != nil {
			globalPoliciesOK = false
			if policyErr == nil {
				policyErr = err
			}
			continue
		}
		hasRetainedApp := false
		for _, id := range policy.ApplicationIDs {
			if id == result.RetainedAppID {
				hasRetainedApp = true
				break
			}
		}
		allDevices, _ := policy.Raw["allDevices"].(bool)
		global := allDevices || strings.EqualFold(policy.AppliesTo, "global") ||
			strings.EqualFold(policy.AppliesTo, "entire organization")
		if !policy.IsEnabled || !hasRetainedApp || !global {
			globalPoliciesOK = false
			continue
		}
		verifiedPolicies++
	}
	addCheck("preserved_policies_global", "Preserved policies moved to Global", globalPoliciesOK,
		tlVerificationDetails(policyErr, globalPoliciesOK,
			fmt.Sprintf("%d preserved policies are enabled, Global, and bound to the parent application.", verifiedPolicies),
			fmt.Sprintf("%d of %d preserved policies passed the Global binding check.", verifiedPolicies, len(result.PromotedPolicyIDs))))

	passed := true
	for _, check := range checks {
		if !check.Passed {
			passed = false
			break
		}
	}
	status := model.TLCleanupNeedsReconciliation
	errorMessage := "Portal verification found one or more mismatches."
	if passed {
		status = model.TLCleanupVerified
		errorMessage = ""
	}
	result.VerificationStatus = status
	result.Verification = model.TLAppCleanupVerification{
		Passed: passed, CheckedAt: time.Now().UTC().Format(time.RFC3339), Checks: checks,
	}
	if err := s.store.UpdateTLAppCleanupOperation(r.Context(), operation.ID, status, result, errorMessage); err != nil {
		s.writeErr(w, r, err)
		return
	}
	scopeName, err := s.threatLockerScopeName(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.app.cleanup.verify",
		Resource: scopeName + " / " + operation.ID, Result: status,
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	operation.Status = status
	operation.Result = result
	operation.Error = errorMessage
	operation.UpdatedAt = time.Now().UTC()
	httpx.WriteJSON(w, http.StatusOK, operation)
}

func tlVerificationDetails(err error, passed bool, success, failure string) string {
	if err != nil {
		return err.Error()
	}
	if passed {
		return success
	}
	return failure
}

func (s *Server) reconcileTLAppCleanupOperation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Resolution string `json:"resolution"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	var nextStatus string
	switch strings.TrimSpace(strings.ToLower(body.Resolution)) {
	case "verified":
		nextStatus = model.TLCleanupVerified
	case "not_applied":
		nextStatus = model.TLCleanupFailed
	default:
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed,
			"Resolution must be verified or not_applied.")
		return
	}
	tenantID := chi.URLParam(r, "tenantId")
	operations, err := s.store.TLAppCleanupOperations(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	operationID := chi.URLParam(r, "operationId")
	var operation *model.TLAppCleanupOperation
	for i := range operations {
		if operations[i].ID == operationID {
			operation = &operations[i]
			break
		}
	}
	if operation == nil {
		s.writeErr(w, r, store.ErrNotFound)
		return
	}
	if !activeTLCleanupOperationStatus(operation.Status) {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeRevertConflict,
			"This cleanup operation has already been reconciled.")
		return
	}
	errorMessage := operation.Error
	if nextStatus == model.TLCleanupVerified {
		errorMessage = ""
	}
	if err := s.store.UpdateTLAppCleanupOperation(r.Context(), operation.ID, nextStatus, operation.Result, errorMessage); err != nil {
		s.writeErr(w, r, err)
		return
	}
	scopeName, err := s.threatLockerScopeName(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.app.cleanup.reconcile",
		Resource: scopeName + " / " + operation.ID, Result: nextStatus,
		CorrelationID: httpx.CorrelationID(r.Context()),
	})
	operation.Status = nextStatus
	operation.Error = errorMessage
	operation.UpdatedAt = time.Now().UTC()
	httpx.WriteJSON(w, http.StatusOK, operation)
}

func activeTLCleanupOperationStatus(status string) bool {
	return status == model.TLCleanupSubmitted ||
		status == model.TLCleanupVerificationPending ||
		status == model.TLCleanupNeedsReconciliation
}

func (s *Server) buildTLAppCleanupPreview(ctx context.Context, tenantID string, req model.TLAppCleanupRequest) (model.TLAppCleanupPreview, string, error) {
	preview := model.TLAppCleanupPreview{
		TenantID:          tenantID,
		SourceApps:        []model.TLApplication{},
		DeleteAppIDs:      []string{},
		DeletePolicyIDs:   []string{},
		DeletePolicies:    []model.TLPolicy{},
		PreservedPolicies: []model.TLPolicy{},
		Warnings:          []string{},
		Blocked:           []string{},
	}
	parent, _, err := s.globalThreatLockerAuth(ctx)
	if err != nil {
		return preview, "", err
	}
	if !completeThreatLockerAuth(parent) {
		return preview, "ThreatLocker parent organization ID is not configured.", nil
	}
	globalDestination, globalErr := s.tl.GlobalComputerGroup(ctx, parent)
	if globalErr != nil {
		preview.Blocked = append(preview.Blocked,
			`The configured parent organization must expose an exact Global computer group before cleanup can continue. `+globalErr.Error())
	} else {
		preview.GlobalDestination = globalDestination
	}
	// Only a parent-org policy can be kept and rewritten in place — the portal
	// refuses PolicyUpdateById into another organization ("Insufficient
	// permission to update policies in the selected destination").
	isParentPolicy := func(p model.TLPolicy) bool {
		return p.ID != "" && strings.EqualFold(strings.TrimSpace(p.OrganizationID), strings.TrimSpace(parent.OrgID))
	}
	// A policy the parent org applied into a child org materializes there as a
	// portal-managed copy named "PARENT ORG\Policy name". Those rows cannot be
	// deleted directly ("You are not authorized to delete policy") and follow
	// their defining parent policy automatically, so cleanup must leave them
	// alone.
	isPushedCopy := func(p model.TLPolicy) bool {
		return p.ID != "" && !isParentPolicy(p) && strings.Contains(p.Name, `\`)
	}
	appIDs := cleanTLIDs(req.AppIDs)
	if len(appIDs) < 2 {
		return preview, "Select at least two applications to clean up.", nil
	}
	if !req.ConfirmDelete {
		preview.Blocked = append(preview.Blocked,
			"Confirm that the native merge may remove the selected source applications.")
	}

	apps, err := s.tl.Applications(ctx, tenantID, threatlocker.AppSearchRequest{
		SearchText:                " ",
		SearchBy:                  "app",
		IncludeChildOrganizations: true,
		IncludeUnused:             true,
	})
	if err != nil {
		return preview, "", err
	}
	appByID := map[string]model.TLApplication{}
	for _, app := range apps {
		if app.ID != "" {
			appByID[app.ID] = app
		}
	}
	for _, id := range appIDs {
		app, ok := appByID[id]
		if !ok {
			preview.Blocked = append(preview.Blocked, "Application "+id+" was not found.")
			continue
		}
		preview.SourceApps = append(preview.SourceApps, app)
	}
	if len(preview.SourceApps) < 2 {
		preview.Blocked = append(preview.Blocked, "At least two selected applications must still exist.")
	}

	retainedName := strings.TrimSpace(req.Name)
	if retainedName == "" && len(preview.SourceApps) > 0 {
		retainedName = preview.SourceApps[0].Name
	}
	if req.RetainedAppID != "" {
		if app, ok := appByID[strings.TrimSpace(req.RetainedAppID)]; ok {
			preview.RetainedApp = app
		} else {
			preview.Blocked = append(preview.Blocked, "Retained application "+req.RetainedAppID+" was not found.")
		}
	}
	if preview.RetainedApp.ID != "" &&
		!strings.EqualFold(strings.TrimSpace(preview.RetainedApp.OrganizationID), strings.TrimSpace(parent.OrgID)) {
		preview.Warnings = append(preview.Warnings,
			"The selected retained application is child-owned and cannot be the native merge target. RTM will require a policy promotion to create the parent target.")
		preview.RetainedApp = model.TLApplication{}
	}
	if preview.RetainedApp.ID == "" && retainedName != "" {
		for _, app := range apps {
			if app.Source == "parent" && normalizeTLPolicyText(app.Name) == normalizeTLPolicyText(retainedName) {
				preview.RetainedApp = app
				break
			}
		}
	}
	if preview.RetainedApp.ID == "" {
		osType := 1
		if len(preview.SourceApps) > 0 && preview.SourceApps[0].OSType > 0 {
			osType = preview.SourceApps[0].OSType
		}
		preview.RetainedApp = model.TLApplication{
			Name:           retainedName,
			Source:         "parent",
			OrganizationID: parent.OrgID,
			OSType:         osType,
		}
		preview.Warnings = append(preview.Warnings,
			"A child policy must be promoted to Global before ThreatLocker will create the parent-owned merge target.")
	}

	ruleKeys := map[string]bool{}
	for _, app := range preview.SourceApps {
		if app.ID == preview.RetainedApp.ID {
			continue
		}
		appAuth := parent
		appAuth.OrgID = app.OrganizationID
		files, err := s.tl.ApplicationFilesForAuth(ctx, appAuth, app.ID, app.OSType)
		if err != nil {
			return preview, "", err
		}
		for _, file := range files {
			ruleKeys[tlFileRuleKey(file)] = true
		}
	}
	if preview.RetainedApp.ID != "" {
		retainedAuth := parent
		retainedAuth.OrgID = preview.RetainedApp.OrganizationID
		files, err := s.tl.ApplicationFilesForAuth(ctx, retainedAuth, preview.RetainedApp.ID, preview.RetainedApp.OSType)
		if err != nil {
			return preview, "", err
		}
		for _, file := range files {
			ruleKeys[tlFileRuleKey(file)] = true
		}
	}
	preview.FileRuleCount = len(ruleKeys)

	policiesByID := map[string]model.TLPolicy{}
	policyOrder := []string{}
	policiesByApp := map[string][]model.TLPolicy{}
	addPolicies := func(appID string, policies []model.TLPolicy) {
		policiesByApp[appID] = policies
		for _, policy := range policies {
			if policy.ID == "" {
				continue
			}
			if _, ok := policiesByID[policy.ID]; !ok {
				policyOrder = append(policyOrder, policy.ID)
			}
			policiesByID[policy.ID] = policy
		}
	}
	candidateAppIDs := []string{}
	if preview.RetainedApp.ID != "" {
		candidateAppIDs = append(candidateAppIDs, preview.RetainedApp.ID)
	}
	for _, app := range preview.SourceApps {
		candidateAppIDs = append(candidateAppIDs, app.ID)
	}
	for _, appID := range cleanTLIDs(candidateAppIDs) {
		appAuth := parent
		if app, ok := appByID[appID]; ok && strings.TrimSpace(app.OrganizationID) != "" {
			appAuth.OrgID = app.OrganizationID
		} else if appID == preview.RetainedApp.ID && strings.TrimSpace(preview.RetainedApp.OrganizationID) != "" {
			appAuth.OrgID = preview.RetainedApp.OrganizationID
		}
		policies, err := s.tl.PoliciesForApplicationForAuth(ctx, appAuth, appID)
		if err != nil {
			return preview, "", err
		}
		addPolicies(appID, policies)
	}

	if req.RetainedPolicyID != "" {
		id := strings.TrimSpace(req.RetainedPolicyID)
		if policy, ok := policiesByID[id]; ok {
			preview.RetainedPolicy = policy
		} else if detail, err := s.tl.Policy(ctx, tenantID, id); err == nil {
			preview.RetainedPolicy = tlPolicySummaryFromDetail(detail)
			policiesByID[id] = preview.RetainedPolicy
			policyOrder = append(policyOrder, id)
		} else {
			preview.Blocked = append(preview.Blocked, "Retained policy "+id+" was not found.")
		}
	}
	if preview.RetainedPolicy.ID != "" && !isParentPolicy(preview.RetainedPolicy) {
		preview.Warnings = append(preview.Warnings,
			"The selected managed-organization policy will be moved to the exact Global group after the native application merge.")
	}
	if preview.RetainedPolicy.ID == "" && preview.RetainedApp.ID != "" {
		for _, policy := range policiesByApp[preview.RetainedApp.ID] {
			if isParentPolicy(policy) {
				preview.RetainedPolicy = policy
				break
			}
		}
	}
	if preview.RetainedPolicy.ID == "" {
		for _, id := range policyOrder {
			if isParentPolicy(policiesByID[id]) {
				preview.RetainedPolicy = policiesByID[id]
				break
			}
		}
	}
	if preview.RetainedPolicy.ID == "" {
		preview.Warnings = append(preview.Warnings,
			"After the native merge, each preserved managed-organization policy will be moved to the exact Global group.")
	}
	preview.PolicyCount = len(policyOrder)
	for _, id := range policyOrder {
		if p := policiesByID[id]; isPushedCopy(p) {
			preview.Warnings = append(preview.Warnings,
				"Policy \""+p.Name+"\" is a copy applied into a managed organization by its parent policy; it follows that policy and is not deleted directly.")
			continue
		}
		preview.PreservedPolicies = append(preview.PreservedPolicies, policiesByID[id])
	}
	if preview.RetainedApp.ID == "" {
		for _, app := range preview.SourceApps {
			for _, policy := range policiesByApp[app.ID] {
				if policy.ID == "" || isPushedCopy(policy) || strings.TrimSpace(app.OrganizationID) == "" {
					continue
				}
				preview.ParentPromotion = &model.TLAppParentPromotion{
					ApplicationID:             app.ID,
					ApplicationName:           app.Name,
					ApplicationOrganizationID: app.OrganizationID,
					SourceOrganizationID:      app.OrganizationID,
					PolicyID:                  policy.ID,
					PolicyName:                policy.Name,
					DestinationGroupID:        preview.GlobalDestination.ID,
					DestinationGroupName:      preview.GlobalDestination.Name,
					ParentOrganizationID:      parent.OrgID,
					OSType:                    app.OSType,
				}
				break
			}
			if preview.ParentPromotion != nil {
				break
			}
		}
		if preview.ParentPromotion == nil {
			preview.Blocked = append(preview.Blocked,
				"No selected child application has an attached policy that can create the parent-owned application.")
		} else {
			preview.Blocked = append(preview.Blocked,
				"A parent-owned application is required. Promote the proposed child policy to Global, then refresh this preview.")
		}
	}
	for _, app := range preview.SourceApps {
		if app.ID != "" && app.ID != preview.RetainedApp.ID {
			preview.DeleteAppIDs = append(preview.DeleteAppIDs, app.ID)
		}
	}
	return preview, "", nil
}

func (s *Server) threatLockerScopeName(ctx context.Context, tenantID string) (string, error) {
	if strings.TrimSpace(tenantID) == "" {
		return "ThreatLocker Global", nil
	}
	t, err := s.store.Tenant(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return t.Name, nil
}

// tlFileRuleKey identifies a file rule by its match conditions: the hash for
// hash-only rules, else the path/created-by/cert combination.
func tlFileRuleKey(f model.TLApplicationFile) string {
	if h := strings.TrimSpace(f.Hash); h != "" {
		return "hash:" + strings.ToUpper(h)
	}
	return strings.ToLower(strings.Join([]string{"cond", f.FullPath, f.ProcessPath, f.InstalledBy, f.Cert}, "|"))
}

func cleanTLIDs(ids []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func tlAppCleanupFingerprint(req model.TLAppCleanupRequest, preview model.TLAppCleanupPreview) string {
	sourceIDs := cleanTLIDs(req.AppIDs)
	sort.Strings(sourceIDs)
	canonical := strings.Join([]string{
		strings.Join(sourceIDs, ","),
		strings.TrimSpace(preview.RetainedApp.ID),
		strings.ToLower(strings.TrimSpace(preview.RetainedApp.Name)),
		strings.TrimSpace(preview.RetainedPolicy.ID),
		fmt.Sprintf("%t", req.ConfirmDelete),
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("cleanup:%x", sum)
}

func tlParentPromotionFingerprint(proposal model.TLAppParentPromotion) string {
	canonical := strings.Join([]string{
		strings.TrimSpace(proposal.PolicyID),
		strings.TrimSpace(proposal.ApplicationID),
		strings.TrimSpace(proposal.ApplicationOrganizationID),
		strings.TrimSpace(proposal.SourceOrganizationID),
		strings.TrimSpace(proposal.DestinationGroupID),
		strings.TrimSpace(proposal.ParentOrganizationID),
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("parent-promotion:%x", sum)
}

func tlPolicySummaryFromDetail(detail model.TLPolicyDetail) model.TLPolicy {
	status := detail.Status
	if status == "" {
		status = "Enabled"
	}
	return model.TLPolicy{
		ID:             detail.ID,
		Name:           detail.Name,
		Action:         detail.Action,
		PolicyActionID: detail.PolicyActionID,
		AppliesTo:      detail.AppliesTo,
		Status:         status,
		AllUsers:       detail.Raw != nil && detail.Raw["allUserGroups"] == true,
		MonitorMode:    detail.MonitorMode,
		OrganizationID: detail.OrganizationID,
	}
}

func cleanTLPolicyCreateRaw(raw map[string]any) map[string]any {
	if raw == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range raw {
		switch k {
		case "policyId", "id":
			continue
		default:
			out[k] = v
		}
	}
	return out
}

func (s *Server) getTLPolicy(w http.ResponseWriter, r *http.Request) {
	// orgId addresses a policy that lives in a child organization — the Apps
	// tab's per-application policy list spans child orgs, and the portal only
	// serves PolicyGetById inside the owning org.
	v, err := s.tl.PolicyInOrg(r.Context(), chi.URLParam(r, "tenantId"), chi.URLParam(r, "policyId"),
		r.URL.Query().Get("orgId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (s *Server) updateTLPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, policyID := chi.URLParam(r, "tenantId"), chi.URLParam(r, "policyId")
	scopeName, err := s.threatLockerScopeName(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var patch model.TLPolicyPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	patch.ID = policyID
	token := patch.ApprovalToken
	patch.ApprovalToken = ""
	if !s.consumeApproval(w, r, token, patch) {
		return
	}
	updated, err := s.tl.UpdatePolicy(r.Context(), tenantID, patch)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.policy.update", Resource: scopeName + " / " + updated.Name,
		Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, updated)
}

func (s *Server) previewTLPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	var patch model.TLPolicyPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	patch.ID = chi.URLParam(r, "policyId")
	patch.ApprovalToken = ""
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"approvalToken": s.issueApproval(r, patch), "summary": "Update ThreatLocker policy " + patch.ID})
}

func (s *Server) promoteTLPolicyGlobal(w http.ResponseWriter, r *http.Request) {
	tenantID, policyID := chi.URLParam(r, "tenantId"), chi.URLParam(r, "policyId")
	var body struct {
		ApprovalToken string `json:"approvalToken"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !s.consumeApproval(w, r, body.ApprovalToken, map[string]string{"policyId": policyID}) {
		return
	}
	scopeName, err := s.threatLockerScopeName(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	result, err := s.consolidateTLPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.policy.promote_global", Resource: scopeName + " / " + result.Name,
		Result: result.Status, CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) previewTLPolicyPromote(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "policyId")
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"approvalToken": s.issueApproval(r, map[string]string{"policyId": policyID}), "summary": "Promote ThreatLocker policy " + policyID + " globally"})
}

func (s *Server) promoteTLPolicyTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string `json:"tenantId"`
		PolicyID    string `json:"policyId"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if body.TenantID == "" || body.PolicyID == "" {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "tenantId and policyId are required.")
		return
	}
	pol, err := s.tl.Policy(r.Context(), body.TenantID, body.PolicyID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	if strings.TrimSpace(body.Name) != "" {
		pol.Name = strings.TrimSpace(body.Name)
	}
	if body.Description != "" {
		pol.Description = body.Description
	}
	tpl := s.savePolicyTemplate("promoted:"+body.TenantID+":"+body.PolicyID, pol)
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.policy.template_promote", Resource: tpl.Name,
		Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, tpl)
}

func (s *Server) mergeTLPolicyTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantID    string   `json:"tenantId"`
		PolicyIDs   []string `json:"policyIds"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	if body.TenantID == "" || len(body.PolicyIDs) == 0 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "tenantId and at least one policyId are required.")
		return
	}
	base, err := s.tl.Policy(r.Context(), body.TenantID, body.PolicyIDs[0])
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	ids := append([]string{}, base.ApplicationIDs...)
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	for _, policyID := range body.PolicyIDs[1:] {
		p, err := s.tl.Policy(r.Context(), body.TenantID, policyID)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		for _, id := range p.ApplicationIDs {
			if !seen[id] {
				seen[id], ids = true, append(ids, id)
			}
		}
	}
	if strings.TrimSpace(body.Name) != "" {
		base.Name = strings.TrimSpace(body.Name)
	}
	if body.Description != "" {
		base.Description = body.Description
	}
	base.ApplicationIDs = ids
	if base.Raw == nil {
		base.Raw = map[string]any{}
	}
	base.Raw["applicationIdList"] = ids
	tpl := s.savePolicyTemplate("merged:"+body.TenantID, base)
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.policy.template_merge", Resource: tpl.Name,
		Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, tpl)
}

func (s *Server) deployTLPolicyTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "templateId")
	var body struct {
		TenantIDs     []string `json:"tenantIds"`
		All           bool     `json:"all"`
		ApprovalToken string   `json:"approvalToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	token := body.ApprovalToken
	body.ApprovalToken = ""
	if !s.consumeApproval(w, r, token, struct {
		TemplateID string   `json:"templateId"`
		TenantIDs  []string `json:"tenantIds"`
		All        bool     `json:"all"`
	}{templateID, body.TenantIDs, body.All}) {
		return
	}
	tpl, ok := s.policyTemplate(templateID)
	if !ok {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.CodeObjectNotFound, "The requested policy template was not found.")
		return
	}
	result := model.TLPolicyDeployResult{
		TemplateID: templateID,
		Status:     "Completed",
		Succeeded:  []string{},
		Failed:     []string{},
	}
	if _, err := s.ensureTLPolicyTemplate(r.Context(), "", tpl.Policy); err != nil {
		result.Failed = append(result.Failed, fmt.Sprintf("global workspace: %v", err))
	} else {
		result.Succeeded = append(result.Succeeded, "global workspace")
	}
	switch {
	case len(result.Succeeded) == 0:
		result.Status = "Failed"
	case len(result.Failed) > 0:
		result.Status = "Partial"
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "threatlocker.policy.template_deploy", Resource: tpl.Name,
		Result: result.Status, CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) previewTLPolicyTemplateDeploy(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "templateId")
	var body struct {
		TenantIDs []string `json:"tenantIds"`
		All       bool     `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid request body.")
		return
	}
	payload := struct {
		TemplateID string   `json:"templateId"`
		TenantIDs  []string `json:"tenantIds"`
		All        bool     `json:"all"`
	}{templateID, body.TenantIDs, body.All}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"approvalToken": s.issueApproval(r, payload), "summary": "Deploy ThreatLocker policy template " + templateID})
}

func (s *Server) ensureTLPolicyTemplate(ctx context.Context, tenantID string, tpl model.TLPolicyDetail) (model.TLPolicyDetail, error) {
	policies, err := s.tl.Policies(ctx, tenantID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	for _, p := range policies {
		if sameTLPolicyFamily(p.Name, p.Action, tpl.Name, tpl.Action) {
			result, err := s.consolidateTLPolicy(ctx, tenantID, p.ID)
			if err != nil {
				return model.TLPolicyDetail{}, err
			}
			return s.tl.Policy(ctx, tenantID, result.PolicyID)
		}
	}
	created, err := s.tl.CreatePolicy(ctx, tenantID, tpl)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	return s.consolidateTLPolicyDetail(ctx, tenantID, created)
}

func (s *Server) consolidateTLPolicy(ctx context.Context, tenantID, policyID string) (model.TLPolicyConsolidateResult, error) {
	base, err := s.tl.Policy(ctx, tenantID, policyID)
	if err != nil {
		return model.TLPolicyConsolidateResult{}, err
	}
	return s.consolidateTLPolicyDetailResult(ctx, tenantID, base)
}

func (s *Server) consolidateTLPolicyDetail(ctx context.Context, tenantID string, base model.TLPolicyDetail) (model.TLPolicyDetail, error) {
	result, err := s.consolidateTLPolicyDetailResult(ctx, tenantID, base)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	return s.tl.Policy(ctx, tenantID, result.PolicyID)
}

func (s *Server) consolidateTLPolicyDetailResult(ctx context.Context, tenantID string, base model.TLPolicyDetail) (model.TLPolicyConsolidateResult, error) {
	policies, err := s.tl.Policies(ctx, tenantID)
	if err != nil {
		return model.TLPolicyConsolidateResult{}, err
	}
	apps := append([]string{}, base.ApplicationIDs...)
	seenApps := map[string]bool{}
	for _, id := range apps {
		seenApps[id] = true
	}
	result := model.TLPolicyConsolidateResult{
		PolicyID:          base.ID,
		Name:              base.Name,
		Status:            "Completed",
		MergedPolicyIDs:   []string{},
		DisabledPolicyIDs: []string{},
		Failed:            []string{},
	}
	duplicateIDs := []string{}
	for _, p := range policies {
		if p.ID == base.ID || !sameTLPolicyFamily(p.Name, p.Action, base.Name, base.Action) {
			continue
		}
		duplicateIDs = append(duplicateIDs, p.ID)
		result.MergedPolicyIDs = append(result.MergedPolicyIDs, p.ID)
		detail, err := s.tl.Policy(ctx, tenantID, p.ID)
		if err != nil {
			return model.TLPolicyConsolidateResult{}, err
		}
		for _, id := range detail.ApplicationIDs {
			if !seenApps[id] {
				seenApps[id], apps = true, append(apps, id)
			}
		}
	}
	enabled, all, emptyGroup := true, true, ""
	if _, err := s.tl.UpdatePolicy(ctx, tenantID, model.TLPolicyPatch{
		ID: base.ID, IsEnabled: &enabled, AllDevices: &all, AllUserGroups: &all,
		ComputerGroupID: &emptyGroup, ApplicationIDs: apps,
	}); err != nil {
		return model.TLPolicyConsolidateResult{}, err
	}
	disabled := false
	for _, id := range duplicateIDs {
		if _, err := s.tl.UpdatePolicy(ctx, tenantID, model.TLPolicyPatch{ID: id, IsEnabled: &disabled}); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		result.DisabledPolicyIDs = append(result.DisabledPolicyIDs, id)
	}
	if len(result.Failed) > 0 {
		result.Status = "Partial"
	}
	return result, nil
}

func sameTLPolicyFamily(leftName, leftAction, rightName, rightAction string) bool {
	return normalizeTLPolicyText(leftName) == normalizeTLPolicyText(rightName) &&
		normalizeTLPolicyText(leftAction) == normalizeTLPolicyText(rightAction)
}

func normalizeTLPolicyText(v string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(v))), " ")
}

func (s *Server) savePolicyTemplate(source string, pol model.TLPolicyDetail) model.TLPolicyTemplate {
	s.templateMu.Lock()
	defer s.templateMu.Unlock()
	s.nextTemplateSeq++
	id := fmt.Sprintf("tl_tpl_%d", s.nextTemplateSeq)
	tpl := model.TLPolicyTemplate{
		ID: id, Name: pol.Name, Description: pol.Description, Source: source,
		Policy: pol, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.policyTemplates[id] = tpl
	return tpl
}

func (s *Server) policyTemplate(id string) (model.TLPolicyTemplate, bool) {
	s.templateMu.Lock()
	defer s.templateMu.Unlock()
	tpl, ok := s.policyTemplates[id]
	return tpl, ok
}

// maxMaintenanceMinutes caps enter_maintenance_mode: reduced protection must
// always have a scheduled end, at most 24 hours out.
const maxMaintenanceMinutes = 24 * 60

// resolveThreatLocker validates a ThreatLocker change request and loads the
// live state (devices or approval requests) that preview/execute plan
// against. Same contract as resolveChange: errMsg → 400, err → provider or
// store failure (ErrNotConnected included).
func (s *Server) resolveThreatLocker(r *http.Request, body *changeRequest, cc *changeContext) (string, error) {
	switch body.Action {
	case worker.ActionEnterMaintenanceMode:
		// Only the maintenance modes the portal API's disable-protection endpoint
		// accepts (Monitor Only and Learning) are offered.
		switch body.MaintenanceType {
		case threatlocker.MaintenanceMonitorOnly, threatlocker.MaintenanceLearning:
		default:
			return "Maintenance type must be monitor_only or learning.", nil
		}
		if body.DurationMinutes < 1 || body.DurationMinutes > maxMaintenanceMinutes {
			return "A maintenance duration between 1 and 1440 minutes is required.", nil
		}
	case worker.ActionApproveRequest:
		switch body.Scope {
		case threatlocker.ScopeComputer, threatlocker.ScopeGroup, threatlocker.ScopeOrganization:
		default:
			return "Scope must be computer, group, or organization.", nil
		}
		if body.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, body.ExpiresAt); err != nil {
				return "expiresAt must be an RFC3339 timestamp.", nil
			}
		}
	}

	if isDeviceAction(body.Action) {
		devices, err := s.tl.Devices(r.Context(), body.TenantID)
		if err != nil {
			return "", err
		}
		cc.devices = make(map[string]model.Device, len(devices))
		for _, d := range devices {
			cc.devices[d.ID] = d
		}
		return "", nil
	}

	// Approval actions plan against the pending queue.
	requests, err := s.tl.ApprovalRequests(r.Context(), body.TenantID, threatlocker.RequestPending)
	if err != nil {
		return "", err
	}
	cc.requests = make(map[string]model.ApprovalRequest, len(requests))
	for _, q := range requests {
		cc.requests[q.ID] = q
	}
	return "", nil
}
