package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
)

const (
	securityEventDefaultWindow = 7 * 24 * time.Hour
	securityEventMaxWindow     = 180 * 24 * time.Hour
	securityEventMaxOffset     = 10000
	securityRawMaxBytes        = 256 * 1024
	securityRuleOptionScanMax  = 5000
	securityRuleOptionValueMax = 250
)

var securityRuleCatalogWorkloads = []string{
	"AzureActiveDirectory", "Exchange", "General", "OneDrive", "SharePoint",
}

var securityRuleCatalogResults = []string{
	"Success", "Succeeded", "Failed", "Failure", "PartiallySucceeded", "Unknown",
}

var securityRuleCatalogOperations = []string{
	"Add application", "Add app role assignment to service principal", "Add authentication method",
	"Add member to group", "Add member to role", "Add named location", "Add owner to application",
	"Add owner to group", "Add owner to service principal", "Add recipient permission",
	"Add service principal", "Add service principal credentials", "Add user", "Add-RoleGroupMember", "Add domain to company", "AnonymousLinkCreated",
	"Consent to application", "Delete application", "Delete authentication method", "Delete named location", "Delete user",
	"Disable-TransportRule", "Enable-TransportRule", "FileAccessed", "FileDeleted", "FileDownloaded",
	"FileRecycled", "Invite external user", "New-InboundConnector", "New-InboxRule", "New-OutboundConnector",
	"New-TransportRule", "Remove-InboundConnector", "Remove-InboxRule", "Remove-OutboundConnector",
	"Remove-TransportRule", "Remove app role assignment from service principal", "Remove domain from company", "Remove member from group",
	"Remove member from role", "Remove owner from group", "Remove recipient permission", "Reset user password",
	"Search-UnifiedAuditLog", "SearchQueryInitiated", "SearchQueryPerformed", "SecureLinkCreated",
	"Set-AdminAuditLogConfig", "Set-AntiPhishPolicy", "Set domain authentication", "Set federation settings on domain",
	"Set-HostedContentFilterPolicy", "Set-InboundConnector", "Set-InboxRule", "Set-Mailbox",
	"Set-MailboxAuditBypassAssociation", "Set-MalwareFilterPolicy", "Set-OrganizationConfig", "Set-OutboundConnector",
	"Set-TransportRule", "SharingInvitationCreated", "SharingSet", "SiteCollectionAdminAdded",
	"SiteCollectionAdminRemoved", "Suspicious activity reported", "Update application", "Update authorization policy",
	"Update conditional access policy", "Update cross-tenant access setting", "Update domain", "Update named location",
	"Update role management policy", "Update security defaults", "Update service principal", "Update user",
	"UserLoggedIn", "UserLoginFailed", "Verify domain",
}

// These are provider field names used by RTM's supported detectors. They are
// safe substring tokens, not values copied out of raw evidence.
var securityRuleCatalogRawTerms = []string{
	"AccountEnabled", "AppRole.Value", "AuthenticationRequirement", "ClientInfoString", "ConsentContext", "Country",
	"DeliverToMailboxAndForward", "EndDateTime", "ForwardAsAttachmentTo", "ForwardTo",
	"ForwardingSmtpAddress", "ModifiedProperties", "OperationProperties", "Parameters",
	"Permission", "RedirectTo", "SessionId", "SharingType", "UserAgent", "UserType",
}

func (s *Server) searchSecurityEvents(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	query := model.SecurityAuditEventSearch{
		Query: strings.TrimSpace(r.URL.Query().Get("query")), TenantID: strings.TrimSpace(r.URL.Query().Get("tenantId")),
		Workload: strings.TrimSpace(r.URL.Query().Get("workload")), Operation: strings.TrimSpace(r.URL.Query().Get("operation")),
		Actor: strings.TrimSpace(r.URL.Query().Get("actor")), ClientIP: strings.TrimSpace(r.URL.Query().Get("clientIp")),
		Result: strings.TrimSpace(r.URL.Query().Get("result")), From: now.Add(-securityEventDefaultWindow), To: now,
		Limit: 50,
	}
	if value := r.URL.Query().Get("from"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The event-search start time must be RFC3339.")
			return
		}
		query.From = parsed.UTC()
	}
	if value := r.URL.Query().Get("to"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "The event-search end time must be RFC3339.")
			return
		}
		query.To = parsed.UTC()
	}
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Event-search limit must be a number.")
			return
		}
		query.Limit = parsed
	}
	if value := r.URL.Query().Get("offset"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Event-search offset must be a number.")
			return
		}
		query.Offset = parsed
	}
	if query.Limit < 1 || query.Limit > 100 || query.Offset < 0 || query.Offset > securityEventMaxOffset || query.To.Before(query.From) || query.To.Sub(query.From) > securityEventMaxWindow {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Search up to 100 rows within a valid 180-day window and offset no more than 10,000.")
		return
	}
	for _, value := range []string{query.Query, query.Workload, query.Operation, query.Actor, query.ClientIP, query.Result} {
		if len(value) > 256 {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Event-search values must be 256 characters or fewer.")
			return
		}
	}
	if query.TenantID != "" {
		if _, err := s.store.Tenant(r.Context(), query.TenantID); err != nil {
			s.writeErr(w, r, err)
			return
		}
	}
	events, hasMore, err := s.store.SearchSecurityAuditEvents(r.Context(), query)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	tenantNames, err := s.securityTenantNames(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	views := make([]model.SecurityAuditEventView, 0, len(events))
	for _, event := range events {
		views = append(views, securityEventView(event, tenantNames[event.TenantID]))
	}
	page := model.SecurityAuditEventPage{Events: views, Offset: query.Offset, Limit: query.Limit, WindowDays: int(query.To.Sub(query.From).Hours() / 24)}
	if hasMore {
		next := query.Offset + query.Limit
		if next <= securityEventMaxOffset {
			page.NextOffset = &next
		} else {
			page.Limited = true
		}
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.events.search", Resource: securityEventSearchResource(query), Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (s *Server) getSecurityEvent(w http.ResponseWriter, r *http.Request) {
	tenantID, eventID := chi.URLParam(r, "tenantId"), chi.URLParam(r, "eventId")
	event, err := s.store.SecurityAuditEvent(r.Context(), tenantID, eventID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	tenant, err := s.store.Tenant(r.Context(), tenantID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	detections, err := s.store.SecurityNativeDetectionsForEvent(r.Context(), tenantID, eventID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	sourceEvidence, err := s.store.SecurityAuditEventEvidence(r.Context(), tenantID, eventID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for index := range sourceEvidence {
		sourceEvidence[index].Raw, sourceEvidence[index].RawTruncated = redactSecurityRaw(sourceEvidence[index].Raw)
	}
	raw, truncated := redactSecurityRaw(event.Raw)
	detail := model.SecurityAuditEventDetail{
		SecurityAuditEventView: securityEventView(event, tenant.Name), Raw: raw,
		RawTruncated: truncated, SourceEvidence: sourceEvidence, RelatedDetections: detections,
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.event.raw_view", Resource: tenant.Name + " / " + event.Operation, Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, detail)
}

func (s *Server) listSecurityDetectionRules(w http.ResponseWriter, r *http.Request) {
	stored, err := s.store.SecurityDetectionRules(r.Context())
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	tenantNames, err := s.securityTenantNames(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	for i := range stored {
		stored[i].TenantName = tenantNames[stored[i].TenantID]
	}
	rules := append(m365audit.BuiltInRules(), stored...)
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rules.view", Resource: "All managed tenants", Result: "Success", CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusOK, rules)
}

func (s *Server) listSecurityRuleConditionOptions(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenantId"))
	resource := "All managed tenants"
	if tenantID != "" {
		tenant, err := s.store.Tenant(r.Context(), tenantID)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		resource = tenant.Name
	}

	sets := map[string]map[string]string{
		"workloads": {}, "operations": {}, "actors": {}, "clientIps": {}, "results": {}, "objects": {},
	}
	for _, value := range securityRuleCatalogWorkloads {
		addSecurityRuleOption(sets["workloads"], value)
	}
	for _, value := range securityRuleCatalogOperations {
		addSecurityRuleOption(sets["operations"], value)
	}
	for _, value := range securityRuleCatalogResults {
		addSecurityRuleOption(sets["results"], value)
	}

	now := time.Now().UTC()
	query := model.SecurityAuditEventSearch{
		TenantID: tenantID, From: now.Add(-securityEventMaxWindow), To: now, Limit: 100,
	}
	eventsScanned, limited := 0, false
	for eventsScanned < securityRuleOptionScanMax {
		events, hasMore, err := s.store.SearchSecurityAuditEvents(r.Context(), query)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		for _, event := range events {
			addSecurityRuleOption(sets["workloads"], event.Workload)
			addSecurityRuleOption(sets["operations"], event.Operation)
			addSecurityRuleOption(sets["actors"], event.Actor)
			addSecurityRuleOption(sets["clientIps"], event.ClientIP)
			addSecurityRuleOption(sets["results"], event.ResultStatus)
			addSecurityRuleOption(sets["objects"], event.ObjectID)
		}
		eventsScanned += len(events)
		if !hasMore || len(events) == 0 {
			break
		}
		query.Offset += query.Limit
		if eventsScanned >= securityRuleOptionScanMax {
			limited = true
		}
	}

	options := model.SecurityRuleConditionOptions{
		Workloads: securityRuleOptionValues(sets["workloads"]), Operations: securityRuleOptionValues(sets["operations"]),
		Actors: securityRuleOptionValues(sets["actors"]), ClientIPs: securityRuleOptionValues(sets["clientIps"]),
		Results: securityRuleOptionValues(sets["results"]), Objects: securityRuleOptionValues(sets["objects"]),
		RawEvidenceTerms: append([]string(nil), securityRuleCatalogRawTerms...), EventsScanned: eventsScanned,
		EvidenceWindowDays: int(securityEventMaxWindow.Hours() / 24), Limited: limited,
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.rule_options.view", Resource: resource,
		Result: "Success", CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, options)
}

func addSecurityRuleOption(options map[string]string, value string) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || len(options) >= securityRuleOptionValueMax {
		return
	}
	key := strings.ToLower(value)
	if _, exists := options[key]; !exists {
		options[key] = value
	}
}

func securityRuleOptionValues(options map[string]string) []string {
	values := make([]string, 0, len(options))
	for _, value := range options {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return strings.ToLower(values[i]) < strings.ToLower(values[j]) })
	return values
}

func (s *Server) getSecurityDetectionRule(w http.ResponseWriter, r *http.Request) {
	rule, err := s.resolveSecurityRule(r, chi.URLParam(r, "ruleId"))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rule.view", Resource: rule.Name, Result: "Success", CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusOK, rule)
}

func (s *Server) listSecurityDetectionRuleRevisions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "ruleId")
	if strings.HasPrefix(id, "builtin:") {
		user := auth.UserFromContext(r.Context())
		_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rule.revisions_view", Resource: id, Result: "Success", CorrelationID: httpx.CorrelationID(r.Context())})
		httpx.WriteJSON(w, http.StatusOK, []model.SecurityDetectionRuleRevision{})
		return
	}
	revisions, err := s.store.SecurityDetectionRuleRevisions(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rule.revisions_view", Resource: id, Result: "Success", CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusOK, revisions)
}

type securityRuleMutation struct {
	Rule          model.SecurityDetectionRule `json:"rule"`
	ApprovalToken string                      `json:"approvalToken,omitempty"`
}

func (s *Server) previewSecurityDetectionRule(w http.ResponseWriter, r *http.Request) {
	var body securityRuleMutation
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid rule preview body.")
		return
	}
	// A rule without a stored ID is being previewed for creation (including a
	// built-in override). Normalize it exactly as the create handler will before
	// signing the payload; otherwise create clears ID/revision and the production
	// approval fingerprint can never match the preview.
	creating := body.Rule.ID == ""
	if err := s.normalizeAndValidateSecurityRule(r, &body.Rule, creating); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, err.Error())
		return
	}
	events, err := s.store.SecurityAuditEventsSince(r.Context(), time.Now().UTC().Add(-30*24*time.Hour))
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	detections := m365audit.PreviewRule(events, body.Rule, time.Now().UTC())
	tenantNames, err := s.securityTenantNames(r)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	preview := model.SecurityRulePreview{
		MatchedEvents: len(detections), EventsScanned: len(events), TenantsMatched: map[string]int{},
		Warnings: []string{"Preview scans the latest 30 days and at most 50,000 retained events. Enabling affects future evaluation; existing incidents are not deleted."},
	}
	eventByID := make(map[string]model.SecurityAuditEvent, len(events))
	for _, event := range events {
		eventByID[event.ID] = event
	}
	seenEvents := map[string]struct{}{}
	for _, detection := range detections {
		preview.TenantsMatched[tenantNames[detection.TenantID]]++
		if len(preview.SampleEvents) >= 20 {
			continue
		}
		event, ok := eventByID[detection.EventID]
		if !ok {
			continue
		}
		if _, exists := seenEvents[event.ID]; exists {
			continue
		}
		seenEvents[event.ID] = struct{}{}
		preview.SampleEvents = append(preview.SampleEvents, securityEventView(event, tenantNames[event.TenantID]))
	}
	preview.ApprovalToken = s.issueApproval(r, body.Rule)
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{
		Actor: user.Name, Action: "security.rule.preview", Resource: body.Rule.Name, Result: fmt.Sprintf("Success — %d matches", len(detections)), CorrelationID: httpx.CorrelationID(r.Context()),
	})
	httpx.WriteJSON(w, http.StatusOK, preview)
}

func (s *Server) createSecurityDetectionRule(w http.ResponseWriter, r *http.Request) {
	var body securityRuleMutation
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid rule body.")
		return
	}
	if err := s.normalizeAndValidateSecurityRule(r, &body.Rule, true); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, err.Error())
		return
	}
	if body.Rule.Enabled || body.Rule.BaseRuleID != "" {
		if !s.consumeApproval(w, r, body.ApprovalToken, body.Rule) {
			return
		}
	} else {
		body.Rule.Enabled = false
	}
	user := auth.UserFromContext(r.Context())
	bodyID := newSecurityRuleID()
	bodyRuleID := "custom_" + bodyID
	if body.Rule.BaseRuleID != "" {
		bodyRuleID = body.Rule.BaseRuleID
	}
	rule := body.Rule
	rule.ID, rule.RuleID, rule.UpdatedBy = bodyID, bodyRuleID, user.Name
	created, err := s.store.CreateSecurityDetectionRule(r.Context(), rule)
	if errors.Is(err, store.ErrConflict) {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeValidationFailed, "A rule already exists for this scope and tenant.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rule.create", Resource: created.Name, Result: ruleAuditResult(created), CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusCreated, created)
}

func (s *Server) updateSecurityDetectionRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "ruleId")
	current, err := s.store.SecurityDetectionRule(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var body securityRuleMutation
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid rule body.")
		return
	}
	body.Rule.ID, body.Rule.RuleID, body.Rule.BaseRuleID, body.Rule.BuiltIn = current.ID, current.RuleID, current.BaseRuleID, current.BuiltIn
	if err := s.normalizeAndValidateSecurityRule(r, &body.Rule, false); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, err.Error())
		return
	}
	if current.Enabled || body.Rule.Enabled {
		if !s.consumeApproval(w, r, body.ApprovalToken, body.Rule) {
			return
		}
	}
	body.Rule.UpdatedBy = auth.UserFromContext(r.Context()).Name
	updated, err := s.store.UpdateSecurityDetectionRule(r.Context(), body.Rule, body.Rule.Revision)
	if errors.Is(err, store.ErrConflict) {
		httpx.WriteError(w, r, http.StatusConflict, httpx.CodeValidationFailed, "The rule changed after you opened it. Reload and preview the latest revision.")
		return
	}
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rule.update", Resource: updated.Name, Result: ruleAuditResult(updated), CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusOK, updated)
}

func (s *Server) restoreSecurityDetectionRuleRevision(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "ruleId")
	revisionNumber, err := strconv.Atoi(chi.URLParam(r, "revision"))
	if err != nil || revisionNumber < 1 {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid rule revision.")
		return
	}
	var body struct {
		ApprovalToken string `json:"approvalToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "Invalid restore body.")
		return
	}
	current, err := s.store.SecurityDetectionRule(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	revisions, err := s.store.SecurityDetectionRuleRevisions(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	var snapshot *model.SecurityDetectionRule
	for i := range revisions {
		if revisions[i].Revision == revisionNumber {
			copy := revisions[i].Snapshot
			snapshot = &copy
			break
		}
	}
	if snapshot == nil {
		s.writeErr(w, r, store.ErrNotFound)
		return
	}
	if current.Enabled || snapshot.Enabled {
		if !s.consumeApproval(w, r, body.ApprovalToken, *snapshot) {
			return
		}
	}
	snapshot.ID, snapshot.RuleID, snapshot.BaseRuleID, snapshot.BuiltIn = current.ID, current.RuleID, current.BaseRuleID, current.BuiltIn
	snapshot.UpdatedBy = auth.UserFromContext(r.Context()).Name
	restored, err := s.store.UpdateSecurityDetectionRule(r.Context(), *snapshot, current.Revision)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	user := auth.UserFromContext(r.Context())
	_ = s.store.AppendAudit(r.Context(), model.AuditEntry{Actor: user.Name, Action: "security.rule.restore", Resource: restored.Name, Result: fmt.Sprintf("Success — restored revision %d as revision %d", revisionNumber, restored.Revision), CorrelationID: httpx.CorrelationID(r.Context())})
	httpx.WriteJSON(w, http.StatusOK, restored)
}

func (s *Server) resolveSecurityRule(r *http.Request, id string) (model.SecurityDetectionRule, error) {
	if strings.HasPrefix(id, "builtin:") {
		for _, rule := range m365audit.BuiltInRules() {
			if rule.ID == id {
				return rule, nil
			}
		}
		return model.SecurityDetectionRule{}, store.ErrNotFound
	}
	rule, err := s.store.SecurityDetectionRule(r.Context(), id)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	if rule.TenantID != "" {
		tenant, err := s.store.Tenant(r.Context(), rule.TenantID)
		if err != nil {
			return model.SecurityDetectionRule{}, err
		}
		rule.TenantName = tenant.Name
	}
	return rule, nil
}

func (s *Server) normalizeAndValidateSecurityRule(r *http.Request, rule *model.SecurityDetectionRule, creating bool) error {
	rule.Name, rule.Description = strings.TrimSpace(rule.Name), strings.TrimSpace(rule.Description)
	rule.Scope, rule.TenantID = strings.ToLower(strings.TrimSpace(rule.Scope)), strings.TrimSpace(rule.TenantID)
	rule.Severity, rule.Confidence = strings.TrimSpace(rule.Severity), strings.ToLower(strings.TrimSpace(rule.Confidence))
	rule.DetectionType = strings.ToLower(strings.TrimSpace(rule.DetectionType))
	if len(rule.Name) < 3 || len(rule.Name) > 120 || len(rule.Description) > 1000 {
		return errors.New("Rule names must be 3–120 characters and descriptions no more than 1,000 characters")
	}
	if !oneOf(rule.Severity, "Critical", "High", "Medium", "Low", "Informational") || !oneOf(rule.Confidence, "high", "medium", "low") {
		return errors.New("Select a supported severity and confidence")
	}
	if rule.Scope != "global" && rule.Scope != "tenant" || rule.Scope == "tenant" && rule.TenantID == "" || rule.Scope == "global" && rule.TenantID != "" {
		return errors.New("Global rules cannot name a tenant; tenant-scoped rules require one tenant")
	}
	if rule.Scope == "tenant" {
		if _, err := s.store.Tenant(r.Context(), rule.TenantID); err != nil {
			return errors.New("The selected tenant does not exist")
		}
	}
	editableDefinition := false
	if rule.BaseRuleID != "" || rule.BuiltIn {
		baseID := rule.BaseRuleID
		if baseID == "" {
			baseID = rule.RuleID
		}
		var base *model.SecurityDetectionRule
		for _, candidate := range m365audit.BuiltInRules() {
			if candidate.RuleID == baseID {
				copy := candidate
				base = &copy
				break
			}
		}
		if base == nil {
			return errors.New("The built-in base rule does not exist")
		}
		rule.BaseRuleID, rule.RuleID, rule.BuiltIn, rule.Locked, rule.Override = baseID, baseID, true, true, true
		if rule.Definition.TriggerMode == "" {
			rule.Definition.TriggerMode = "builtIn"
		}
		switch rule.Definition.TriggerMode {
		case "builtIn":
			rule.DetectionType = base.DetectionType
			if rule.Definition.Threshold == 0 {
				rule.Definition.Threshold = base.Definition.Threshold
			}
			if rule.Definition.WindowMinutes == 0 {
				rule.Definition.WindowMinutes = base.Definition.WindowMinutes
			}
			rule.Definition = model.SecurityRuleDefinition{
				TriggerMode: "builtIn", Threshold: rule.Definition.Threshold, WindowMinutes: rule.Definition.WindowMinutes,
				Exclusions: rule.Definition.Exclusions,
			}
		case "custom":
			editableDefinition = true
		default:
			return errors.New("Built-in overrides must use the built-in detector or a custom event match")
		}
	} else {
		rule.BuiltIn, rule.Locked, rule.Override = false, false, false
		rule.Definition.TriggerMode = ""
		editableDefinition = true
	}
	if editableDefinition {
		if rule.DetectionType != m365audit.DetectionDirect && rule.DetectionType != m365audit.DetectionThreshold {
			return errors.New("Editable triggers support direct or threshold evaluation")
		}
		if !customRuleHasCondition(rule.Definition) {
			return errors.New("Add at least one workload, operation, actor, IP, result, object, or raw-text condition")
		}
		if rule.Definition.OperationMatch == "" {
			rule.Definition.OperationMatch = "contains"
		}
		if !oneOf(rule.Definition.OperationMatch, "exact", "contains") {
			return errors.New("Operation matching must be exact or contains")
		}
		if rule.DetectionType == m365audit.DetectionThreshold {
			if rule.Definition.Threshold < 2 || rule.Definition.Threshold > 10000 || rule.Definition.WindowMinutes < 1 || rule.Definition.WindowMinutes > 1440 || !oneOf(rule.Definition.GroupBy, "actor", "clientIp", "objectId", "tenant") {
				return errors.New("Threshold rules require 2–10,000 events, a 1–1,440 minute window, and a supported group-by field")
			}
		}
	}
	if len(rule.Definition.Exclusions) > 50 {
		return errors.New("A rule can contain at most 50 exclusions")
	}
	for _, exclusion := range rule.Definition.Exclusions {
		if !oneOf(exclusion.Field, "actor", "clientIp", "objectId", "tenantId") || !oneOf(exclusion.Match, "exact", "contains") || strings.TrimSpace(exclusion.Value) == "" || len(exclusion.Value) > 256 {
			return errors.New("Exclusions require a supported field, exact/contains matching, and a value no longer than 256 characters")
		}
	}
	conditionLists := [][]string{rule.Definition.Workloads, rule.Definition.Operations, rule.Definition.Actors, rule.Definition.ClientIPs, rule.Definition.Results, rule.Definition.ObjectContains, rule.Definition.RawContains}
	for _, values := range conditionLists {
		if len(values) > 50 {
			return errors.New("A rule condition can contain at most 50 values")
		}
	}
	for _, value := range append(append(append(append(append(append(append([]string{}, rule.Definition.Workloads...), rule.Definition.Operations...), rule.Definition.Actors...), rule.Definition.ClientIPs...), rule.Definition.Results...), rule.Definition.ObjectContains...), rule.Definition.RawContains...) {
		if strings.TrimSpace(value) == "" || len(value) > 256 {
			return errors.New("Rule condition values must be non-empty and 256 characters or fewer")
		}
	}
	if len(rule.Definition.RawContains) > 10 {
		return errors.New("A rule can contain at most 10 raw-evidence terms")
	}
	if creating {
		rule.ID, rule.Revision = "", 0
	}
	return nil
}

func securityEventView(event model.SecurityAuditEvent, tenantName string) model.SecurityAuditEventView {
	return model.SecurityAuditEventView{
		ID: event.ID, TenantID: event.TenantID, TenantName: tenantName, ProviderRecordID: event.ProviderRecordID,
		ContentType: event.ContentType, Workload: event.Workload, Operation: event.Operation,
		Actor: event.Actor, ClientIP: event.ClientIP, ObjectID: event.ObjectID, ResultStatus: event.ResultStatus,
		OccurredAt: event.OccurredAt, AvailableAt: event.AvailableAt, IngestedAt: event.IngestedAt,
		Sources: append([]string(nil), event.Sources...), Sample: event.Sample,
		HistoricalImport: slices.Contains(event.Sources, "historical_backfill"),
	}
}

func (s *Server) securityTenantNames(r *http.Request) (map[string]string, error) {
	tenants, err := s.store.Tenants(r.Context())
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(tenants))
	for _, tenant := range tenants {
		out[tenant.ID] = tenant.Name
	}
	return out, nil
}

func redactSecurityRaw(raw json.RawMessage) (json.RawMessage, bool) {
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return json.RawMessage(`{"_unavailable":"Provider evidence was not valid JSON."}`), false
	}
	value = redactSecurityValue(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{"_unavailable":"Provider evidence could not be formatted."}`), false
	}
	if len(encoded) > securityRawMaxBytes {
		return json.RawMessage(`{"_truncated":true,"message":"Redacted provider evidence exceeded the 256 KiB response limit. Use normalized fields and narrower event evidence."}`), true
	}
	return encoded, false
}

func redactSecurityValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		dangerousParameter := false
		for key, child := range typed {
			if strings.EqualFold(key, "name") {
				dangerousParameter = sensitiveEvidenceKey(fmt.Sprint(child))
			}
		}
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			if sensitiveEvidenceKey(key) || dangerousParameter && strings.EqualFold(key, "value") {
				out[key] = "[REDACTED]"
			} else {
				out[key] = redactSecurityValue(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = redactSecurityValue(typed[i])
		}
		return out
	default:
		return value
	}
}

func sensitiveEvidenceKey(value string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(value))
	for _, marker := range []string{"accesstoken", "refreshtoken", "authorization", "clientsecret", "password", "assertion", "sessionkey", "cookie", "setcookie"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func customRuleHasCondition(definition model.SecurityRuleDefinition) bool {
	return len(definition.Workloads)+len(definition.Operations)+len(definition.Actors)+len(definition.ClientIPs)+len(definition.Results)+len(definition.ObjectContains)+len(definition.RawContains) > 0
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func newSecurityRuleID() string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return "rule_" + hex.EncodeToString(value)
}

func securityEventSearchResource(query model.SecurityAuditEventSearch) string {
	tenant := query.TenantID
	if tenant == "" {
		tenant = "all"
	}
	return fmt.Sprintf("tenant:%s window:%s..%s offset:%d limit:%d", tenant, query.From.Format(time.RFC3339), query.To.Format(time.RFC3339), query.Offset, query.Limit)
}

func ruleAuditResult(rule model.SecurityDetectionRule) string {
	state := "Draft"
	if rule.Enabled {
		state = "Enabled"
	}
	return fmt.Sprintf("Success — %s revision %d", state, rule.Revision)
}
