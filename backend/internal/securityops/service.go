// Package securityops builds RTM's cross-tenant Microsoft security view. It
// deliberately separates provider incidents/evidence from RTM-owned state:
// Microsoft Defender XDR is read on demand while PostgreSQL stores the first
// RTM observation time plus the local owner/status overlay.
package securityops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/model"
	attackstorylines "github.com/rarity/rtm/internal/storylines"
)

const (
	defenderConnectorKey  = "defender_xdr"
	defenderConnectorName = "Microsoft Defender XDR"
	defenderPermission    = "SecurityIncident.Read.All"
	auditConnectorKey     = "m365_audit"
	auditConnectorName    = "Microsoft 365 Audit"
	auditPermission       = "ActivityFeed.Read"
	auditWorkloadCount    = 4
	fastConnectorKey      = "entra_fast_identity"
	fastConnectorName     = "Entra fast identity"
	fastPermission        = "AuditLog.Read.All"
	fastWorkloadCount     = 2
	maxConcurrentTenants  = 4
	maxConcurrentTriage   = 4
)

var ErrInvalidTriageStatus = errors.New("invalid security incident triage status")

type Store interface {
	Tenants(ctx context.Context) ([]model.Tenant, error)
	Tenant(ctx context.Context, id string) (model.Tenant, error)
	SecurityIncidentStates(ctx context.Context) ([]model.SecurityIncidentState, error)
	ObserveSecurityIncident(ctx context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error)
	UpsertSecurityIncidentState(ctx context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error)
	SecurityAuditCheckpoints(ctx context.Context) ([]model.SecurityAuditCheckpoint, error)
	SecurityHistoryImports(ctx context.Context) ([]model.SecurityHistoryImport, error)
	SecurityAuditEventsByIDs(ctx context.Context, eventIDs []string) ([]model.SecurityAuditEvent, error)
	SecurityAuditEvent(ctx context.Context, tenantID, eventID string) (model.SecurityAuditEvent, error)
	SecurityNativeDetections(ctx context.Context) ([]model.SecurityNativeDetection, error)
	SecurityNativeDetectionsByIDs(ctx context.Context, detectionIDs []string) ([]model.SecurityNativeDetection, error)
	SecurityNativeDetection(ctx context.Context, tenantID, id string) (model.SecurityNativeDetection, error)
	SecurityStorylines(ctx context.Context) ([]model.SecurityStoryline, error)
	SecurityStoryline(ctx context.Context, id string) (model.SecurityStoryline, error)
	UpdateSecurityStorylineState(ctx context.Context, id, status, owner, actor string) (model.SecurityStoryline, error)
}

type Service struct {
	store    Store
	provider graph.Provider
	log      *slog.Logger
}

type IncidentReference struct {
	TenantID   string
	IncidentID string
}

type BulkTriageOptions struct {
	Status *string
	Accept bool
	Actor  string
}

type BulkTriageOutcome struct {
	Reference IncidentReference
	Incident  model.SecurityIncidentDetail
	Err       error
}

func New(st Store, provider graph.Provider, log *slog.Logger) *Service {
	return &Service{store: st, provider: provider, log: log}
}

type tenantSecurityResult struct {
	feed model.SecurityIncidentFeed
	err  error
}

func (s *Service) Snapshot(ctx context.Context) (model.SecurityOperationsSnapshot, error) {
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		return model.SecurityOperationsSnapshot{}, err
	}
	checkpoints, err := s.store.SecurityAuditCheckpoints(ctx)
	if err != nil {
		return model.SecurityOperationsSnapshot{}, err
	}
	historyImports, err := s.store.SecurityHistoryImports(ctx)
	if err != nil {
		return model.SecurityOperationsSnapshot{}, err
	}
	detections, err := s.store.SecurityNativeDetections(ctx)
	if err != nil {
		return model.SecurityOperationsSnapshot{}, err
	}
	storylines, err := s.store.SecurityStorylines(ctx)
	if err != nil {
		return model.SecurityOperationsSnapshot{}, err
	}
	eventIDs := make([]string, 0, len(detections))
	for _, detection := range detections {
		eventIDs = append(eventIDs, detection.EventID)
	}
	events, err := s.store.SecurityAuditEventsByIDs(ctx, eventIDs)
	if err != nil {
		return model.SecurityOperationsSnapshot{}, err
	}
	evidenceByEvent := make(map[string]*model.SecurityEvidenceSummary, len(events))
	for _, event := range events {
		evidenceByEvent[event.ID] = summarizeSecurityEvent(event)
	}
	results := make([]tenantSecurityResult, len(tenants))
	sem := make(chan struct{}, maxConcurrentTenants)
	var wg sync.WaitGroup
	for i, tenant := range tenants {
		wg.Add(1)
		go func(index int, tenantID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[index].feed, results[index].err = s.provider.SecurityIncidents(ctx, tenantID)
		}(i, tenant.ID)
	}
	wg.Wait()

	snapshotAt := time.Now().UTC()
	now := snapshotAt.Format(time.RFC3339)
	snapshot := model.SecurityOperationsSnapshot{
		GeneratedAt: now,
		Coverage:    []model.SecurityCoverage{},
		Incidents:   []model.SecurityIncident{},
		Warnings:    []string{},
		Severity: []model.SecuritySeverityCount{
			{Severity: "Critical"}, {Severity: "High"}, {Severity: "Medium"},
			{Severity: "Low"}, {Severity: "Informational"}, {Severity: "Unknown"},
		},
		HistoryImports: historyImports,
		Storylines:     storylines,
	}
	connector := model.SecurityConnectorSummary{
		Key: defenderConnectorKey, Name: defenderConnectorName,
		RequiredPermission: defenderPermission,
	}
	auditConnector := model.SecurityConnectorSummary{
		Key: auditConnectorKey, Name: auditConnectorName, RequiredPermission: auditPermission,
	}
	fastConnector := model.SecurityConnectorSummary{
		Key: fastConnectorKey, Name: fastConnectorName, RequiredPermission: fastPermission,
	}
	checkpointsByTenant := make(map[string][]model.SecurityAuditCheckpoint)
	for _, checkpoint := range checkpoints {
		checkpointsByTenant[checkpoint.TenantID] = append(checkpointsByTenant[checkpoint.TenantID], checkpoint)
	}
	coveredTenants, liveTenants, sampleTenants := map[string]bool{}, map[string]bool{}, map[string]bool{}

	for i, tenant := range tenants {
		result := results[i]
		auditCheckpoints, fastCheckpoints := splitAuditCheckpoints(checkpointsByTenant[tenant.ID])
		fastCoverage := connectorCoverageForTenant(tenant, fastCheckpoints, now, fastConnectorKey, fastConnectorName, fastPermission, fastWorkloadCount,
			"Entra fast identity ingestion has not completed its first run yet.", "Graph identity records are polling every minute across both feeds.")
		snapshot.Coverage = append(snapshot.Coverage, fastCoverage)
		switch fastCoverage.Status {
		case "healthy":
			fastConnector.HealthyTenants++
			coveredTenants[tenant.ID], liveTenants[tenant.ID] = true, true
		case "sample":
			fastConnector.SampleTenants++
			coveredTenants[tenant.ID], sampleTenants[tenant.ID] = true, true
		default:
			fastConnector.AttentionTenants++
			if len(fastCheckpoints) > 0 {
				snapshot.Warnings = append(snapshot.Warnings, tenant.Name+": "+fastCoverage.Detail)
			}
		}
		auditCoverage := auditCoverageForTenant(tenant, auditCheckpoints, now)
		snapshot.Coverage = append(snapshot.Coverage, auditCoverage)
		switch auditCoverage.Status {
		case "healthy":
			auditConnector.HealthyTenants++
			coveredTenants[tenant.ID], liveTenants[tenant.ID] = true, true
		case "sample":
			auditConnector.SampleTenants++
			coveredTenants[tenant.ID], sampleTenants[tenant.ID] = true, true
		default:
			auditConnector.AttentionTenants++
			// A missing checkpoint only means the periodic worker has not
			// completed its first run. Surface it in coverage without turning
			// normal startup into a warning.
			if len(checkpointsByTenant[tenant.ID]) > 0 {
				snapshot.Warnings = append(snapshot.Warnings, tenant.Name+": "+auditCoverage.Detail)
			}
		}
		coverage := model.SecurityCoverage{
			TenantID: tenant.ID, TenantName: tenant.Name,
			ConnectorKey: defenderConnectorKey, ConnectorName: defenderConnectorName,
			RequiredPermission: defenderPermission, CheckedAt: now,
		}
		if result.err != nil {
			coverage.Status, coverage.Detail = providerCoverageError(result.err)
			connector.AttentionTenants++
			snapshot.Warnings = append(snapshot.Warnings, tenant.Name+": "+coverage.Detail)
			s.log.Warn("security operations: tenant incident feed unavailable", "tenant", tenant.Name, "error", result.err)
			snapshot.Coverage = append(snapshot.Coverage, coverage)
			continue
		}

		switch result.feed.Mode {
		case "sample":
			coverage.Status = "sample"
			coverage.Detail = "Sample Defender incidents — no live security connection is active for this tenant."
			connector.SampleTenants++
			sampleTenants[tenant.ID] = true
		case "live":
			coverage.Status = "healthy"
			coverage.Detail = "Microsoft Defender XDR incidents are readable."
			connector.HealthyTenants++
			liveTenants[tenant.ID] = true
		default:
			coverage.Status = "degraded"
			coverage.Detail = "The security provider returned an unknown connection mode."
			connector.AttentionTenants++
			snapshot.Warnings = append(snapshot.Warnings, tenant.Name+": "+coverage.Detail)
			snapshot.Coverage = append(snapshot.Coverage, coverage)
			continue
		}
		coveredTenants[tenant.ID] = true
		if result.feed.Truncated {
			warning := tenant.Name + ": showing the newest 100 Defender incidents; older incidents are not loaded in Phase 1."
			snapshot.Warnings = append(snapshot.Warnings, warning)
		}
		snapshot.Coverage = append(snapshot.Coverage, coverage)

		for _, incident := range result.feed.Incidents {
			incident.TenantID, incident.TenantName = tenant.ID, tenant.Name
			incident, err = s.observeIncident(ctx, incident, snapshotAt)
			if err != nil {
				return model.SecurityOperationsSnapshot{}, fmt.Errorf("record RTM incident receipt: %w", err)
			}
			snapshot.Incidents = append(snapshot.Incidents, incident)
		}
	}
	for _, detection := range detections {
		tenantName := "Unknown tenant"
		for _, tenant := range tenants {
			if tenant.ID == detection.TenantID {
				tenantName = tenant.Name
				break
			}
		}
		incident := nativeIncident(detection, tenantName, evidenceByEvent[detection.EventID])
		incident, err = s.observeIncident(ctx, incident, detection.CreatedAt.UTC())
		if err != nil {
			return model.SecurityOperationsSnapshot{}, fmt.Errorf("record RTM native incident receipt: %w", err)
		}
		snapshot.Incidents = append(snapshot.Incidents, incident)
	}

	snapshot.Summary.TenantsTotal = len(tenants)
	snapshot.Summary.TenantsCovered = len(coveredTenants)
	snapshot.Summary.LiveTenants = len(liveTenants)
	for tenantID := range sampleTenants {
		if !liveTenants[tenantID] {
			snapshot.Summary.SampleTenants++
		}
	}
	if len(tenants) > 0 {
		snapshot.Summary.IngestionHealth = snapshot.Summary.TenantsCovered * 100 / len(tenants)
	}
	connector.Status = connectorStatus(connector)
	auditConnector.Status = connectorStatus(auditConnector)
	fastConnector.Status = connectorStatus(fastConnector)
	snapshot.Connectors = []model.SecurityConnectorSummary{
		connector,
		fastConnector,
		auditConnector,
		{Key: "entra_id_protection", Name: "Entra ID Protection", Status: "planned", RequiredPermission: "IdentityRiskEvent.Read.All"},
	}

	for _, incident := range snapshot.Incidents {
		if incident.Status == model.SecurityTriageResolved || incident.Status == model.SecurityTriageDismissed {
			continue
		}
		snapshot.Summary.Open++
		switch incident.Severity {
		case "Critical":
			snapshot.Summary.Critical++
		case "High":
			snapshot.Summary.High++
		}
		for i := range snapshot.Severity {
			if snapshot.Severity[i].Severity == incident.Severity {
				snapshot.Severity[i].Count++
				break
			}
		}
	}
	sort.SliceStable(snapshot.Incidents, func(i, j int) bool {
		return snapshot.Incidents[i].RTMReceivedAt > snapshot.Incidents[j].RTMReceivedAt
	})
	return snapshot, nil
}

func (s *Service) Storyline(ctx context.Context, storylineID string) (model.SecurityStorylineDetail, error) {
	storyline, err := s.store.SecurityStoryline(ctx, storylineID)
	if err != nil {
		return model.SecurityStorylineDetail{}, err
	}
	detections, err := s.store.SecurityNativeDetectionsByIDs(ctx, storyline.DetectionIDs)
	if err != nil {
		return model.SecurityStorylineDetail{}, err
	}
	events, err := s.store.SecurityAuditEventsByIDs(ctx, storyline.EventIDs)
	if err != nil {
		return model.SecurityStorylineDetail{}, err
	}
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		return model.SecurityStorylineDetail{}, err
	}
	tenantNames := make(map[string]string, len(tenants))
	for _, tenant := range tenants {
		tenantNames[tenant.ID] = tenant.Name
	}
	eventsByID := make(map[string]model.SecurityAuditEvent, len(events))
	for _, event := range events {
		eventsByID[event.ID] = event
	}
	detail := model.SecurityStorylineDetail{SecurityStoryline: storyline, Evidence: []model.SecurityStorylineEvidence{}}
	for _, detection := range detections {
		item := model.SecurityStorylineEvidence{
			DetectionID: detection.ID, RuleID: detection.RuleID, Title: detection.Title,
			Severity: detection.Severity, Confidence: detection.Confidence,
			Stage:      attackstorylines.StageFor(storyline.PackID, detection.RuleID),
			OccurredAt: detection.OccurredAt, TenantID: detection.TenantID,
			TenantName: tenantNames[detection.TenantID], Events: []model.SecurityEvidenceSummary{},
		}
		ids := detection.EventIDs
		if len(ids) == 0 {
			ids = []string{detection.EventID}
		}
		for _, eventID := range ids {
			if event, ok := eventsByID[eventID]; ok {
				if summary := summarizeSecurityEvent(event); summary != nil {
					item.Events = append(item.Events, *summary)
				}
			}
		}
		detail.Evidence = append(detail.Evidence, item)
	}
	sort.Slice(detail.Evidence, func(i, j int) bool { return detail.Evidence[i].OccurredAt.Before(detail.Evidence[j].OccurredAt) })
	return detail, nil
}

func (s *Service) TriageStoryline(ctx context.Context, storylineID, status, owner, actor string) (model.SecurityStoryline, error) {
	if !validTriageStatus(status) {
		return model.SecurityStoryline{}, ErrInvalidTriageStatus
	}
	return s.store.UpdateSecurityStorylineState(ctx, storylineID, status, strings.TrimSpace(owner), actor)
}

func (s *Service) Incident(ctx context.Context, tenantID, incidentID string) (model.SecurityIncidentDetail, error) {
	tenant, err := s.store.Tenant(ctx, tenantID)
	if err != nil {
		return model.SecurityIncidentDetail{}, err
	}
	var detail model.SecurityIncidentDetail
	receivedAt := time.Now().UTC()
	if strings.HasPrefix(incidentID, "rta_") {
		detection, err := s.store.SecurityNativeDetection(ctx, tenantID, incidentID)
		if err != nil {
			return model.SecurityIncidentDetail{}, err
		}
		var evidence *model.SecurityEvidenceSummary
		event, eventErr := s.store.SecurityAuditEvent(ctx, tenantID, detection.EventID)
		if eventErr == nil {
			evidence = summarizeSecurityEvent(event)
		} else {
			s.log.Warn("security operations: source event unavailable for incident", "tenant_id", tenantID, "incident_id", incidentID, "event_id", detection.EventID, "error", eventErr)
		}
		receivedAt = detection.CreatedAt.UTC()
		detail.SecurityIncident = nativeIncident(detection, tenant.Name, evidence)
		detail.Alerts = []model.SecurityAlert{{
			ID: detection.ID + "_rule", Title: detection.Title, Severity: detection.Severity,
			Status: "Detected", ServiceSource: "RTM M365 Audit", DetectionSource: detection.RuleID,
			CreatedAt: detection.CreatedAt.Format(time.RFC3339), UpdatedAt: detection.CreatedAt.Format(time.RFC3339),
		}}
		detail.Timeline = []model.SecurityTimelineEvent{{
			ID: detection.EventID, Timestamp: detection.OccurredAt.Format(time.RFC3339),
			Title:       "Microsoft 365 audit event matched rule " + detection.RuleID,
			Description: detection.Description, Source: "RTM M365 Audit",
		}}
	} else {
		detail, err = s.provider.SecurityIncident(ctx, tenantID, incidentID)
		if err != nil {
			return model.SecurityIncidentDetail{}, err
		}
		detail.TenantID, detail.TenantName = tenant.ID, tenant.Name
	}
	detail.SecurityIncident, err = s.observeIncident(ctx, detail.SecurityIncident, receivedAt)
	if err != nil {
		return model.SecurityIncidentDetail{}, err
	}
	detail.Remediation = remediationPlan(detail)
	return detail, nil
}

func nativeIncident(detection model.SecurityNativeDetection, tenantName string, evidence *model.SecurityEvidenceSummary) model.SecurityIncident {
	occurredAt := detection.OccurredAt.UTC().Format(time.RFC3339)
	createdAt := detection.CreatedAt.UTC().Format(time.RFC3339)
	return model.SecurityIncident{
		ID: detection.ID, TenantID: detection.TenantID, TenantName: tenantName,
		Title: detection.Title, Description: detection.Description, Severity: detection.Severity,
		Status: model.SecurityTriageNew, ProviderStatus: "Detected", Source: "RTM M365 Audit",
		DetectionType: detection.DetectionType, Confidence: detection.Confidence,
		RuleID: detection.RuleID, RuleVersion: detection.RuleVersion,
		AlertCount: 1, EntityCount: len(detection.Entities), Entities: detection.Entities,
		Evidence: evidence, RTMReceivedAt: createdAt,
		CreatedAt: occurredAt, UpdatedAt: createdAt, Sample: detection.Sample,
	}
}

func (s *Service) observeIncident(ctx context.Context, incident model.SecurityIncident, receivedAt time.Time) (model.SecurityIncident, error) {
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}
	state, err := s.store.ObserveSecurityIncident(ctx, model.SecurityIncidentState{
		TenantID: incident.TenantID, IncidentID: incident.ID,
		Status: incident.Status, Owner: incident.Owner,
		ReceivedAt: receivedAt, UpdatedBy: "RTM monitoring", UpdatedAt: receivedAt,
	})
	if err != nil {
		return model.SecurityIncident{}, err
	}
	incident.Status, incident.Owner = state.Status, state.Owner
	incident.RTMReceivedAt = state.ReceivedAt.UTC().Format(time.RFC3339)
	return incident, nil
}

func auditCoverageForTenant(tenant model.Tenant, checkpoints []model.SecurityAuditCheckpoint, checkedAt string) model.SecurityCoverage {
	return connectorCoverageForTenant(tenant, checkpoints, checkedAt, auditConnectorKey, auditConnectorName, auditPermission, auditWorkloadCount,
		"Microsoft 365 audit ingestion has not completed its first run yet.", "Microsoft 365 audit records are ingesting across all subscribed workloads.")
}

func splitAuditCheckpoints(checkpoints []model.SecurityAuditCheckpoint) (audit, fast []model.SecurityAuditCheckpoint) {
	for _, checkpoint := range checkpoints {
		if strings.HasPrefix(checkpoint.ContentType, "Graph.") {
			fast = append(fast, checkpoint)
		} else {
			audit = append(audit, checkpoint)
		}
	}
	return audit, fast
}

func connectorCoverageForTenant(tenant model.Tenant, checkpoints []model.SecurityAuditCheckpoint, checkedAt, key, name, permission string, requiredCount int, initializing, healthy string) model.SecurityCoverage {
	coverage := model.SecurityCoverage{
		TenantID: tenant.ID, TenantName: tenant.Name, ConnectorKey: key,
		ConnectorName: name, RequiredPermission: permission, CheckedAt: checkedAt,
	}
	if len(checkpoints) == 0 {
		coverage.Status = "degraded"
		coverage.Detail = initializing
		return coverage
	}
	status := "healthy"
	for _, checkpoint := range checkpoints {
		switch checkpoint.Status {
		case "missing_permission":
			coverage.Status, coverage.Detail = "missing_permission", checkpoint.Detail
			return coverage
		case "auditing_disabled":
			coverage.Status, coverage.Detail = "auditing_disabled", checkpoint.Detail
			return coverage
		case "degraded":
			status = "degraded"
			coverage.Detail = checkpoint.Detail
		case "sample":
			if status == "healthy" {
				status = "sample"
				coverage.Detail = checkpoint.Detail
			}
		}
	}
	if len(checkpoints) < requiredCount {
		coverage.Status = "degraded"
		coverage.Detail = fmt.Sprintf("%s has checkpoints for %d of %d required feeds.", name, len(checkpoints), requiredCount)
		return coverage
	}
	coverage.Status = status
	if status == "healthy" {
		coverage.Detail = healthy
	}
	if status == "degraded" && coverage.Detail == "" {
		coverage.Detail = "One or more " + name + " feeds could not be ingested."
	}
	return coverage
}

// Triage updates RTM's local workflow state only. It deliberately does not
// PATCH Microsoft Defender or mutate the customer tenant.
func (s *Service) Triage(ctx context.Context, tenantID, incidentID string, status, owner *string, actor string) (model.SecurityIncidentDetail, error) {
	detail, err := s.Incident(ctx, tenantID, incidentID)
	if err != nil {
		return model.SecurityIncidentDetail{}, err
	}
	return s.persistTriage(ctx, detail, status, owner, actor)
}

// BulkTriage applies RTM-local workflow changes with bounded concurrency.
// Every item has an independent outcome so a provider row that disappeared
// after the queue snapshot cannot hide successful updates to other incidents.
func (s *Service) BulkTriage(ctx context.Context, references []IncidentReference, options BulkTriageOptions) ([]BulkTriageOutcome, error) {
	if options.Status != nil && !validTriageStatus(strings.TrimSpace(*options.Status)) {
		return nil, ErrInvalidTriageStatus
	}
	outcomes := make([]BulkTriageOutcome, len(references))
	sem := make(chan struct{}, maxConcurrentTriage)
	var wg sync.WaitGroup
	for index, reference := range references {
		wg.Add(1)
		go func(index int, reference IncidentReference) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			outcome := BulkTriageOutcome{Reference: reference}
			detail, err := s.Incident(ctx, reference.TenantID, reference.IncidentID)
			if err != nil {
				outcome.Err = err
				outcomes[index] = outcome
				return
			}
			status, owner := options.Status, (*string)(nil)
			if options.Accept {
				owner = &options.Actor
				if detail.Status == model.SecurityTriageNew {
					inProgress := model.SecurityTriageInProgress
					status = &inProgress
				} else {
					status = nil
				}
			}
			outcome.Incident, outcome.Err = s.persistTriage(ctx, detail, status, owner, options.Actor)
			outcomes[index] = outcome
		}(index, reference)
	}
	wg.Wait()
	return outcomes, nil
}

func (s *Service) persistTriage(ctx context.Context, detail model.SecurityIncidentDetail, status, owner *string, actor string) (model.SecurityIncidentDetail, error) {
	nextStatus, nextOwner := detail.Status, detail.Owner
	if status != nil {
		nextStatus = strings.TrimSpace(*status)
	}
	if owner != nil {
		nextOwner = strings.TrimSpace(*owner)
	}
	if !validTriageStatus(nextStatus) {
		return model.SecurityIncidentDetail{}, ErrInvalidTriageStatus
	}
	state, err := s.store.UpsertSecurityIncidentState(ctx, model.SecurityIncidentState{
		TenantID: detail.TenantID, IncidentID: detail.ID, Status: nextStatus,
		Owner: nextOwner, UpdatedBy: actor,
	})
	if err != nil {
		return model.SecurityIncidentDetail{}, err
	}
	detail.Status, detail.Owner = state.Status, state.Owner
	return detail, nil
}

func validTriageStatus(status string) bool {
	switch status {
	case model.SecurityTriageNew, model.SecurityTriageInProgress, model.SecurityTriageResolved, model.SecurityTriageDismissed:
		return true
	default:
		return false
	}
}

func connectorStatus(connector model.SecurityConnectorSummary) string {
	if connector.AttentionTenants > 0 {
		return "degraded"
	}
	if connector.SampleTenants > 0 {
		return "sample"
	}
	if connector.HealthyTenants > 0 {
		return "healthy"
	}
	return "degraded"
}

func providerCoverageError(err error) (string, string) {
	var apiErr *graph.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusForbidden:
			if strings.Contains(strings.ToLower(apiErr.Message), "account is not provisioned") {
				return "not_provisioned", "Microsoft Defender XDR is not provisioned for this tenant. Open the Microsoft Defender portal and complete onboarding, then verify a supported Defender license."
			}
			return "missing_permission", "Microsoft denied Defender incident access. Grant admin consent for " + defenderPermission + "."
		case http.StatusUnauthorized:
			return "degraded", "Microsoft rejected the tenant app credentials."
		case http.StatusTooManyRequests:
			return "degraded", "Microsoft Defender XDR is throttling incident reads."
		default:
			return "degraded", fmt.Sprintf("Microsoft Defender XDR returned HTTP %d.", apiErr.Status)
		}
	}
	return "degraded", "Microsoft Defender XDR incidents could not be retrieved."
}
