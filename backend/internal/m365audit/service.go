package m365audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
	attackstorylines "github.com/rarity/rtm/internal/storylines"
)

const (
	initialLookback        = 24 * time.Hour
	overlapWindow          = 30 * time.Minute
	retention              = 180 * 24 * time.Hour
	correlationLookback    = 30 * 24 * time.Hour
	fastIdentityLookback   = time.Hour
	fastIdentityOverlap    = 5 * time.Minute
	detectionPackVersion   = 5
	HistoryBackfillJobType = "security_history_backfill"
)

type Store interface {
	Tenants(ctx context.Context) ([]model.Tenant, error)
	SecurityAuditCheckpoint(ctx context.Context, tenantID, contentType string) (model.SecurityAuditCheckpoint, error)
	SecurityHistoryImports(ctx context.Context) ([]model.SecurityHistoryImport, error)
	SecurityHistoryImport(ctx context.Context, tenantID string) (model.SecurityHistoryImport, error)
	UpsertSecurityHistoryImport(ctx context.Context, history model.SecurityHistoryImport) (model.SecurityHistoryImport, error)
	SecurityAuditEventsSince(ctx context.Context, since time.Time) ([]model.SecurityAuditEvent, error)
	StoreSecurityAuditBatch(ctx context.Context, checkpoint model.SecurityAuditCheckpoint, events []model.SecurityAuditEvent, detections []model.SecurityNativeDetection) (int, error)
	StoreSecurityNativeDetections(ctx context.Context, detections []model.SecurityNativeDetection) (int, error)
	SecurityDetectionReplayCompleted(ctx context.Context, packVersion int) (bool, error)
	MarkSecurityDetectionReplay(ctx context.Context, packVersion, eventsScanned, detectionsInserted int) error
	SecurityDetectionRules(ctx context.Context) ([]model.SecurityDetectionRule, error)
	PruneSecurityAuditEvents(ctx context.Context, before time.Time) (int64, error)
	AppendAudit(ctx context.Context, entry model.AuditEntry) error
	UpdateJobStatus(ctx context.Context, id, status string, progress int) error
	CompleteJob(ctx context.Context, id, status, duration string) error
}

// RunFastAll ingests the two Graph identity feeds independently of the
// slower Management Activity collector. It is scheduled every minute and
// then evaluates multi-event rules over retained history so login sequences
// and cross-object changes alert on the same cycle.
func (s *Service) RunFastAll(ctx context.Context) ([]IngestResult, error) {
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		return nil, err
	}
	rules, err := s.store.SecurityDetectionRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("load detection rules: %w", err)
	}
	results := make([]IngestResult, len(tenants))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, tenant := range tenants {
		wg.Add(1)
		go func(index int, tenantID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[index] = s.runFastTenant(ctx, tenantID, rules)
		}(i, tenant.ID)
	}
	wg.Wait()
	now := s.now()
	events, err := s.store.SecurityAuditEventsSince(ctx, now.Add(-correlationLookback))
	if err != nil {
		return results, fmt.Errorf("load recent events for fast identity correlation: %w", err)
	}
	detections := s.incidentEligibleDetections(ctx, events, append(CorrelateConfigured(events, now, rules), DetectCustom(events, now, rules)...))
	if _, err := s.store.StoreSecurityNativeDetections(ctx, detections); err != nil {
		return results, fmt.Errorf("store fast identity correlations: %w", err)
	}
	if err := s.refreshStorylines(ctx, now); err != nil {
		return results, fmt.Errorf("refresh attack storylines: %w", err)
	}
	return results, nil
}

func (s *Service) RunFastTenant(ctx context.Context, tenantID string) IngestResult {
	rules, err := s.store.SecurityDetectionRules(ctx)
	if err != nil {
		s.log.Warn("fast identity rules unavailable", "tenant_id", tenantID, "error", err)
		return IngestResult{TenantID: tenantID, Failed: len(FastIdentityContentTypes)}
	}
	return s.runFastTenant(ctx, tenantID, rules)
}

func (s *Service) runFastTenant(ctx context.Context, tenantID string, rules []model.SecurityDetectionRule) IngestResult {
	now := s.now()
	mode, modeErr := s.provider.Mode(ctx, tenantID)
	result := IngestResult{TenantID: tenantID, Mode: mode}
	for _, contentType := range FastIdentityContentTypes {
		checkpoint, err := s.store.SecurityAuditCheckpoint(ctx, tenantID, contentType)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("fast identity checkpoint unavailable", "tenant_id", tenantID, "content_type", contentType, "error", err)
			result.Failed++
			continue
		}
		start := now.Add(-fastIdentityLookback)
		if err == nil && !checkpoint.CursorEnd.IsZero() {
			start = checkpoint.CursorEnd.Add(-fastIdentityOverlap)
		}
		if start.Before(now.Add(-fastIdentityLookback)) {
			start = now.Add(-fastIdentityLookback)
		}
		checkpoint.TenantID, checkpoint.ContentType = tenantID, contentType
		checkpoint.LastPolledAt, checkpoint.EventsReceived = now, 0
		if modeErr != nil {
			checkpoint.Status, checkpoint.Mode, checkpoint.Detail = "degraded", ModeLive, "RTM could not resolve the tenant Graph connection."
			result.Failed++
			_, _ = s.store.StoreSecurityAuditBatch(ctx, checkpoint, nil, nil)
			continue
		}
		events, collectErr := s.provider.CollectFastIdentity(ctx, tenantID, contentType, start, now)
		if collectErr != nil {
			checkpoint.Status, checkpoint.Detail = classifyFastIdentityError(collectErr)
			checkpoint.Mode = mode
			result.Failed++
			_, _ = s.store.StoreSecurityAuditBatch(ctx, checkpoint, nil, nil)
			continue
		}
		checkpoint.Mode, checkpoint.Status, checkpoint.CursorEnd = mode, "healthy", now
		if mode == ModeSample {
			checkpoint.Status, checkpoint.Detail = "sample", "RTM sample Graph identity events are active; no live connection is configured."
		} else {
			checkpoint.Detail = "Microsoft Graph sign-in and directory audit records are polling every minute."
		}
		checkpoint.EventsReceived = len(events)
		for _, event := range events {
			if event.OccurredAt.After(checkpoint.LastEventAt) {
				checkpoint.LastEventAt = event.OccurredAt
			}
		}
		detections := s.incidentEligibleDetections(ctx, events, DetectConfigured(events, now, rules))
		inserted, storeErr := s.store.StoreSecurityAuditBatch(ctx, checkpoint, events, detections)
		if storeErr != nil {
			s.log.Warn("fast identity batch failed", "tenant_id", tenantID, "content_type", contentType, "error", storeErr)
			result.Failed++
			continue
		}
		result.Received += len(events)
		result.Inserted += inserted
	}
	status := "Succeeded"
	if result.Failed > 0 {
		status = "Partial"
	}
	_ = s.store.AppendAudit(ctx, model.AuditEntry{
		Actor: "system", Action: "security.identity_fast_ingest", Resource: "tenant:" + tenantID,
		Result:        fmt.Sprintf("%s — received %d, inserted %d, failed feeds %d", status, result.Received, result.Inserted, result.Failed),
		CorrelationID: "identity-fast-ingest-" + now.Format("20060102T150405Z"),
	})
	return result
}

func classifyFastIdentityError(err error) (string, string) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.Status == http.StatusForbidden {
			return "missing_permission", "Microsoft denied Graph identity-log access. Grant AuditLog.Read.All application permission and admin consent."
		}
		if apiErr.Status == http.StatusTooManyRequests {
			return "degraded", "Microsoft Graph is throttling fast identity ingestion; RTM will retry automatically."
		}
		if apiErr.Status == http.StatusUnauthorized {
			return "degraded", "Microsoft rejected the tenant Graph application credentials."
		}
		return "degraded", fmt.Sprintf("Microsoft Graph identity logs returned HTTP %d.", apiErr.Status)
	}
	return "degraded", "Microsoft Graph identity records could not be ingested."
}

type Service struct {
	store    Store
	provider Provider
	log      *slog.Logger
	now      func() time.Time
}

type IngestResult struct {
	TenantID string
	Mode     string
	Received int
	Inserted int
	Failed   int
}

func NewService(st Store, provider Provider, log *slog.Logger) *Service {
	return &Service{store: st, provider: provider, log: log, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) RunAll(ctx context.Context) ([]IngestResult, error) {
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		return nil, err
	}
	rules, err := s.store.SecurityDetectionRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("load detection rules: %w", err)
	}
	results := make([]IngestResult, len(tenants))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, tenant := range tenants {
		wg.Add(1)
		go func(index int, tenantID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[index] = s.runTenant(ctx, tenantID, rules)
		}(i, tenant.ID)
	}
	wg.Wait()
	now := s.now()
	events, err := s.store.SecurityAuditEventsSince(ctx, now.Add(-correlationLookback))
	if err != nil {
		return results, fmt.Errorf("load recent audit events for detection replay: %w", err)
	}
	detections := s.incidentEligibleDetections(ctx, events, append(CorrelateConfigured(events, now, rules), DetectCustom(events, now, rules)...))
	replayCompleted, err := s.store.SecurityDetectionReplayCompleted(ctx, detectionPackVersion)
	if err != nil {
		return results, fmt.Errorf("check detection replay state: %w", err)
	}
	if !replayCompleted {
		detections = append(s.incidentEligibleDetections(ctx, events, DetectBuiltInsConfigured(events, now, rules)), detections...)
	}
	inserted, err := s.store.StoreSecurityNativeDetections(ctx, detections)
	if err != nil {
		return results, fmt.Errorf("store replayed and correlated detections: %w", err)
	}
	if !replayCompleted {
		if err := s.store.MarkSecurityDetectionReplay(ctx, detectionPackVersion, len(events), inserted); err != nil {
			return results, fmt.Errorf("mark detection replay complete: %w", err)
		}
		s.log.Info("m365 audit detection replay complete", "pack_version", detectionPackVersion, "events", len(events), "detections_inserted", inserted)
	} else if inserted > 0 {
		s.log.Info("m365 audit correlation cycle complete", "events", len(events), "detections_inserted", inserted)
	}
	if err := s.refreshStorylines(ctx, now); err != nil {
		return results, fmt.Errorf("refresh attack storylines: %w", err)
	}
	if deleted, err := s.store.PruneSecurityAuditEvents(ctx, now.Add(-retention)); err != nil {
		s.log.Warn("m365 audit retention failed", "error", err)
	} else if deleted > 0 {
		s.log.Info("m365 audit retention pruned events", "count", deleted)
	}
	return results, nil
}

type storylineStore interface {
	SecurityNativeDetectionsSince(ctx context.Context, since time.Time) ([]model.SecurityNativeDetection, error)
	SecurityAuditEventsSince(ctx context.Context, since time.Time) ([]model.SecurityAuditEvent, error)
	UpsertSecurityStorylines(ctx context.Context, storylines []model.SecurityStoryline) error
}

func (s *Service) refreshStorylines(ctx context.Context, now time.Time) error {
	storeWithStorylines, ok := s.store.(storylineStore)
	if !ok {
		return nil
	}
	since := now.Add(-attackstorylines.Lookback)
	detections, err := storeWithStorylines.SecurityNativeDetectionsSince(ctx, since)
	if err != nil {
		return err
	}
	events, err := storeWithStorylines.SecurityAuditEventsSince(ctx, since)
	if err != nil {
		return err
	}
	tenants, err := s.store.Tenants(ctx)
	if err != nil {
		return err
	}
	tenantNames := make(map[string]string, len(tenants))
	for _, tenant := range tenants {
		tenantNames[tenant.ID] = tenant.Name
	}
	return storeWithStorylines.UpsertSecurityStorylines(ctx, attackstorylines.Evaluate(detections, events, tenantNames, now))
}

func (s *Service) RunTenant(ctx context.Context, tenantID string) IngestResult {
	rules, err := s.store.SecurityDetectionRules(ctx)
	if err != nil {
		s.log.Warn("m365 audit rules unavailable", "tenant_id", tenantID, "error", err)
		return IngestResult{TenantID: tenantID, Failed: len(ContentTypes)}
	}
	return s.runTenant(ctx, tenantID, rules)
}

func (s *Service) runTenant(ctx context.Context, tenantID string, rules []model.SecurityDetectionRule) IngestResult {
	now := s.now()
	mode, modeErr := s.provider.Mode(ctx, tenantID)
	result := IngestResult{TenantID: tenantID, Mode: mode}
	for _, contentType := range ContentTypes {
		checkpoint, err := s.store.SecurityAuditCheckpoint(ctx, tenantID, contentType)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("m365 audit checkpoint unavailable", "tenant_id", tenantID, "content_type", contentType, "error", err)
			result.Failed++
			continue
		}
		start := now.Add(-initialLookback)
		if err == nil && !checkpoint.CursorEnd.IsZero() {
			start = checkpoint.CursorEnd.Add(-overlapWindow)
		}
		if start.Before(now.Add(-initialLookback)) {
			start = now.Add(-initialLookback)
		}
		checkpoint.TenantID, checkpoint.ContentType = tenantID, contentType
		checkpoint.LastPolledAt, checkpoint.EventsReceived = now, 0
		if modeErr != nil {
			checkpoint.Status, checkpoint.Mode, checkpoint.Detail = "degraded", ModeLive, "RTM could not resolve the tenant audit connection."
			result.Failed++
			_, _ = s.store.StoreSecurityAuditBatch(ctx, checkpoint, nil, nil)
			continue
		}
		events, collectErr := s.provider.Collect(ctx, tenantID, contentType, start, now)
		if collectErr != nil {
			checkpoint.Status, checkpoint.Detail = classifyError(collectErr)
			checkpoint.Mode = mode
			result.Failed++
			if _, err := s.store.StoreSecurityAuditBatch(ctx, checkpoint, nil, nil); err != nil {
				s.log.Warn("m365 audit failed checkpoint write", "tenant_id", tenantID, "content_type", contentType, "error", err)
			}
			continue
		}
		checkpoint.Mode, checkpoint.Status, checkpoint.CursorEnd = mode, "healthy", now
		if mode == ModeSample {
			checkpoint.Status = "sample"
			checkpoint.Detail = "RTM sample audit events are active; no live Management Activity connection is configured."
		} else {
			checkpoint.Detail = "Microsoft 365 Management Activity records are ingesting."
		}
		checkpoint.EventsReceived = len(events)
		for _, event := range events {
			if event.OccurredAt.After(checkpoint.LastEventAt) {
				checkpoint.LastEventAt = event.OccurredAt
			}
		}
		detections := s.incidentEligibleDetections(ctx, events, DetectConfigured(events, now, rules))
		inserted, err := s.store.StoreSecurityAuditBatch(ctx, checkpoint, events, detections)
		if err != nil {
			s.log.Warn("m365 audit batch failed", "tenant_id", tenantID, "content_type", contentType, "error", err)
			result.Failed++
			continue
		}
		result.Received += len(events)
		result.Inserted += inserted
	}
	status := "Succeeded"
	if result.Failed > 0 {
		status = "Partial"
	}
	_ = s.store.AppendAudit(ctx, model.AuditEntry{
		Actor: "system", Action: "security.audit_ingest", Resource: "tenant:" + tenantID,
		Result:        fmt.Sprintf("%s — received %d, inserted %d, failed feeds %d", status, result.Received, result.Inserted, result.Failed),
		CorrelationID: "audit-ingest-" + now.Format("20060102T150405Z"),
	})
	return result
}

func classifyError(err error) (string, string) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		message := strings.ToLower(apiErr.Code + " " + apiErr.Message)
		if apiErr.Status == http.StatusForbidden || strings.Contains(message, "activityfeed.read") || strings.Contains(message, "permission") {
			return "missing_permission", "Microsoft denied audit-feed access. Grant Office 365 Management APIs ActivityFeed.Read application permission and admin consent."
		}
		if strings.Contains(message, "tenantnotstarted") || strings.Contains(message, "audit") && strings.Contains(message, "disabled") {
			return "auditing_disabled", "Microsoft 365 unified auditing is not enabled for this tenant."
		}
		if apiErr.Status == http.StatusTooManyRequests {
			return "degraded", "Microsoft is throttling audit ingestion; RTM will retry automatically."
		}
		if apiErr.Status == http.StatusUnauthorized {
			return "degraded", "Microsoft rejected the tenant application credentials."
		}
		return "degraded", fmt.Sprintf("Microsoft 365 Management Activity returned HTTP %d.", apiErr.Status)
	}
	return "degraded", "Microsoft 365 audit records could not be ingested."
}
