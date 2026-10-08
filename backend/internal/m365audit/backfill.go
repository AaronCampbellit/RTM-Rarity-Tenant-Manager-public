package m365audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

const historicalBackfillSource = "historical_backfill"

type HistoryBackfillPayload struct {
	TenantID string `json:"tenantId"`
}

// RunHistoryBackfill imports newest-to-oldest, one-day source windows. The
// Management Activity API rejects larger windows; using the same bounded
// slices for Graph also prevents a high-volume tenant from hitting page caps.
func (s *Service) RunHistoryBackfill(ctx context.Context, jobID, payload string) {
	started := s.now()
	var args HistoryBackfillPayload
	if err := json.Unmarshal([]byte(payload), &args); err != nil || args.TenantID == "" {
		_ = s.store.CompleteJob(ctx, jobID, "Failed", time.Since(started).Round(time.Second).String())
		return
	}
	history, err := s.store.SecurityHistoryImport(ctx, args.TenantID)
	if err != nil || history.JobID != jobID {
		_ = s.store.CompleteJob(ctx, jobID, "Failed", time.Since(started).Round(time.Second).String())
		return
	}
	history.Status, history.StartedAt, history.Detail = "running", started, "Importing Microsoft 365 history newest to oldest."
	_, _ = s.store.UpsertSecurityHistoryImport(ctx, history)
	_ = s.store.UpdateJobStatus(ctx, jobID, "Running", 0)

	if history.WindowHours == 0 {
		history.Status, history.Progress, history.CompletedAt = "completed", 100, s.now()
		history.Detail = "Monitoring starts now; no historical evidence was requested."
		_, _ = s.store.UpsertSecurityHistoryImport(ctx, history)
		_ = s.store.CompleteJob(ctx, jobID, "Completed", time.Since(started).Round(time.Second).String())
		return
	}

	rules, err := s.store.SecurityDetectionRules(ctx)
	if err != nil {
		s.finishHistoryBackfill(ctx, &history, jobID, started, 1, "Detection rules could not be loaded.")
		return
	}
	collectionEnd := started
	windowStart := collectionEnd.Add(-time.Duration(history.WindowHours) * time.Hour)
	// Leave a small edge inside Management Activity's rolling seven-day limit.
	// The live lanes cover these latest minutes and semantic event fingerprints
	// deduplicate the overlap, so this avoids a fragile oldest-slice boundary.
	if history.WindowHours == 168 {
		windowStart = windowStart.Add(5 * time.Minute)
	}
	slices := (history.WindowHours + 23) / 24
	history.FeedsTotal = slices * (len(ContentTypes) + len(FastIdentityContentTypes))
	_, _ = s.store.UpsertSecurityHistoryImport(ctx, history)
	failures := 0

	for sliceEnd := collectionEnd; sliceEnd.After(windowStart); {
		sliceStart := sliceEnd.Add(-24 * time.Hour)
		if sliceStart.Before(windowStart) {
			sliceStart = windowStart
		}
		for _, feed := range append(append([]string{}, FastIdentityContentTypes...), ContentTypes...) {
			var events []model.SecurityAuditEvent
			if strings.HasPrefix(feed, "Graph.") {
				events, err = s.provider.CollectFastIdentity(ctx, history.TenantID, feed, sliceStart, sliceEnd)
			} else {
				events, err = s.provider.Collect(ctx, history.TenantID, feed, sliceStart, sliceEnd)
			}
			if err != nil {
				failures++
			} else {
				observedAt := s.now()
				for i := range events {
					events[i].AvailableAt, events[i].IngestedAt = observedAt, observedAt
					events[i].Sources = appendSource(events[i].Sources, historicalBackfillSource)
				}
				detections := s.incidentEligibleDetections(ctx, events, DetectConfigured(events, observedAt, rules))
				inserted, storeErr := s.store.StoreSecurityAuditBatch(ctx, model.SecurityAuditCheckpoint{TenantID: history.TenantID}, events, nil)
				if storeErr != nil {
					failures++
				} else {
					history.EventsReceived += len(events)
					history.EventsInserted += inserted
					detectionCount, detectionErr := s.store.StoreSecurityNativeDetections(ctx, detections)
					if detectionErr != nil {
						failures++
					} else {
						history.DetectionsCreated += detectionCount
					}
				}
			}
			history.FeedsCompleted++
			history.Progress = history.FeedsCompleted * 90 / history.FeedsTotal
			history.Detail = fmt.Sprintf("Imported %d of %d source windows · %d new events retained.", history.FeedsCompleted, history.FeedsTotal, history.EventsInserted)
			_, _ = s.store.UpsertSecurityHistoryImport(ctx, history)
			_ = s.store.UpdateJobStatus(ctx, jobID, "Running", history.Progress)
		}
		sliceEnd = sliceStart
	}

	// Imported evidence participates in baselines and correlation. Only a
	// detection anchored on or after the persisted incident cutoff is eligible.
	events, loadErr := s.store.SecurityAuditEventsSince(ctx, windowStart)
	if loadErr != nil {
		failures++
	} else {
		createdAt := s.now()
		detections := s.incidentEligibleDetections(ctx, events, append(CorrelateConfigured(events, createdAt, rules), DetectCustom(events, createdAt, rules)...))
		inserted, storeErr := s.store.StoreSecurityNativeDetections(ctx, detections)
		if storeErr != nil {
			failures++
		} else {
			history.DetectionsCreated += inserted
		}
	}
	if err := s.refreshStorylines(ctx, s.now()); err != nil {
		failures++
		s.log.Warn("security history storyline refresh failed", "tenant_id", history.TenantID, "error", err)
	}
	s.finishHistoryBackfill(ctx, &history, jobID, started, failures, "")
}

func (s *Service) finishHistoryBackfill(ctx context.Context, history *model.SecurityHistoryImport, jobID string, started time.Time, failures int, detail string) {
	history.Progress, history.CompletedAt = 100, s.now()
	jobStatus := "Completed"
	switch {
	case failures == 0:
		history.Status = "completed"
		history.Detail = fmt.Sprintf("History import complete · %d events retained · %d detections created.", history.EventsInserted, history.DetectionsCreated)
	case history.EventsInserted > 0:
		history.Status, jobStatus = "partial", "Partial"
		history.Detail = fmt.Sprintf("History import completed with %d unavailable source windows · %d events retained.", failures, history.EventsInserted)
	default:
		history.Status, jobStatus = "failed", "Failed"
		history.Detail = detail
		if history.Detail == "" {
			history.Detail = fmt.Sprintf("History import failed across %d source windows. Check connector permissions and try the live feeds again.", failures)
		}
	}
	_, _ = s.store.UpsertSecurityHistoryImport(ctx, *history)
	_ = s.store.CompleteJob(ctx, jobID, jobStatus, time.Since(started).Round(time.Second).String())
	_ = s.store.AppendAudit(ctx, model.AuditEntry{
		Actor: "system", Action: "security.history_backfill", Resource: "tenant:" + history.TenantID,
		Result:        fmt.Sprintf("%s — received %d, inserted %d, detections %d, failed feeds %d", jobStatus, history.EventsReceived, history.EventsInserted, history.DetectionsCreated, failures),
		CorrelationID: "security-history-" + history.RequestedAt.UTC().Format("20060102T150405Z"),
	})
}

func appendSource(sources []string, source string) []string {
	for _, existing := range sources {
		if existing == source {
			return sources
		}
	}
	return append(sources, source)
}

func (s *Service) incidentEligibleDetections(ctx context.Context, events []model.SecurityAuditEvent, detections []model.SecurityNativeDetection) []model.SecurityNativeDetection {
	history, err := s.store.SecurityHistoryImports(ctx)
	if err != nil || len(history) == 0 || len(detections) == 0 {
		return detections
	}
	cutoffs := make(map[string]time.Time, len(history))
	for _, item := range history {
		cutoffs[item.TenantID] = item.IncidentCutoffAt
	}
	eventsByID := make(map[string]model.SecurityAuditEvent, len(events))
	for _, event := range events {
		eventsByID[event.ID] = event
	}
	out := detections[:0]
	for _, detection := range detections {
		cutoff, hasPolicy := cutoffs[detection.TenantID]
		event, found := eventsByID[detection.EventID]
		if !hasPolicy || cutoff.IsZero() || found && !event.OccurredAt.Before(cutoff) {
			out = append(out, detection)
		}
	}
	return out
}
