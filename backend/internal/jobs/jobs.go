// Package jobs is the background-job layer (River). The API enqueues via the
// Enqueuer; the worker process consumes jobs and executes them through
// internal/worker. When no database is configured, the Inline enqueuer runs
// the same pipeline in-process so memory mode behaves identically.
package jobs

import (
	"context"
	"errors"
	"log/slog"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
	"github.com/rarity/rtm/internal/worker"
)

// Enqueuer hands a unit of async work to the background system. payload is
// the serialized worker.Payload describing the write.
type Enqueuer interface {
	Enqueue(ctx context.Context, jobType, jobID, payload string) error
}

// Inline executes jobs immediately in-process (in-memory mode, tests). The
// job still goes through the full pipeline: Running → Graph write → change
// record → Completed/Failed.
type Inline struct {
	Store        store.Store
	Graph        graph.Provider
	ThreatLocker threatlocker.Provider
	Log          *slog.Logger
	Audit        *m365audit.Service
	Offline      *offlineinvestigations.Service
}

func (i Inline) Enqueue(_ context.Context, jobType, jobID, payload string) error {
	// Detached context: the job must outlive the HTTP request that queued it.
	if jobType == m365audit.HistoryBackfillJobType && i.Audit != nil {
		go i.Audit.RunHistoryBackfill(context.Background(), jobID, payload)
		return nil
	}
	if jobType == m365audit.HistoryBackfillJobType {
		return errors.New("security history service is unavailable")
	}
	if jobType == offlineinvestigations.AnalysisJobType && i.Offline != nil {
		go func() { _ = i.Offline.RunAnalysis(context.Background(), jobID, payload) }()
		return nil
	}
	if jobType == offlineinvestigations.AnalysisJobType {
		return errors.New("offline investigation service is unavailable")
	}
	go worker.Process(context.Background(), i.Store, i.Graph, i.ThreatLocker, i.Log, jobID, payload)
	return nil
}

// WriteArgs is the River job payload for RTM write workflows. It carries the
// RTM jobs-table id so the worker can update status/progress as it runs.
type WriteArgs struct {
	JobID   string `json:"job_id"`
	JobType string `json:"job_type"`
	Payload string `json:"payload"`
}

// Kind implements river.JobArgs.
func (WriteArgs) Kind() string { return "rtm_write" }

// AuditIngestArgs is the singleton periodic Microsoft 365 audit ingestion
// job. Tenant fan-out and per-content checkpoints happen inside the service.
type AuditIngestArgs struct{}

func (AuditIngestArgs) Kind() string { return "m365_audit_ingest" }

// FastIdentityIngestArgs is the one-minute Microsoft Graph sign-in and
// directory-audit collector. It is separate from unified-audit backfill so
// the slower source retains its existing schedule and checkpoints.
type FastIdentityIngestArgs struct{}

func (FastIdentityIngestArgs) Kind() string { return "entra_fast_identity_ingest" }
