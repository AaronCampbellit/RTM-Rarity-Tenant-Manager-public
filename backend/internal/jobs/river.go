package jobs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
	"github.com/rarity/rtm/internal/worker"
)

// riverMigrationLockID is a stable PostgreSQL advisory-lock key ("RTM_rive").
// The API and worker start together and both need River's schema; serializing
// the migrator prevents concurrent CREATE TYPE/TABLE statements on a fresh DB.
const riverMigrationLockID int64 = 0x52544d5f72697665

// Migrate applies River's schema (its own tables) to the database.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, riverMigrationLockID); err != nil {
		return err
	}
	defer func() {
		_, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, riverMigrationLockID)
	}()

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return err
	}
	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	return err
}

type auditIngestWorker struct {
	river.WorkerDefaults[AuditIngestArgs]
	service *m365audit.Service
	log     *slog.Logger
}

type fastIdentityIngestWorker struct {
	river.WorkerDefaults[FastIdentityIngestArgs]
	service *m365audit.Service
	log     *slog.Logger
}

func (w *fastIdentityIngestWorker) Work(ctx context.Context, _ *river.Job[FastIdentityIngestArgs]) error {
	results, err := w.service.RunFastAll(ctx)
	if err != nil {
		return err
	}
	w.log.Info("fast identity ingestion complete", "tenants", len(results))
	return nil
}

func (w *auditIngestWorker) Work(ctx context.Context, _ *river.Job[AuditIngestArgs]) error {
	results, err := w.service.RunAll(ctx)
	if err != nil {
		return err
	}
	w.log.Info("m365 audit ingestion complete", "tenants", len(results))
	return nil
}

// RiverEnqueuer inserts jobs from the API process (no workers here).
type RiverEnqueuer struct {
	client *river.Client[pgx.Tx]
}

// NewRiverEnqueuer builds an insert-only River client.
func NewRiverEnqueuer(pool *pgxpool.Pool) (*RiverEnqueuer, error) {
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, err
	}
	return &RiverEnqueuer{client: client}, nil
}

func (e *RiverEnqueuer) Enqueue(ctx context.Context, jobType, jobID, payload string) error {
	_, err := e.client.Insert(ctx, WriteArgs{JobID: jobID, JobType: jobType, Payload: payload}, nil)
	return err
}

// writeWorker processes RTM write jobs by delegating to the shared execution
// pipeline (Graph write → job status → change record → audit).
type writeWorker struct {
	river.WorkerDefaults[WriteArgs]
	store   store.Store
	graph   graph.Provider
	tl      threatlocker.Provider
	log     *slog.Logger
	audit   *m365audit.Service
	offline *offlineinvestigations.Service
}

func (w *writeWorker) Work(ctx context.Context, job *river.Job[WriteArgs]) error {
	w.log.Info("job start", "id", job.Args.JobID, "type", job.Args.JobType)
	if job.Args.JobType == m365audit.HistoryBackfillJobType {
		w.audit.RunHistoryBackfill(ctx, job.Args.JobID, job.Args.Payload)
		return nil
	}
	if job.Args.JobType == offlineinvestigations.AnalysisJobType {
		if w.offline == nil {
			return errors.New("offline investigation service is unavailable")
		}
		return w.offline.RunAnalysis(ctx, job.Args.JobID, job.Args.Payload)
	}
	worker.Process(ctx, w.store, w.graph, w.tl, w.log, job.Args.JobID, job.Args.Payload)
	return nil
}

// RunWorker starts a River worker that consumes jobs until ctx is cancelled.
func RunWorker(ctx context.Context, pool *pgxpool.Pool, st store.Store, gp graph.Provider, tlp threatlocker.Provider, audit *m365audit.Service, offline *offlineinvestigations.Service, log *slog.Logger) error {
	workers := river.NewWorkers()
	river.AddWorker(workers, &writeWorker{store: st, graph: gp, tl: tlp, log: log, audit: audit, offline: offline})
	river.AddWorker(workers, &auditIngestWorker{service: audit, log: log})
	river.AddWorker(workers, &fastIdentityIngestWorker{service: audit, log: log})

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		PeriodicJobs: []*river.PeriodicJob{
			river.NewPeriodicJob(
				river.PeriodicInterval(time.Minute),
				func() (river.JobArgs, *river.InsertOpts) { return FastIdentityIngestArgs{}, nil },
				&river.PeriodicJobOpts{ID: "rtm-entra-fast-identity-ingest", RunOnStart: true},
			),
			river.NewPeriodicJob(
				river.PeriodicInterval(5*time.Minute),
				func() (river.JobArgs, *river.InsertOpts) { return AuditIngestArgs{}, nil },
				&river.PeriodicJobOpts{ID: "rtm-m365-audit-ingest", RunOnStart: true},
			),
		},
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 5}},
		Workers: workers,
	})
	if err != nil {
		return err
	}
	if err := client.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return client.Stop(context.Background())
}
