// Command api is the RTM HTTP API server.
//
// Backed by Postgres (pgx) when RTM_DATABASE_URL is set, otherwise an in-memory
// store so it runs offline. Serves the /api/v1 contract with RTM-native auth,
// the Graph provider (sample or live), and River-backed async workflows.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/config"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/jobs"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/securefields"
	"github.com/rarity/rtm/internal/server"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "error", err)
		os.Exit(1)
	}

	ctx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()

	// Store: Postgres when configured, else in-memory.
	var (
		st   store.Store
		pool *pgxpool.Pool
	)
	if cfg.DatabaseURL != "" {
		protector, err := securefields.New(cfg.FieldEncryptionKey)
		if err != nil {
			log.Error("field encryption", "error", err)
			os.Exit(1)
		}
		pg, err := store.NewPG(ctx, cfg.DatabaseURL, protector)
		if err != nil {
			log.Error("database", "error", err)
			os.Exit(1)
		}
		st, pool = pg, pg.Pool()
		log.Info("store: postgres")
	} else {
		st = store.NewMem()
		log.Info("store: in-memory")
	}
	defer st.Close()

	// Graph provider (sample or live Microsoft Graph). In live mode each
	// managed tenant is tokened against its own authority — and its own app
	// registration when one was stored with the tenant — resolved from the
	// tenants store (Microsoft tenant id, falling back to the verified domain).
	resolveAuthority := func(ctx context.Context, tenantID string) (graph.TenantAuth, error) {
		c, err := st.TenantCreds(ctx, tenantID)
		if err != nil {
			return graph.TenantAuth{}, err
		}
		return tenantAuth(c), nil
	}
	gp := graph.NewProvider(graph.Config{
		ClientID:                  cfg.EntraClientID,
		ClientSecret:              cfg.EntraClientSecret,
		TenantID:                  cfg.EntraTenantID,
		SharePointClientID:        cfg.SharePointClientID,
		SharePointCertificatePath: cfg.SharePointCertificatePath,
		SharePointPrivateKeyPath:  cfg.SharePointPrivateKeyPath,
	}, log, resolveAuthority)
	auditProvider := m365audit.NewProvider(m365audit.Config{
		ClientID: cfg.EntraClientID, ClientSecret: cfg.EntraClientSecret, TenantID: cfg.EntraTenantID,
	}, log, func(ctx context.Context, tenantID string) (m365audit.Auth, error) {
		c, err := st.TenantCreds(ctx, tenantID)
		if err != nil {
			return m365audit.Auth{}, err
		}
		return m365audit.Auth{Authority: c.Authority(), ClientID: c.ClientID, ClientSecret: c.ClientSecret}, nil
	})
	auditService := m365audit.NewService(st, auditProvider, log)
	offlineService := offlineinvestigations.New(st, log)

	// ThreatLocker provider (live-only, no sample mode): one MSP parent
	// connection from Admin Settings, with environment values as bootstrap.
	tlp := threatlocker.NewProvider(threatlocker.Config{
		Instance:    cfg.ThreatLockerInstance,
		Token:       cfg.ThreatLockerToken,
		ParentOrgID: cfg.ThreatLockerParentOrgID,
		GlobalAuth:  threatlockerGlobalAuth(st),
	})

	// Auth.
	au := auth.NewService(st, signingKey(cfg, log), log)

	// Jobs: River when Postgres is available, else the inline executor so the
	// full pipeline (Graph write → change record) still runs in memory mode.
	var enq jobs.Enqueuer = jobs.Inline{Store: st, Graph: gp, ThreatLocker: tlp, Log: log, Audit: auditService, Offline: offlineService}
	if pool != nil {
		if err := jobs.Migrate(ctx, pool); err != nil {
			log.Error("river migrate", "error", err)
			os.Exit(1)
		}
		re, err := jobs.NewRiverEnqueuer(pool)
		if err != nil {
			log.Error("river client", "error", err)
			os.Exit(1)
		}
		enq = re
		log.Info("jobs: river")
	}

	apiServer := server.New(cfg, log, st, gp, tlp, au, enq)
	apiServer.SetM365AuditProvider(auditProvider)
	apiServer.SetOfflineInvestigationService(offlineService)
	apiServer.StartSharePointScheduler(ctx)
	if pool == nil {
		go func() {
			_, _ = auditService.RunFastAll(ctx)
			_, _ = auditService.RunAll(ctx)
			fastTicker := time.NewTicker(time.Minute)
			auditTicker := time.NewTicker(5 * time.Minute)
			defer fastTicker.Stop()
			defer auditTicker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-fastTicker.C:
					_, _ = auditService.RunFastAll(ctx)
				case <-auditTicker.C:
					_, _ = auditService.RunAll(ctx)
				}
			}
		}()
	}
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("starting", "addr", cfg.HTTPAddr, "env", cfg.Env, "store", cfg.StoreMode(), "graph", gp.Mode())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutting down")
	cancelApp()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("shutdown", "error", err)
	}
}

func threatlockerGlobalAuth(st store.Store) threatlocker.GlobalAuthResolver {
	return func(ctx context.Context) (threatlocker.Auth, error) {
		c, err := st.ThreatLockerGlobalConfig(ctx)
		if err != nil {
			return threatlocker.Auth{}, err
		}
		return threatlocker.Auth{Instance: c.Instance, Token: c.Token, OrgID: c.ParentOrgID}, nil
	}
}

// tenantAuth maps stored tenant credentials to the Graph provider's per-tenant
// auth, applying the Exchange Online / SharePoint admin → Graph app fallback.
func tenantAuth(c store.TenantCreds) graph.TenantAuth {
	r := c.Resolved()
	return graph.TenantAuth{
		Authority: r.Authority(), ClientID: r.ClientID, ClientSecret: r.ClientSecret,
		ExchangeClientID: r.ExchangeClientID, ExchangeClientSecret: r.ExchangeClientSecret,
		SharePointClientID: r.SharePointClientID, SharePointClientSecret: r.SharePointClientSecret,
		SharePointAdminURL: r.SharePointAdminURL,
	}
}

// signingKey returns the configured JWT key, or a random one in dev (tokens
// won't survive a restart, which is fine locally).
func signingKey(cfg *config.Config, log *slog.Logger) []byte {
	if cfg.JWTSigningKey != "" {
		return []byte(cfg.JWTSigningKey)
	}
	log.Warn("RTM_JWT_SIGNING_KEY not set — generating an ephemeral dev key")
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
