// Command worker runs RTM background jobs (River). It consumes jobs enqueued by
// the API, advances their status in the RTM jobs table, and writes audit
// records. Requires RTM_DATABASE_URL (River is PostgreSQL-backed).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rarity/rtm/internal/config"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/jobs"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/securefields"
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
	if cfg.DatabaseURL == "" {
		log.Error("worker requires RTM_DATABASE_URL (River is PostgreSQL-backed)")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	defer pg.Close()

	if err := jobs.Migrate(ctx, pg.Pool()); err != nil {
		log.Error("river migrate", "error", err)
		os.Exit(1)
	}

	// Graph provider with the same per-tenant authority/credential resolution
	// as the API, so the worker executes writes against the right tenant.
	resolveAuthority := func(ctx context.Context, tenantID string) (graph.TenantAuth, error) {
		c, err := pg.TenantCreds(ctx, tenantID)
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
		c, err := pg.TenantCreds(ctx, tenantID)
		if err != nil {
			return m365audit.Auth{}, err
		}
		return m365audit.Auth{Authority: c.Authority(), ClientID: c.ClientID, ClientSecret: c.ClientSecret}, nil
	})
	auditService := m365audit.NewService(pg, auditProvider, log)
	offlineService := offlineinvestigations.New(pg, log)

	// ThreatLocker provider with the same global MSP parent connection as the
	// API.
	tlp := threatlocker.NewProvider(threatlocker.Config{
		Instance:    cfg.ThreatLockerInstance,
		Token:       cfg.ThreatLockerToken,
		ParentOrgID: cfg.ThreatLockerParentOrgID,
		GlobalAuth: func(ctx context.Context) (threatlocker.Auth, error) {
			c, err := pg.ThreatLockerGlobalConfig(ctx)
			if err != nil {
				return threatlocker.Auth{}, err
			}
			return threatlocker.Auth{Instance: c.Instance, Token: c.Token, OrgID: c.ParentOrgID}, nil
		},
	})

	// Stop on signal.
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		log.Info("worker shutting down")
		cancel()
	}()

	log.Info("worker started", "env", cfg.Env, "graph", gp.Mode())
	if err := jobs.RunWorker(ctx, pg.Pool(), pg, gp, tlp, auditService, offlineService, log); err != nil {
		log.Error("worker", "error", err)
		os.Exit(1)
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
