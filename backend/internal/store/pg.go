package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for goose
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/securefields"
	"github.com/rarity/rtm/internal/seed"
	"github.com/rarity/rtm/migrations"
)

const offlineEvidenceChunkBytes = 8 << 20

// PG is the Postgres-backed Store (pgx). Schema is Goose-managed (migrations/,
// applied at startup). It persists the core mutable entities; static/derived
// presentation data (roles, tenant-access matrix, dashboard aggregates,
// approvals) is served from the seed package in the BETA.
type PG struct {
	pool      *pgxpool.Pool
	protector *securefields.Protector
}

// NewPG connects, applies Goose migrations, and seeds if empty.
func NewPG(ctx context.Context, dsn string, protector *securefields.Protector) (*PG, error) {
	if protector == nil {
		return nil, errors.New("field encryption is required for Postgres")
	}
	if err := migrate(ctx, dsn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	s := &PG{pool: pool, protector: protector}
	if err := s.encryptLegacyTenantSecrets(ctx); err != nil {
		return nil, fmt.Errorf("encrypt tenant secrets: %w", err)
	}
	if err := s.seedIfEmpty(ctx); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	return s, nil
}

func (s *PG) encryptLegacyTenantSecrets(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT id,client_secret,exchange_client_secret,sharepoint_client_secret FROM tenants`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, a, b, c string
		if err := rows.Scan(&id, &a, &b, &c); err != nil {
			return err
		}
		values := []*string{&a, &b, &c}
		changed := false
		for _, value := range values {
			if *value != "" && !securefields.IsSealed(*value) {
				sealed, err := s.protector.Seal(*value)
				if err != nil {
					return err
				}
				*value = sealed
				changed = true
			}
		}
		if changed {
			if _, err := s.pool.Exec(ctx, `UPDATE tenants SET client_secret=$2,exchange_client_secret=$3,sharepoint_client_secret=$4 WHERE id=$1`, id, a, b, c); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (s *PG) sealTenantSecrets(t *NewTenant) error {
	for _, value := range []*string{&t.ClientSecret, &t.ExchangeClientSecret, &t.SharePointClientSecret} {
		sealed, err := s.protector.Seal(*value)
		if err != nil {
			return err
		}
		*value = sealed
	}
	return nil
}

func (s *PG) openTenantSecrets(c *TenantCreds) error {
	for _, value := range []*string{&c.ClientSecret, &c.ExchangeClientSecret, &c.SharePointClientSecret} {
		plain, err := s.protector.Open(*value)
		if err != nil {
			return err
		}
		*value = plain
	}
	return nil
}

// schemaMigrationLockID is a stable PostgreSQL advisory-lock key ("RTM_sche").
// Both the API and worker initialize the store, so the lock prevents their
// Goose runs from racing when a brand-new database starts.
const schemaMigrationLockID int64 = 0x52544d5f73636865

// migrate applies the embedded Goose migrations via a short-lived *sql.DB.
func migrate(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	lockConn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer lockConn.Close()
	if _, err := lockConn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockID); err != nil {
		return fmt.Errorf("acquire schema migration lock: %w", err)
	}
	defer func() {
		_, _ = lockConn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockID)
	}()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}

// Pool exposes the connection pool (used by the River worker/enqueuer).
func (s *PG) Pool() *pgxpool.Pool { return s.pool }

func (s *PG) Close() { s.pool.Close() }

func (s *PG) seedIfEmpty(ctx context.Context) error {
	var n int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, a := range seed.Accounts {
		hash, _ := bcrypt.GenerateFromPassword([]byte(a.Password), bcrypt.DefaultCost)
		batch.Queue(`INSERT INTO accounts (id,name,email,role,is_admin,status,password_hash,must_change_password) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			a.ID, a.Name, a.Email, a.Role, a.IsAdmin, a.Status, string(hash), a.MustChange)
	}
	for _, t := range seed.Tenants {
		batch.Queue(`INSERT INTO tenants (id,name,domain,microsoft_tenant_id,status,users,last_graph_test,modules) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			t.ID, t.Name, t.Domain, t.MicrosoftTenantID, t.Status, t.Users, t.LastGraphTest, t.Modules)
	}
	for _, st := range seed.AppSettings {
		batch.Queue(`INSERT INTO app_settings (key,label,description,enabled,locked,value) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			st.Key, st.Label, st.Description, st.Enabled, st.Locked, st.Value)
	}
	// Jobs, changes, audit, and working sets are never seeded: those tables
	// only contain what the platform actually did.
	return s.pool.SendBatch(ctx, batch).Close()
}

func (s *PG) Tenants(ctx context.Context) ([]model.Tenant, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,domain,microsoft_tenant_id,status,users,last_graph_test,modules,
		client_id <> '', exchange_client_id <> '', sharepoint_admin_url <> '' FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Tenant
	for rows.Next() {
		var t model.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Domain, &t.MicrosoftTenantID, &t.Status, &t.Users, &t.LastGraphTest, &t.Modules,
			&t.Connections.Graph, &t.Connections.Exchange, &t.Connections.SharePoint); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PG) Tenant(ctx context.Context, id string) (model.Tenant, error) {
	var t model.Tenant
	err := s.pool.QueryRow(ctx, `SELECT id,name,domain,microsoft_tenant_id,status,users,last_graph_test,modules,
		client_id <> '', exchange_client_id <> '', sharepoint_admin_url <> '' FROM tenants WHERE id=$1`, id).
		Scan(&t.ID, &t.Name, &t.Domain, &t.MicrosoftTenantID, &t.Status, &t.Users, &t.LastGraphTest, &t.Modules,
			&t.Connections.Graph, &t.Connections.Exchange, &t.Connections.SharePoint)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Tenant{}, ErrNotFound
	}
	return t, err
}

func (s *PG) TenantPreflight(ctx context.Context, tenantID string) (model.Preflight, error) {
	var preflight model.Preflight
	var ranAt time.Time
	var checks []byte
	err := s.pool.QueryRow(ctx, `SELECT mode,ran_at,checks FROM tenant_preflight_snapshots WHERE tenant_id=$1`, tenantID).
		Scan(&preflight.Mode, &ranAt, &checks)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Preflight{}, ErrNotFound
	}
	if err != nil {
		return model.Preflight{}, err
	}
	if err := json.Unmarshal(checks, &preflight.Checks); err != nil {
		return model.Preflight{}, err
	}
	preflight.RanAt = ranAt.UTC().Format(time.RFC3339)
	return preflight, nil
}

func (s *PG) UpsertTenantPreflight(ctx context.Context, tenantID string, preflight model.Preflight) error {
	ranAt, err := time.Parse(time.RFC3339, preflight.RanAt)
	if err != nil {
		return fmt.Errorf("parse preflight ranAt: %w", err)
	}
	checks, err := json.Marshal(preflight.Checks)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO tenant_preflight_snapshots (tenant_id,mode,ran_at,checks)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (tenant_id) DO UPDATE SET mode=EXCLUDED.mode,ran_at=EXCLUDED.ran_at,checks=EXCLUDED.checks`,
		tenantID, preflight.Mode, ranAt, checks)
	return err
}

func (s *PG) CreateTenant(ctx context.Context, nt NewTenant) (model.Tenant, error) {
	if err := s.sealTenantSecrets(&nt); err != nil {
		return model.Tenant{}, err
	}
	created := model.Tenant{
		ID: "ten_" + randID(), Name: nt.Name, Domain: nt.Domain,
		MicrosoftTenantID: nt.MicrosoftTenantID, Status: "Disconnected",
		Users: 0, LastGraphTest: "—",
		Modules: []string{"Users", "Groups", "Exchange", "SharePoint", "Licensing"},
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenants (id,name,domain,microsoft_tenant_id,status,users,last_graph_test,modules,
			client_id,client_secret,
			exchange_client_id,exchange_client_secret,
			sharepoint_client_id,sharepoint_client_secret,sharepoint_admin_url)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		created.ID, created.Name, created.Domain, created.MicrosoftTenantID, created.Status,
		created.Users, created.LastGraphTest, created.Modules, nt.ClientID, nt.ClientSecret,
		nt.ExchangeClientID, nt.ExchangeClientSecret,
		nt.SharePointClientID, nt.SharePointClientSecret, nt.SharePointAdminURL)
	created.Connections = connectionsFor(TenantCreds{
		ClientID: nt.ClientID, ExchangeClientID: nt.ExchangeClientID, SharePointClientID: nt.SharePointClientID,
		SharePointAdminURL: nt.SharePointAdminURL,
	})
	return created, err
}

func (s *PG) UpdateTenant(ctx context.Context, id string, update TenantUpdate) (model.Tenant, error) {
	tenant, err := s.Tenant(ctx, id)
	if err != nil {
		return model.Tenant{}, err
	}
	creds, err := s.TenantCreds(ctx, id)
	if err != nil {
		return model.Tenant{}, err
	}
	applyTenantUpdate(&tenant, &creds, update)
	graphSecret, err := s.protector.Seal(creds.ClientSecret)
	if err != nil {
		return model.Tenant{}, err
	}
	exchangeSecret, err := s.protector.Seal(creds.ExchangeClientSecret)
	if err != nil {
		return model.Tenant{}, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE tenants SET
		name=$2,domain=$3,microsoft_tenant_id=$4,
		client_id=$5,client_secret=$6,
		exchange_client_id=$7,exchange_client_secret=$8,
		sharepoint_admin_url=$9
		WHERE id=$1`,
		id, tenant.Name, tenant.Domain, tenant.MicrosoftTenantID,
		creds.ClientID, graphSecret, creds.ExchangeClientID, exchangeSecret,
		creds.SharePointAdminURL)
	if err != nil {
		return model.Tenant{}, err
	}
	if tag.RowsAffected() == 0 {
		return model.Tenant{}, ErrNotFound
	}
	tenant.Connections = connectionsFor(creds)
	return tenant, nil
}

func (s *PG) DeleteTenant(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// A cross-tenant storyline is invalid once any affected tenant is removed;
	// the next ingestion cycle can rebuild a valid reduced storyline if needed.
	if _, err := tx.Exec(ctx, `DELETE FROM security_storylines WHERE tenant_ids @> to_jsonb(ARRAY[$1]::TEXT[])`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Rule revisions cascade from the scoped rule. Global rules remain.
	if _, err := tx.Exec(ctx, `DELETE FROM security_detection_rules WHERE scope='tenant' AND tenant_id=$1`, id); err != nil {
		return err
	}
	// Cascade: revoke every technician grant on this tenant.
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_access WHERE tenant_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PG) UpdateTenantStatus(ctx context.Context, id, status, lastGraphTest string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE tenants SET status=$2, last_graph_test=$3 WHERE id=$1`, id, status, lastGraphTest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PG) ThreatLockerGlobalConfig(ctx context.Context) (ThreatLockerGlobalConfig, error) {
	var c ThreatLockerGlobalConfig
	err := s.pool.QueryRow(ctx, `SELECT instance,token,parent_org_id FROM threatlocker_global_config WHERE singleton=true`).
		Scan(&c.Instance, &c.Token, &c.ParentOrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ThreatLockerGlobalConfig{}, nil
	}
	if err != nil {
		return c, err
	}
	c.Token, err = s.protector.Open(c.Token)
	return c, err
}

func (s *PG) UpdateThreatLockerGlobalConfig(ctx context.Context, c ThreatLockerGlobalConfig) error {
	sealed, err := s.protector.Seal(c.Token)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO threatlocker_global_config (singleton,instance,token,parent_org_id)
		VALUES (true,$1,$2,$3)
		ON CONFLICT (singleton) DO UPDATE SET instance=EXCLUDED.instance,token=EXCLUDED.token,parent_org_id=EXCLUDED.parent_org_id,updated_at=now()`,
		c.Instance, sealed, c.ParentOrgID)
	return err
}

func (s *PG) TLAppCleanupOperations(ctx context.Context, tenantID string) ([]model.TLAppCleanupOperation, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,tenant_id,status,requested_by,fingerprint,request_payload,result_payload,error,created_at,updated_at
		FROM threatlocker_cleanup_operations WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.TLAppCleanupOperation
	for rows.Next() {
		operation, err := scanTLAppCleanupOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, operation)
	}
	return out, rows.Err()
}

func (s *PG) ActiveTLAppCleanupOperation(ctx context.Context, fingerprint string) (model.TLAppCleanupOperation, error) {
	row := s.pool.QueryRow(ctx, `SELECT id,tenant_id,status,requested_by,fingerprint,request_payload,result_payload,error,created_at,updated_at
		FROM threatlocker_cleanup_operations
		WHERE fingerprint=$1 AND status IN ('submitted','verification_pending','needs_reconciliation')
		ORDER BY created_at DESC LIMIT 1`, fingerprint)
	operation, err := scanTLAppCleanupOperation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.TLAppCleanupOperation{}, ErrNotFound
	}
	return operation, err
}

func (s *PG) CreateTLAppCleanupOperation(ctx context.Context, operation model.TLAppCleanupOperation) (model.TLAppCleanupOperation, error) {
	if operation.ID == "" {
		operation.ID = "tlop_" + randID()
	}
	now := time.Now().UTC()
	if operation.CreatedAt.IsZero() {
		operation.CreatedAt = now
	}
	if operation.UpdatedAt.IsZero() {
		operation.UpdatedAt = operation.CreatedAt
	}
	requestPayload, err := json.Marshal(operation.Request)
	if err != nil {
		return operation, err
	}
	resultPayload, err := json.Marshal(operation.Result)
	if err != nil {
		return operation, err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO threatlocker_cleanup_operations
		(id,tenant_id,status,requested_by,fingerprint,request_payload,result_payload,error,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		operation.ID, operation.TenantID, operation.Status, operation.RequestedBy, operation.Fingerprint,
		requestPayload, resultPayload, operation.Error, operation.CreatedAt, operation.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return model.TLAppCleanupOperation{}, ErrConflict
		}
	}
	return operation, err
}

func (s *PG) UpdateTLAppCleanupOperation(ctx context.Context, id, status string, result model.TLAppCleanupResult, errorMessage string) error {
	resultPayload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE threatlocker_cleanup_operations
		SET status=$2,result_payload=$3,error=$4,updated_at=now() WHERE id=$1`,
		id, status, resultPayload, errorMessage)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type tlCleanupRow interface {
	Scan(dest ...any) error
}

func scanTLAppCleanupOperation(row tlCleanupRow) (model.TLAppCleanupOperation, error) {
	var (
		operation      model.TLAppCleanupOperation
		requestPayload []byte
		resultPayload  []byte
	)
	err := row.Scan(
		&operation.ID, &operation.TenantID, &operation.Status, &operation.RequestedBy,
		&operation.Fingerprint, &requestPayload, &resultPayload, &operation.Error,
		&operation.CreatedAt, &operation.UpdatedAt,
	)
	if err != nil {
		return operation, err
	}
	if len(requestPayload) > 0 {
		if err := json.Unmarshal(requestPayload, &operation.Request); err != nil {
			return operation, err
		}
	}
	if len(resultPayload) > 0 {
		if err := json.Unmarshal(resultPayload, &operation.Result); err != nil {
			return operation, err
		}
	}
	return operation, nil
}

// ---- SharePoint inventory ----

func (s *PG) CreateSharePointScan(ctx context.Context, scan model.SharePointScan) (model.SharePointScan, error) {
	if scan.ID == "" {
		scan.ID = "spscan_" + randID()
	}
	if scan.StartedAt == "" {
		scan.StartedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if scan.Coverage == "" {
		scan.Coverage = "pending"
	}
	started, err := time.Parse(time.RFC3339, scan.StartedAt)
	if err != nil {
		return scan, fmt.Errorf("sharepoint scan startedAt: %w", err)
	}
	warnings, err := json.Marshal(scan.Warnings)
	if err != nil {
		return scan, err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO sharepoint_scans
		(id,tenant_id,scope,site_id,node_id,status,trigger,started_by,started_at,coverage,warnings)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		scan.ID, scan.TenantID, scan.Scope, scan.SiteID, scan.NodeID, scan.Status,
		scan.Trigger, scan.StartedBy, started, scan.Coverage, warnings)
	return scan, err
}

func (s *PG) CompleteSharePointScan(ctx context.Context, scan model.SharePointScan, nodes []model.SharePointInventoryNode) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var completed any
	if scan.CompletedAt != "" {
		tm, err := time.Parse(time.RFC3339, scan.CompletedAt)
		if err != nil {
			return fmt.Errorf("sharepoint scan completedAt: %w", err)
		}
		completed = tm
	}
	warnings, err := json.Marshal(scan.Warnings)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE sharepoint_scans SET
		status=$2,completed_at=$3,coverage=$4,site_count=$5,library_count=$6,
		folder_count=$7,file_count=$8,total_bytes=$9,unique_permission_count=$10,
		warnings=$11,error=$12 WHERE id=$1`,
		scan.ID, scan.Status, completed, scan.Coverage, scan.SiteCount,
		scan.LibraryCount, scan.FolderCount, scan.FileCount, scan.TotalBytes,
		scan.UniquePermissionCount, warnings, scan.Error)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sharepoint_inventory_nodes WHERE tenant_id=$1 AND scope=$2`,
		scan.TenantID, scan.Scope); err != nil {
		return err
	}
	for _, n := range nodes {
		lastScanned := completed
		if n.LastScannedAt != "" {
			tm, err := time.Parse(time.RFC3339, n.LastScannedAt)
			if err != nil {
				return fmt.Errorf("sharepoint node lastScannedAt: %w", err)
			}
			lastScanned = tm
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sharepoint_inventory_nodes
			(tenant_id,scope,scan_id,id,parent_id,site_id,drive_id,item_id,kind,name,path,
			 web_url,size_bytes,file_count,has_unique_permissions,external_sharing,last_scanned_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			n.TenantID, scan.Scope, scan.ID, n.ID, n.ParentID, n.SiteID, n.DriveID,
			n.ItemID, n.Kind, n.Name, n.Path, n.WebURL, n.SizeBytes, n.FileCount,
			n.HasUniquePermissions, n.ExternalSharing, lastScanned); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PG) SharePointScans(ctx context.Context, tenantID string) ([]model.SharePointScan, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,tenant_id,scope,site_id,node_id,status,trigger,
		started_by,started_at,completed_at,coverage,site_count,library_count,folder_count,
		file_count,total_bytes,unique_permission_count,warnings,error
		FROM sharepoint_scans WHERE tenant_id=$1 ORDER BY started_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SharePointScan
	for rows.Next() {
		scan, err := scanSharePointScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, scan)
	}
	return out, rows.Err()
}

func (s *PG) SharePointInventory(ctx context.Context, tenantID, scope string) (model.SharePointInventory, error) {
	row := s.pool.QueryRow(ctx, `SELECT id,tenant_id,scope,site_id,node_id,status,trigger,
		started_by,started_at,completed_at,coverage,site_count,library_count,folder_count,
		file_count,total_bytes,unique_permission_count,warnings,error
		FROM sharepoint_scans WHERE tenant_id=$1 AND scope=$2 AND status IN ('completed','partial')
		ORDER BY started_at DESC LIMIT 1`, tenantID, scope)
	scan, err := scanSharePointScan(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SharePointInventory{}, ErrNotFound
	}
	if err != nil {
		return model.SharePointInventory{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id,parent_id,site_id,drive_id,item_id,kind,name,path,
		web_url,size_bytes,file_count,has_unique_permissions,external_sharing,last_scanned_at
		FROM sharepoint_inventory_nodes WHERE tenant_id=$1 AND scope=$2 AND scan_id=$3
		ORDER BY kind,path`, tenantID, scope, scan.ID)
	if err != nil {
		return model.SharePointInventory{}, err
	}
	defer rows.Close()
	nodes := []model.SharePointInventoryNode{}
	for rows.Next() {
		n := model.SharePointInventoryNode{TenantID: tenantID, ScanID: scan.ID}
		var last time.Time
		if err := rows.Scan(&n.ID, &n.ParentID, &n.SiteID, &n.DriveID, &n.ItemID,
			&n.Kind, &n.Name, &n.Path, &n.WebURL, &n.SizeBytes, &n.FileCount,
			&n.HasUniquePermissions, &n.ExternalSharing, &last); err != nil {
			return model.SharePointInventory{}, err
		}
		n.LastScannedAt = last.UTC().Format(time.RFC3339)
		nodes = append(nodes, n)
	}
	return model.SharePointInventory{Scan: scan, Nodes: nodes}, rows.Err()
}

type sharePointScanRow interface {
	Scan(dest ...any) error
}

func scanSharePointScan(row sharePointScanRow) (model.SharePointScan, error) {
	var scan model.SharePointScan
	var started time.Time
	var completed *time.Time
	var warnings []byte
	err := row.Scan(&scan.ID, &scan.TenantID, &scan.Scope, &scan.SiteID, &scan.NodeID,
		&scan.Status, &scan.Trigger, &scan.StartedBy, &started, &completed, &scan.Coverage,
		&scan.SiteCount, &scan.LibraryCount, &scan.FolderCount, &scan.FileCount,
		&scan.TotalBytes, &scan.UniquePermissionCount, &warnings, &scan.Error)
	if err != nil {
		return scan, err
	}
	scan.StartedAt = started.UTC().Format(time.RFC3339)
	if completed != nil {
		scan.CompletedAt = completed.UTC().Format(time.RFC3339)
	}
	if len(warnings) > 0 {
		_ = json.Unmarshal(warnings, &scan.Warnings)
	}
	return scan, nil
}

func (s *PG) TenantCreds(ctx context.Context, id string) (TenantCreds, error) {
	var c TenantCreds
	err := s.pool.QueryRow(ctx, `SELECT microsoft_tenant_id,domain,client_id,client_secret,
		exchange_client_id,exchange_client_secret,
		sharepoint_client_id,sharepoint_client_secret,sharepoint_admin_url FROM tenants WHERE id=$1`, id).
		Scan(&c.MicrosoftTenantID, &c.Domain, &c.ClientID, &c.ClientSecret,
			&c.ExchangeClientID, &c.ExchangeClientSecret,
			&c.SharePointClientID, &c.SharePointClientSecret, &c.SharePointAdminURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantCreds{}, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	return c, s.openTenantSecrets(&c)
}

func (s *PG) WorkingSets(ctx context.Context) ([]model.WorkingSet, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,description,type,items,COALESCE(tenant_id,''),tenant,user_ids,created_by,last_used FROM working_sets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.WorkingSet
	for rows.Next() {
		var w model.WorkingSet
		if err := rows.Scan(&w.ID, &w.Name, &w.Description, &w.Type, &w.Items, &w.TenantID, &w.Tenant, &w.UserIDs, &w.CreatedBy, &w.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *PG) WorkingSet(ctx context.Context, id string) (model.WorkingSet, error) {
	var ws model.WorkingSet
	err := s.pool.QueryRow(ctx, `SELECT id,name,description,type,items,COALESCE(tenant_id,''),tenant,user_ids,created_by,last_used FROM working_sets WHERE id=$1`, id).
		Scan(&ws.ID, &ws.Name, &ws.Description, &ws.Type, &ws.Items, &ws.TenantID, &ws.Tenant, &ws.UserIDs, &ws.CreatedBy, &ws.LastUsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.WorkingSet{}, ErrNotFound
	}
	return ws, err
}

func (s *PG) CreateWorkingSet(ctx context.Context, ws NewWorkingSet) (model.WorkingSet, error) {
	created := model.WorkingSet{
		ID: "ws_" + randID(), Name: ws.Name, Description: ws.Description, Type: "Users", Items: len(ws.UserIDs),
		TenantID: ws.TenantID, Tenant: ws.Tenant, UserIDs: append([]string(nil), ws.UserIDs...), CreatedBy: ws.CreatedBy, LastUsed: "just now",
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO working_sets (id,name,description,type,items,tenant_id,tenant,user_ids,created_by,last_used) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		created.ID, created.Name, created.Description, created.Type, created.Items, created.TenantID, created.Tenant, created.UserIDs, created.CreatedBy, created.LastUsed)
	return created, err
}

func (s *PG) UpdateWorkingSet(ctx context.Context, id string, update WorkingSetUpdate) (model.WorkingSet, error) {
	result, err := s.pool.Exec(ctx, `UPDATE working_sets SET name=$2,description=$3,user_ids=$4,items=$5 WHERE id=$1`,
		id, update.Name, update.Description, update.UserIDs, len(update.UserIDs))
	if err != nil {
		return model.WorkingSet{}, err
	}
	if result.RowsAffected() == 0 {
		return model.WorkingSet{}, ErrNotFound
	}
	return s.WorkingSet(ctx, id)
}

func (s *PG) Jobs(ctx context.Context) ([]model.Job, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,type,tenant,status,progress,started,duration,triggered_by,acknowledged FROM jobs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Job
	for rows.Next() {
		var j model.Job
		if err := rows.Scan(&j.ID, &j.Type, &j.Tenant, &j.Status, &j.Progress, &j.Started, &j.Duration, &j.TriggeredBy, &j.Acknowledged); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *PG) CreateJob(ctx context.Context, j model.Job) (model.Job, error) {
	if j.ID == "" {
		j.ID = "job_" + randID()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO jobs (id,type,tenant,status,progress,started,duration,triggered_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		j.ID, j.Type, j.Tenant, j.Status, j.Progress, j.Started, j.Duration, j.TriggeredBy)
	return j, err
}

func (s *PG) UpdateJobStatus(ctx context.Context, id, status string, progress int) error {
	_, err := s.pool.Exec(ctx, `UPDATE jobs SET status=$2, progress=$3 WHERE id=$1`, id, status, progress)
	return err
}

func (s *PG) CompleteJob(ctx context.Context, id, status, duration string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE jobs SET status=$2, progress=100, duration=$3 WHERE id=$1`, id, status, duration)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PG) AcknowledgeJob(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE jobs SET acknowledged=true WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PG) Changes(ctx context.Context) ([]model.Change, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,ts,technician,tenant,action,target,status,revert FROM change_history ORDER BY sort_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Change
	for rows.Next() {
		var c model.Change
		if err := rows.Scan(&c.ID, &c.Timestamp, &c.Technician, &c.Tenant, &c.Action, &c.Target, &c.Status, &c.Revert); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// changeDetailDoc is the JSONB payload persisted alongside a change record.
type changeDetailDoc struct {
	GraphRequestID string   `json:"graphRequestId"`
	RevertEligible bool     `json:"revertEligible"`
	Before         []string `json:"before"`
	After          []string `json:"after"`
	ExecutionLog   []string `json:"executionLog"`
	RevertPayload  string   `json:"revertPayload,omitempty"`
}

func (s *PG) Change(ctx context.Context, id string) (model.ChangeDetail, error) {
	var (
		c   model.Change
		doc changeDetailDoc
	)
	err := s.pool.QueryRow(ctx, `SELECT id,ts,technician,tenant,action,target,status,revert,detail FROM change_history WHERE id=$1`, id).
		Scan(&c.ID, &c.Timestamp, &c.Technician, &c.Tenant, &c.Action, &c.Target, &c.Status, &c.Revert, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ChangeDetail{}, ErrNotFound
	}
	if err != nil {
		return model.ChangeDetail{}, err
	}
	return model.ChangeDetail{
		Change: c, GraphRequestID: doc.GraphRequestID, RevertEligible: doc.RevertEligible,
		Before: doc.Before, After: doc.After, ExecutionLog: doc.ExecutionLog, RevertPayload: doc.RevertPayload,
	}, nil
}

func (s *PG) AppendChange(ctx context.Context, c model.ChangeDetail) error {
	if c.ID == "" {
		c.ID = "chg_" + randID()
	}
	doc := changeDetailDoc{
		GraphRequestID: c.GraphRequestID, RevertEligible: c.RevertEligible,
		Before: c.Before, After: c.After, ExecutionLog: c.ExecutionLog, RevertPayload: c.RevertPayload,
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO change_history (id,ts,technician,tenant,action,target,status,revert,detail) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ID, c.Timestamp, c.Technician, c.Tenant, c.Action, c.Target, c.Status, c.Revert, doc)
	return err
}

func (s *PG) UpdateChangeRevert(ctx context.Context, id, revert string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE change_history SET revert=$2 WHERE id=$1`, id, revert)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SecurityIncidentStates returns RTM receipt timestamps plus local owner/status
// overlays. Provider incident content stays in Microsoft Defender and is
// fetched on demand.
func (s *PG) SecurityIncidentStates(ctx context.Context) ([]model.SecurityIncidentState, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id,incident_id,status,owner,received_at,updated_by,updated_at
		FROM security_incident_states ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityIncidentState
	for rows.Next() {
		var state model.SecurityIncidentState
		if err := rows.Scan(&state.TenantID, &state.IncidentID, &state.Status, &state.Owner, &state.ReceivedAt, &state.UpdatedBy, &state.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	return out, rows.Err()
}

func (s *PG) ObserveSecurityIncident(ctx context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error) {
	if state.Status == "" {
		state.Status = model.SecurityTriageNew
	}
	if state.ReceivedAt.IsZero() {
		state.ReceivedAt = time.Now().UTC()
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = state.ReceivedAt
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO security_incident_states
			(tenant_id,incident_id,status,owner,received_at,updated_by,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_id,incident_id) DO UPDATE SET
			incident_id=security_incident_states.incident_id
		RETURNING status,owner,received_at,updated_by,updated_at`,
		state.TenantID, state.IncidentID, state.Status, state.Owner,
		state.ReceivedAt, state.UpdatedBy, state.UpdatedAt).
		Scan(&state.Status, &state.Owner, &state.ReceivedAt, &state.UpdatedBy, &state.UpdatedAt)
	return state, err
}

func (s *PG) UpsertSecurityIncidentState(ctx context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error) {
	if state.ReceivedAt.IsZero() {
		state.ReceivedAt = time.Now().UTC()
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO security_incident_states
			(tenant_id,incident_id,status,owner,received_at,updated_by,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (tenant_id,incident_id) DO UPDATE SET
			status=EXCLUDED.status, owner=EXCLUDED.owner,
			updated_by=EXCLUDED.updated_by, updated_at=now()
		RETURNING received_at,updated_at`,
		state.TenantID, state.IncidentID, state.Status, state.Owner, state.ReceivedAt, state.UpdatedBy).
		Scan(&state.ReceivedAt, &state.UpdatedAt)
	return state, err
}

func scanSecurityAuditCheckpoint(row pgx.Row) (model.SecurityAuditCheckpoint, error) {
	var checkpoint model.SecurityAuditCheckpoint
	var lastEventAt sql.NullTime
	err := row.Scan(
		&checkpoint.TenantID, &checkpoint.ContentType, &checkpoint.Status,
		&checkpoint.Mode, &checkpoint.Detail, &checkpoint.CursorEnd,
		&checkpoint.LastPolledAt, &lastEventAt, &checkpoint.EventsReceived,
		&checkpoint.EventsInserted,
	)
	if lastEventAt.Valid {
		checkpoint.LastEventAt = lastEventAt.Time
	}
	return checkpoint, err
}

func (s *PG) SecurityAuditCheckpoints(ctx context.Context) ([]model.SecurityAuditCheckpoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id,content_type,status,mode,detail,cursor_end,
		       last_polled_at,last_event_at,events_received,events_inserted
		FROM security_audit_checkpoints ORDER BY tenant_id,content_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityAuditCheckpoint
	for rows.Next() {
		checkpoint, err := scanSecurityAuditCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, checkpoint)
	}
	return out, rows.Err()
}

func (s *PG) SecurityAuditCheckpoint(ctx context.Context, tenantID, contentType string) (model.SecurityAuditCheckpoint, error) {
	checkpoint, err := scanSecurityAuditCheckpoint(s.pool.QueryRow(ctx, `
		SELECT tenant_id,content_type,status,mode,detail,cursor_end,
		       last_polled_at,last_event_at,events_received,events_inserted
		FROM security_audit_checkpoints WHERE tenant_id=$1 AND content_type=$2`, tenantID, contentType))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityAuditCheckpoint{}, ErrNotFound
	}
	return checkpoint, err
}

func scanSecurityHistoryImport(row pgx.Row) (model.SecurityHistoryImport, error) {
	var history model.SecurityHistoryImport
	var startedAt, completedAt, incidentCutoffAt sql.NullTime
	err := row.Scan(
		&history.TenantID, &history.TenantName, &history.JobID,
		&history.RequestedWindow, &history.WindowHours, &history.HistoricalIncidentMode,
		&history.Status, &history.Progress, &history.FeedsCompleted, &history.FeedsTotal,
		&history.EventsReceived, &history.EventsInserted, &history.DetectionsCreated,
		&history.Detail, &history.RequestedAt, &startedAt, &completedAt,
		&incidentCutoffAt,
	)
	if startedAt.Valid {
		history.StartedAt = startedAt.Time
	}
	if completedAt.Valid {
		history.CompletedAt = completedAt.Time
	}
	if incidentCutoffAt.Valid {
		history.IncidentCutoffAt = incidentCutoffAt.Time
	}
	return history, err
}

const securityHistorySelect = `
	SELECT history.tenant_id,tenant.name,history.job_id,history.requested_window,
	       history.window_hours,history.historical_incident_mode,history.status,
	       history.progress,history.feeds_completed,history.feeds_total,
	       history.events_received,history.events_inserted,history.detections_created,
	       history.detail,history.requested_at,history.started_at,history.completed_at,
	       history.incident_cutoff_at
	FROM security_history_imports history
	JOIN tenants tenant ON tenant.id=history.tenant_id`

func (s *PG) SecurityHistoryImports(ctx context.Context) ([]model.SecurityHistoryImport, error) {
	rows, err := s.pool.Query(ctx, securityHistorySelect+` ORDER BY history.requested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.SecurityHistoryImport, 0)
	for rows.Next() {
		history, err := scanSecurityHistoryImport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, history)
	}
	return out, rows.Err()
}

func (s *PG) SecurityHistoryImport(ctx context.Context, tenantID string) (model.SecurityHistoryImport, error) {
	history, err := scanSecurityHistoryImport(s.pool.QueryRow(ctx, securityHistorySelect+` WHERE history.tenant_id=$1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityHistoryImport{}, ErrNotFound
	}
	return history, err
}

func (s *PG) UpsertSecurityHistoryImport(ctx context.Context, history model.SecurityHistoryImport) (model.SecurityHistoryImport, error) {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO security_history_imports
		(tenant_id,job_id,requested_window,window_hours,historical_incident_mode,status,
		 progress,feeds_completed,feeds_total,events_received,events_inserted,detections_created,
		 detail,requested_at,started_at,completed_at,incident_cutoff_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (tenant_id) DO UPDATE SET
		job_id=EXCLUDED.job_id,requested_window=EXCLUDED.requested_window,
		window_hours=EXCLUDED.window_hours,historical_incident_mode=EXCLUDED.historical_incident_mode,
		status=EXCLUDED.status,progress=EXCLUDED.progress,feeds_completed=EXCLUDED.feeds_completed,
		feeds_total=EXCLUDED.feeds_total,events_received=EXCLUDED.events_received,
		events_inserted=EXCLUDED.events_inserted,detections_created=EXCLUDED.detections_created,
		detail=EXCLUDED.detail,requested_at=EXCLUDED.requested_at,started_at=EXCLUDED.started_at,
		completed_at=EXCLUDED.completed_at,incident_cutoff_at=EXCLUDED.incident_cutoff_at`,
		history.TenantID, history.JobID, history.RequestedWindow, history.WindowHours,
		history.HistoricalIncidentMode, history.Status, history.Progress, history.FeedsCompleted,
		history.FeedsTotal, history.EventsReceived, history.EventsInserted, history.DetectionsCreated,
		history.Detail, history.RequestedAt, nullableTime(history.StartedAt), nullableTime(history.CompletedAt),
		nullableTime(history.IncidentCutoffAt))
	if err != nil {
		return model.SecurityHistoryImport{}, err
	}
	return s.SecurityHistoryImport(ctx, history.TenantID)
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func scanSecurityAuditEvent(row pgx.Row) (model.SecurityAuditEvent, error) {
	var event model.SecurityAuditEvent
	var raw []byte
	err := row.Scan(
		&event.ID, &event.TenantID, &event.ProviderRecordID, &event.ContentType,
		&event.Workload, &event.Operation, &event.Actor, &event.ClientIP,
		&event.ObjectID, &event.ResultStatus, &event.OccurredAt,
		&event.AvailableAt, &event.IngestedAt, &event.Sources, &raw, &event.Sample,
	)
	event.Raw = append([]byte(nil), raw...)
	return event, err
}

func (s *PG) SecurityAuditEventsSince(ctx context.Context, since time.Time) ([]model.SecurityAuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id,tenant_id,provider_record_id,content_type,workload,operation,
		       actor,client_ip,object_id,result_status,occurred_at,available_at,ingested_at,sources,raw,sample
		FROM security_audit_events WHERE occurred_at >= $1 AND canonical_event_id IS NULL
		ORDER BY occurred_at DESC LIMIT 50000`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.SecurityAuditEvent, 0)
	for rows.Next() {
		event, err := scanSecurityAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *PG) SecurityAuditEventsByIDs(ctx context.Context, eventIDs []string) ([]model.SecurityAuditEvent, error) {
	if len(eventIDs) == 0 {
		return []model.SecurityAuditEvent{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,tenant_id,provider_record_id,content_type,workload,operation,
		       actor,client_ip,object_id,result_status,occurred_at,available_at,ingested_at,sources,raw,sample
		FROM security_audit_events WHERE id = ANY($1)`, eventIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.SecurityAuditEvent, 0, len(eventIDs))
	for rows.Next() {
		event, err := scanSecurityAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *PG) SearchSecurityAuditEvents(ctx context.Context, query model.SecurityAuditEventSearch) ([]model.SecurityAuditEvent, bool, error) {
	limit := query.Limit
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	args := []any{query.From, query.To}
	conditions := []string{"occurred_at >= $1", "occurred_at <= $2", "canonical_event_id IS NULL"}
	add := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(args)))
	}
	if query.TenantID != "" {
		add("tenant_id = $%d", query.TenantID)
	}
	if query.Workload != "" {
		add("lower(workload) = lower($%d)", query.Workload)
	}
	if query.Operation != "" {
		add("operation ILIKE '%%' || $%d || '%%'", query.Operation)
	}
	if query.Actor != "" {
		add("actor ILIKE '%%' || $%d || '%%'", query.Actor)
	}
	if query.ClientIP != "" {
		add("client_ip ILIKE '%%' || $%d || '%%'", query.ClientIP)
	}
	if query.Result != "" {
		add("lower(result_status) = lower($%d)", query.Result)
	}
	if query.Query != "" {
		add("concat_ws(' ',workload,operation,actor,client_ip,object_id,result_status) ILIKE '%%' || $%d || '%%'", query.Query)
	}
	args = append(args, limit+1, query.Offset)
	statement := fmt.Sprintf(`
		SELECT id,tenant_id,provider_record_id,content_type,workload,operation,
		       actor,client_ip,object_id,result_status,occurred_at,available_at,ingested_at,sources,raw,sample
		FROM security_audit_events WHERE %s
		ORDER BY occurred_at DESC,id DESC LIMIT $%d OFFSET $%d`,
		strings.Join(conditions, " AND "), len(args)-1, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	events := make([]model.SecurityAuditEvent, 0, limit+1)
	for rows.Next() {
		event, err := scanSecurityAuditEvent(rows)
		if err != nil {
			return nil, false, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	return events, hasMore, nil
}

func (s *PG) SecurityAuditEvent(ctx context.Context, tenantID, eventID string) (model.SecurityAuditEvent, error) {
	event, err := scanSecurityAuditEvent(s.pool.QueryRow(ctx, `
		SELECT id,tenant_id,provider_record_id,content_type,workload,operation,
		       actor,client_ip,object_id,result_status,occurred_at,available_at,ingested_at,sources,raw,sample
		FROM security_audit_events WHERE tenant_id=$1 AND id=$2`, tenantID, eventID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityAuditEvent{}, ErrNotFound
	}
	return event, err
}

func (s *PG) SecurityAuditEventEvidence(ctx context.Context, tenantID, eventID string) ([]model.SecurityAuditEventEvidence, error) {
	rows, err := s.pool.Query(ctx, `
		WITH requested AS (
			SELECT COALESCE(canonical_event_id,id) AS event_id
			FROM security_audit_events WHERE tenant_id=$1 AND id=$2
		)
		SELECT alias.source,alias.provider_record_id,alias.content_type,
		       alias.available_at,alias.ingested_at,alias.raw
		FROM security_audit_event_aliases alias
		JOIN requested ON requested.event_id=alias.event_id
		WHERE alias.tenant_id=$1 AND alias.raw IS NOT NULL
		  AND alias.source <> 'historical_backfill'
		ORDER BY CASE alias.source WHEN 'entra_graph' THEN 0 WHEN 'm365_audit' THEN 1 ELSE 2 END,
		         alias.available_at,alias.provider_record_id`, tenantID, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.SecurityAuditEventEvidence, 0, 2)
	for rows.Next() {
		var evidence model.SecurityAuditEventEvidence
		var raw []byte
		if err := rows.Scan(&evidence.Source, &evidence.ProviderRecordID, &evidence.ContentType,
			&evidence.AvailableAt, &evidence.IngestedAt, &raw); err != nil {
			return nil, err
		}
		evidence.Raw = append([]byte(nil), raw...)
		out = append(out, evidence)
	}
	return out, rows.Err()
}

func (s *PG) StoreSecurityAuditBatch(ctx context.Context, checkpoint model.SecurityAuditCheckpoint, events []model.SecurityAuditEvent, detections []model.SecurityNativeDetection) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Identity and unified-audit pollers can overlap. Serialize writes for this
	// tenant so two workers cannot both miss the semantic match and insert a
	// second canonical copy.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, checkpoint.TenantID); err != nil {
		return 0, err
	}
	inserted := 0
	canonicalEventIDs := make(map[string]string, len(events))
	for _, event := range events {
		if event.AvailableAt.IsZero() {
			event.AvailableAt = event.IngestedAt
		}
		if len(event.Sources) == 0 {
			event.Sources = []string{"m365_audit"}
		}
		semanticKey := securityEventSemanticKey(event)
		var canonicalID string
		var providerRecordExists bool
		lookupErr := tx.QueryRow(ctx, `
			SELECT COALESCE(canonical_event_id,id), provider_record_id=$2
			FROM security_audit_events
			WHERE tenant_id=$1 AND (
				provider_record_id=$2 OR
				($3 <> '' AND semantic_key=$3 AND canonical_event_id IS NULL
				 AND occurred_at BETWEEN $4::timestamptz - interval '10 seconds' AND $4::timestamptz + interval '10 seconds'))
			ORDER BY CASE WHEN provider_record_id=$2 THEN 0 ELSE 1 END,
			         abs(extract(epoch FROM (occurred_at-$4::timestamptz))), id
			LIMIT 1`, event.TenantID, event.ProviderRecordID, semanticKey, event.OccurredAt).Scan(&canonicalID, &providerRecordExists)
		if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
			return 0, lookupErr
		}
		if errors.Is(lookupErr, pgx.ErrNoRows) {
			if err := tx.QueryRow(ctx, `
				INSERT INTO security_audit_events
				(id,tenant_id,provider_record_id,content_type,workload,operation,actor,client_ip,object_id,result_status,occurred_at,available_at,ingested_at,sources,raw,sample,semantic_key)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
				RETURNING id`,
				event.ID, event.TenantID, event.ProviderRecordID, event.ContentType,
				event.Workload, event.Operation, event.Actor, event.ClientIP,
				event.ObjectID, event.ResultStatus, event.OccurredAt, event.AvailableAt, event.IngestedAt,
				event.Sources, []byte(event.Raw), event.Sample, semanticKey).Scan(&canonicalID); err != nil {
				return 0, err
			}
			inserted++
		} else {
			if !providerRecordExists {
				// Retain the source-native record as immutable evidence while all
				// analyst queries and detections resolve to the canonical event.
				if _, err := tx.Exec(ctx, `
					INSERT INTO security_audit_events
					(id,tenant_id,provider_record_id,content_type,workload,operation,actor,client_ip,object_id,result_status,occurred_at,available_at,ingested_at,sources,raw,sample,semantic_key,canonical_event_id)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
					event.ID, event.TenantID, event.ProviderRecordID, event.ContentType,
					event.Workload, event.Operation, event.Actor, event.ClientIP,
					event.ObjectID, event.ResultStatus, event.OccurredAt, event.AvailableAt, event.IngestedAt,
					event.Sources, []byte(event.Raw), event.Sample, semanticKey, canonicalID); err != nil {
					return 0, err
				}
			}
			authoritative := hasString(event.Sources, "m365_audit")
			if _, err := tx.Exec(ctx, `
				UPDATE security_audit_events SET
					available_at=LEAST(available_at,$2),
					ingested_at=LEAST(ingested_at,$3),
					sources=(SELECT ARRAY_AGG(DISTINCT source ORDER BY source)
					         FROM unnest(sources || $4::TEXT[]) AS expanded(source)),
					content_type=CASE WHEN $5 THEN $6 ELSE content_type END,
					workload=CASE WHEN $5 AND $7 <> '' THEN $7 ELSE workload END,
					operation=CASE WHEN $5 AND $8 <> '' THEN $8 ELSE operation END,
					actor=CASE WHEN $5 AND $9 <> '' THEN $9 ELSE actor END,
					client_ip=CASE WHEN $5 AND $10 <> '' THEN $10 ELSE client_ip END,
					object_id=CASE WHEN $5 AND $11 <> '' THEN $11 ELSE object_id END,
					result_status=CASE WHEN $5 AND $12 <> '' THEN $12 ELSE result_status END,
					raw=CASE WHEN $5 THEN $13 ELSE raw END,
					sample=sample AND $14
				WHERE id=$1`, canonicalID, event.AvailableAt, event.IngestedAt, event.Sources,
				authoritative, event.ContentType, event.Workload, event.Operation, event.Actor,
				event.ClientIP, event.ObjectID, event.ResultStatus, []byte(event.Raw), event.Sample); err != nil {
				return 0, err
			}
		}
		canonicalEventIDs[event.ID] = canonicalID
		for _, source := range event.Sources {
			if source == "historical_backfill" {
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO security_audit_event_aliases
					(event_id,tenant_id,source,provider_record_id,content_type,available_at,ingested_at,raw)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT (tenant_id,source,provider_record_id) DO UPDATE SET
					event_id=EXCLUDED.event_id,
					content_type=EXCLUDED.content_type,
					available_at=COALESCE(LEAST(security_audit_event_aliases.available_at,EXCLUDED.available_at),security_audit_event_aliases.available_at,EXCLUDED.available_at),
					ingested_at=COALESCE(LEAST(security_audit_event_aliases.ingested_at,EXCLUDED.ingested_at),security_audit_event_aliases.ingested_at,EXCLUDED.ingested_at),
					raw=EXCLUDED.raw`,
				canonicalID, event.TenantID, source, event.ProviderRecordID, event.ContentType,
				event.AvailableAt, event.IngestedAt, []byte(event.Raw)); err != nil {
				return 0, err
			}
		}
	}
	for _, detection := range detections {
		if canonicalID := canonicalEventIDs[detection.EventID]; canonicalID != "" {
			detection.EventID = canonicalID
		}
		for index, eventID := range detection.EventIDs {
			if canonicalID := canonicalEventIDs[eventID]; canonicalID != "" {
				detection.EventIDs[index] = canonicalID
			}
		}
		detection.EventIDs = mergeStringValues(nil, detection.EventIDs, detection.EventID)
		if detection.DetectionType == "" {
			detection.DetectionType = "direct"
		}
		if detection.Confidence == "" {
			detection.Confidence = "medium"
		}
		entities, err := json.Marshal(detection.Entities)
		if err != nil {
			return 0, err
		}
		eventIDs := detection.EventIDs
		if len(eventIDs) == 0 {
			eventIDs = []string{detection.EventID}
		}
		eventIDsJSON, err := json.Marshal(eventIDs)
		if err != nil {
			return 0, err
		}
		var persistedDetectionID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO security_native_detections
			(id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (tenant_id,event_id,rule_id,rule_version) DO UPDATE SET
				event_ids=security_native_detections.event_ids
			RETURNING id`,
			detection.ID, detection.TenantID, detection.EventID, eventIDsJSON, detection.RuleID,
			detection.RuleVersion, detection.Title, detection.Description,
			detection.Severity, detection.DetectionType, detection.Confidence,
			entities, detection.OccurredAt, detection.CreatedAt,
			detection.Sample).Scan(&persistedDetectionID); err != nil {
			return 0, err
		}
		detection.ID = persistedDetectionID
		if err := storeDetectionEvidence(ctx, tx, detection, eventIDs); err != nil {
			return 0, err
		}
	}
	checkpoint.EventsInserted = inserted
	var lastEventAt any
	if !checkpoint.LastEventAt.IsZero() {
		lastEventAt = checkpoint.LastEventAt
	}
	if checkpoint.ContentType != "" {
		if _, err := tx.Exec(ctx, `
		INSERT INTO security_audit_checkpoints
		(tenant_id,content_type,status,mode,detail,cursor_end,last_polled_at,last_event_at,events_received,events_inserted)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (tenant_id,content_type) DO UPDATE SET
		status=EXCLUDED.status,mode=EXCLUDED.mode,detail=EXCLUDED.detail,
		cursor_end=EXCLUDED.cursor_end,last_polled_at=EXCLUDED.last_polled_at,
		last_event_at=COALESCE(EXCLUDED.last_event_at,security_audit_checkpoints.last_event_at),
		events_received=EXCLUDED.events_received,events_inserted=EXCLUDED.events_inserted`,
			checkpoint.TenantID, checkpoint.ContentType, checkpoint.Status,
			checkpoint.Mode, checkpoint.Detail, checkpoint.CursorEnd,
			checkpoint.LastPolledAt, lastEventAt, checkpoint.EventsReceived,
			checkpoint.EventsInserted); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return inserted, nil
}

func (s *PG) StoreSecurityNativeDetections(ctx context.Context, detections []model.SecurityNativeDetection) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	inserted := 0
	for _, detection := range detections {
		canonicalID, err := canonicalSecurityEventID(ctx, tx, detection.TenantID, detection.EventID)
		if err != nil {
			return 0, err
		}
		detection.EventID = canonicalID
		for index, eventID := range detection.EventIDs {
			canonicalID, err := canonicalSecurityEventID(ctx, tx, detection.TenantID, eventID)
			if err != nil {
				return 0, err
			}
			detection.EventIDs[index] = canonicalID
		}
		detection.EventIDs = mergeStringValues(nil, detection.EventIDs, detection.EventID)
		if detection.DetectionType == "" {
			detection.DetectionType = "direct"
		}
		if detection.Confidence == "" {
			detection.Confidence = "medium"
		}
		entities, err := json.Marshal(detection.Entities)
		if err != nil {
			return 0, err
		}
		eventIDs := detection.EventIDs
		if len(eventIDs) == 0 {
			eventIDs = []string{detection.EventID}
		}
		eventIDsJSON, err := json.Marshal(eventIDs)
		if err != nil {
			return 0, err
		}
		var persistedDetectionID string
		var created bool
		err = tx.QueryRow(ctx, `
			INSERT INTO security_native_detections
			(id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (tenant_id,event_id,rule_id,rule_version) DO UPDATE SET
				event_ids=security_native_detections.event_ids
			RETURNING id,(xmax=0)`,
			detection.ID, detection.TenantID, detection.EventID, eventIDsJSON, detection.RuleID,
			detection.RuleVersion, detection.Title, detection.Description,
			detection.Severity, detection.DetectionType, detection.Confidence,
			entities, detection.OccurredAt, detection.CreatedAt, detection.Sample).Scan(&persistedDetectionID, &created)
		if err != nil {
			return 0, err
		}
		if created {
			inserted++
		}
		detection.ID = persistedDetectionID
		if err := storeDetectionEvidence(ctx, tx, detection, eventIDs); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return inserted, nil
}

func canonicalSecurityEventID(ctx context.Context, tx pgx.Tx, tenantID, eventID string) (string, error) {
	var canonicalID string
	err := tx.QueryRow(ctx, `
		SELECT COALESCE(canonical_event_id,id)
		FROM security_audit_events WHERE tenant_id=$1 AND id=$2`, tenantID, eventID).Scan(&canonicalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return eventID, nil
	}
	return canonicalID, err
}

func storeDetectionEvidence(ctx context.Context, tx pgx.Tx, detection model.SecurityNativeDetection, eventIDs []string) error {
	for _, eventID := range eventIDs {
		relationship := "supporting"
		if eventID == detection.EventID {
			relationship = "anchor"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_detection_events (detection_id,event_id,relationship)
			VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, detection.ID, eventID, relationship); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE security_native_detections SET event_ids=(
			SELECT COALESCE(jsonb_agg(event_id ORDER BY event_id),'[]'::jsonb)
			FROM security_detection_events WHERE detection_id=$1)
		WHERE id=$1`, detection.ID); err != nil {
		return err
	}
	for _, entity := range detection.Entities {
		key := strings.TrimSpace(entity.Key)
		if key == "" {
			key = detection.TenantID + "|" + strings.ToLower(strings.TrimSpace(entity.Type)) + "|" + strings.ToLower(strings.TrimSpace(entity.Label))
		}
		if key == "" || strings.TrimSpace(entity.Label) == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_detection_entities (detection_id,tenant_id,entity_type,entity_key,label)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
			detection.ID, detection.TenantID, entity.Type, key, entity.Label); err != nil {
			return err
		}
	}
	return nil
}

func (s *PG) SecurityDetectionReplayCompleted(ctx context.Context, packVersion int) (bool, error) {
	var completed bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM security_detection_replays WHERE pack_version=$1)`,
		packVersion).Scan(&completed)
	return completed, err
}

func (s *PG) MarkSecurityDetectionReplay(ctx context.Context, packVersion, eventsScanned, detectionsInserted int) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO security_detection_replays (pack_version,events_scanned,detections_inserted)
		VALUES ($1,$2,$3)
		ON CONFLICT (pack_version) DO NOTHING`, packVersion, eventsScanned, detectionsInserted)
	return err
}

func scanSecurityNativeDetection(row pgx.Row) (model.SecurityNativeDetection, error) {
	var detection model.SecurityNativeDetection
	var entities, eventIDs []byte
	err := row.Scan(
		&detection.ID, &detection.TenantID, &detection.EventID, &eventIDs,
		&detection.RuleID, &detection.RuleVersion, &detection.Title,
		&detection.Description, &detection.Severity, &detection.DetectionType,
		&detection.Confidence, &entities,
		&detection.OccurredAt, &detection.CreatedAt, &detection.Sample,
	)
	if err == nil {
		err = json.Unmarshal(entities, &detection.Entities)
	}
	if err == nil {
		err = json.Unmarshal(eventIDs, &detection.EventIDs)
	}
	return detection, err
}

func (s *PG) SecurityNativeDetections(ctx context.Context) ([]model.SecurityNativeDetection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample
		FROM (
			SELECT DISTINCT ON (COALESCE(event.canonical_event_id,event.id),detection.rule_id,detection.rule_version)
				detection.id,detection.tenant_id,detection.event_id,detection.event_ids,detection.rule_id,detection.rule_version,
				detection.title,detection.description,detection.severity,detection.detection_type,detection.confidence,
				detection.entities,detection.occurred_at,detection.created_at,detection.sample
			FROM security_native_detections detection
			JOIN security_audit_events event ON event.id=detection.event_id
			WHERE detection.occurred_at >= now() - interval '180 days'
			ORDER BY COALESCE(event.canonical_event_id,event.id),detection.rule_id,detection.rule_version,
			         (event.canonical_event_id IS NULL) DESC,detection.created_at
		) deduplicated
		ORDER BY occurred_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityNativeDetection
	for rows.Next() {
		detection, err := scanSecurityNativeDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, detection)
	}
	return out, rows.Err()
}

func (s *PG) SecurityNativeDetectionsSince(ctx context.Context, since time.Time) ([]model.SecurityNativeDetection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample
		FROM (
			SELECT DISTINCT ON (COALESCE(event.canonical_event_id,event.id),detection.rule_id,detection.rule_version)
				detection.id,detection.tenant_id,detection.event_id,detection.event_ids,detection.rule_id,detection.rule_version,
				detection.title,detection.description,detection.severity,detection.detection_type,detection.confidence,
				detection.entities,detection.occurred_at,detection.created_at,detection.sample
			FROM security_native_detections detection
			JOIN security_audit_events event ON event.id=detection.event_id
			WHERE detection.occurred_at >= $1
			ORDER BY COALESCE(event.canonical_event_id,event.id),detection.rule_id,detection.rule_version,
			         (event.canonical_event_id IS NULL) DESC,detection.created_at
		) deduplicated
		ORDER BY occurred_at DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityNativeDetection
	for rows.Next() {
		detection, err := scanSecurityNativeDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, detection)
	}
	return out, rows.Err()
}

func (s *PG) SecurityNativeDetectionsByIDs(ctx context.Context, detectionIDs []string) ([]model.SecurityNativeDetection, error) {
	if len(detectionIDs) == 0 {
		return []model.SecurityNativeDetection{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample
		FROM security_native_detections WHERE id=ANY($1) ORDER BY occurred_at`, detectionIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityNativeDetection
	for rows.Next() {
		detection, err := scanSecurityNativeDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, detection)
	}
	return out, rows.Err()
}

func (s *PG) SecurityNativeDetection(ctx context.Context, tenantID, id string) (model.SecurityNativeDetection, error) {
	detection, err := scanSecurityNativeDetection(s.pool.QueryRow(ctx, `
		SELECT id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample
		FROM security_native_detections WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityNativeDetection{}, ErrNotFound
	}
	return detection, err
}

func (s *PG) SecurityNativeDetectionsForEvent(ctx context.Context, tenantID, eventID string) ([]model.SecurityNativeDetection, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id,tenant_id,event_id,event_ids,rule_id,rule_version,title,description,severity,detection_type,confidence,entities,occurred_at,created_at,sample
		FROM (
			SELECT DISTINCT ON (detection.rule_id,detection.rule_version)
				detection.id,detection.tenant_id,detection.event_id,detection.event_ids,detection.rule_id,detection.rule_version,
				detection.title,detection.description,detection.severity,detection.detection_type,detection.confidence,
				detection.entities,detection.occurred_at,detection.created_at,detection.sample,
				(anchor.canonical_event_id IS NULL) AS canonical_anchor
			FROM security_native_detections detection
			JOIN security_audit_events anchor ON anchor.id=detection.event_id
			WHERE detection.tenant_id=$1 AND (
				COALESCE(anchor.canonical_event_id,anchor.id)=$2 OR EXISTS (
					SELECT 1 FROM security_detection_events related
					JOIN security_audit_events evidence ON evidence.id=related.event_id
					WHERE related.detection_id=detection.id
					  AND COALESCE(evidence.canonical_event_id,evidence.id)=$2))
			ORDER BY detection.rule_id,detection.rule_version,canonical_anchor DESC,detection.created_at
		) deduplicated
		ORDER BY occurred_at DESC`, tenantID, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityNativeDetection
	for rows.Next() {
		detection, err := scanSecurityNativeDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, detection)
	}
	return out, rows.Err()
}

const securityStorylineColumns = `
	id,correlation_key,pack_id,title,summary,severity,risk_score,confidence,status,owner,
	first_seen,last_seen,updated_at,tenant_ids,tenant_names,entities,stages,workloads,
	detection_ids,event_ids,signal_count,affected_users,affected_resources,reasons,
	weak_evidence,recommended_actions,sample`

func scanSecurityStoryline(row pgx.Row) (model.SecurityStoryline, error) {
	var storyline model.SecurityStoryline
	var tenantIDs, tenantNames, entities, stages, workloads, detectionIDs, eventIDs, reasons, weak, actions []byte
	err := row.Scan(
		&storyline.ID, &storyline.CorrelationKey, &storyline.PackID, &storyline.Title,
		&storyline.Summary, &storyline.Severity, &storyline.RiskScore, &storyline.Confidence,
		&storyline.Status, &storyline.Owner, &storyline.FirstSeen, &storyline.LastSeen,
		&storyline.UpdatedAt, &tenantIDs, &tenantNames, &entities, &stages, &workloads,
		&detectionIDs, &eventIDs, &storyline.SignalCount, &storyline.AffectedUsers,
		&storyline.AffectedResources, &reasons, &weak, &actions, &storyline.Sample,
	)
	if err != nil {
		return model.SecurityStoryline{}, err
	}
	for _, target := range []struct {
		raw []byte
		to  any
	}{
		{tenantIDs, &storyline.TenantIDs}, {tenantNames, &storyline.TenantNames},
		{entities, &storyline.Entities}, {stages, &storyline.Stages}, {workloads, &storyline.Workloads},
		{detectionIDs, &storyline.DetectionIDs}, {eventIDs, &storyline.EventIDs},
		{reasons, &storyline.Reasons}, {weak, &storyline.WeakEvidence}, {actions, &storyline.RecommendedActions},
	} {
		if err := json.Unmarshal(target.raw, target.to); err != nil {
			return model.SecurityStoryline{}, err
		}
	}
	return storyline, nil
}

func (s *PG) SecurityStorylines(ctx context.Context) ([]model.SecurityStoryline, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+securityStorylineColumns+` FROM security_storylines ORDER BY risk_score DESC,last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityStoryline
	for rows.Next() {
		storyline, err := scanSecurityStoryline(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, storyline)
	}
	return out, rows.Err()
}

func (s *PG) SecurityStoryline(ctx context.Context, id string) (model.SecurityStoryline, error) {
	storyline, err := scanSecurityStoryline(s.pool.QueryRow(ctx, `SELECT `+securityStorylineColumns+` FROM security_storylines WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityStoryline{}, ErrNotFound
	}
	return storyline, err
}

func (s *PG) UpsertSecurityStorylines(ctx context.Context, storylines []model.SecurityStoryline) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, storyline := range storylines {
		values := []any{
			storyline.TenantIDs, storyline.TenantNames, storyline.Entities, storyline.Stages,
			storyline.Workloads, storyline.DetectionIDs, storyline.EventIDs, storyline.Reasons,
			storyline.WeakEvidence, storyline.RecommendedActions,
		}
		encoded := make([][]byte, len(values))
		for i, value := range values {
			encoded[i], err = json.Marshal(value)
			if err != nil {
				return err
			}
		}
		var persistedID string
		err = tx.QueryRow(ctx, `
			INSERT INTO security_storylines
			(id,correlation_key,pack_id,title,summary,severity,risk_score,confidence,status,owner,
			 first_seen,last_seen,updated_at,tenant_ids,tenant_names,entities,stages,workloads,
			 detection_ids,event_ids,signal_count,affected_users,affected_resources,reasons,
			 weak_evidence,recommended_actions,sample)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
			ON CONFLICT (correlation_key) DO UPDATE SET
			 title=EXCLUDED.title,summary=EXCLUDED.summary,severity=EXCLUDED.severity,
			 risk_score=EXCLUDED.risk_score,confidence=EXCLUDED.confidence,
			 first_seen=LEAST(security_storylines.first_seen,EXCLUDED.first_seen),
			 last_seen=GREATEST(security_storylines.last_seen,EXCLUDED.last_seen),updated_at=EXCLUDED.updated_at,
			 tenant_ids=EXCLUDED.tenant_ids,tenant_names=EXCLUDED.tenant_names,entities=EXCLUDED.entities,
			 stages=EXCLUDED.stages,workloads=EXCLUDED.workloads,detection_ids=EXCLUDED.detection_ids,
			 event_ids=EXCLUDED.event_ids,signal_count=EXCLUDED.signal_count,
			 affected_users=EXCLUDED.affected_users,affected_resources=EXCLUDED.affected_resources,
			 reasons=EXCLUDED.reasons,weak_evidence=EXCLUDED.weak_evidence,
			 recommended_actions=EXCLUDED.recommended_actions,sample=EXCLUDED.sample
			RETURNING id`,
			storyline.ID, storyline.CorrelationKey, storyline.PackID, storyline.Title, storyline.Summary,
			storyline.Severity, storyline.RiskScore, storyline.Confidence, storyline.Status, storyline.Owner,
			storyline.FirstSeen, storyline.LastSeen, storyline.UpdatedAt,
			encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5], encoded[6],
			storyline.SignalCount, storyline.AffectedUsers, storyline.AffectedResources,
			encoded[7], encoded[8], encoded[9], storyline.Sample).Scan(&persistedID)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM security_storyline_detections WHERE storyline_id=$1`, persistedID); err != nil {
			return err
		}
		for _, detectionID := range storyline.DetectionIDs {
			if _, err = tx.Exec(ctx, `
				INSERT INTO security_storyline_detections (storyline_id,detection_id)
				VALUES ($1,$2) ON CONFLICT DO NOTHING`, persistedID, detectionID); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `DELETE FROM security_storyline_tenants WHERE storyline_id=$1`, persistedID); err != nil {
			return err
		}
		for _, tenantID := range storyline.TenantIDs {
			if _, err = tx.Exec(ctx, `
				INSERT INTO security_storyline_tenants (storyline_id,tenant_id)
				VALUES ($1,$2) ON CONFLICT DO NOTHING`, persistedID, tenantID); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (s *PG) UpdateSecurityStorylineState(ctx context.Context, id, status, owner, _ string) (model.SecurityStoryline, error) {
	storyline, err := scanSecurityStoryline(s.pool.QueryRow(ctx, `
		UPDATE security_storylines SET status=$2,owner=$3,updated_at=now() WHERE id=$1
		RETURNING `+securityStorylineColumns, id, status, owner))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityStoryline{}, ErrNotFound
	}
	return storyline, err
}

func scanSecurityDetectionRule(row pgx.Row) (model.SecurityDetectionRule, error) {
	var rule model.SecurityDetectionRule
	var definition []byte
	err := row.Scan(
		&rule.ID, &rule.RuleID, &rule.BaseRuleID, &rule.Name, &rule.Description,
		&rule.BuiltIn, &rule.DetectionType, &rule.Severity, &rule.Confidence,
		&rule.Enabled, &rule.Scope, &rule.TenantID, &definition, &rule.Revision,
		&rule.UpdatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err == nil {
		err = json.Unmarshal(definition, &rule.Definition)
	}
	rule.Override = rule.BaseRuleID != ""
	rule.Locked = rule.BuiltIn
	return rule, err
}

const securityRuleColumns = `id,rule_id,base_rule_id,name,description,built_in,detection_type,severity,confidence,enabled,scope,tenant_id,definition,revision,updated_by,created_at,updated_at`

func (s *PG) SecurityDetectionRules(ctx context.Context) ([]model.SecurityDetectionRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+securityRuleColumns+` FROM security_detection_rules ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityDetectionRule
	for rows.Next() {
		rule, err := scanSecurityDetectionRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func (s *PG) SecurityDetectionRule(ctx context.Context, id string) (model.SecurityDetectionRule, error) {
	rule, err := scanSecurityDetectionRule(s.pool.QueryRow(ctx, `SELECT `+securityRuleColumns+` FROM security_detection_rules WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecurityDetectionRule{}, ErrNotFound
	}
	return rule, err
}

func (s *PG) CreateSecurityDetectionRule(ctx context.Context, rule model.SecurityDetectionRule) (model.SecurityDetectionRule, error) {
	definition, err := json.Marshal(rule.Definition)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		INSERT INTO security_detection_rules
		(id,rule_id,base_rule_id,name,description,built_in,detection_type,severity,confidence,enabled,scope,tenant_id,definition,revision,updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14)
		RETURNING revision,created_at,updated_at`,
		rule.ID, rule.RuleID, rule.BaseRuleID, rule.Name, rule.Description,
		rule.BuiltIn, rule.DetectionType, rule.Severity, rule.Confidence,
		rule.Enabled, rule.Scope, rule.TenantID, definition, rule.UpdatedBy).
		Scan(&rule.Revision, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return model.SecurityDetectionRule{}, ErrConflict
		}
		return model.SecurityDetectionRule{}, err
	}
	rule.Override, rule.Locked = rule.BaseRuleID != "", rule.BuiltIn
	snapshot, err := json.Marshal(rule)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_detection_rule_revisions (rule_id,revision,snapshot,actor) VALUES ($1,1,$2,$3)`, rule.ID, snapshot, rule.UpdatedBy); err != nil {
		return model.SecurityDetectionRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.SecurityDetectionRule{}, err
	}
	return rule, nil
}

func (s *PG) UpdateSecurityDetectionRule(ctx context.Context, rule model.SecurityDetectionRule, expectedRevision int) (model.SecurityDetectionRule, error) {
	definition, err := json.Marshal(rule.Definition)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		UPDATE security_detection_rules SET
		rule_id=$2,base_rule_id=$3,name=$4,description=$5,built_in=$6,
		detection_type=$7,severity=$8,confidence=$9,enabled=$10,scope=$11,
		tenant_id=$12,definition=$13,revision=revision+1,updated_by=$14,updated_at=now()
		WHERE id=$1 AND revision=$15
		RETURNING revision,created_at,updated_at`,
		rule.ID, rule.RuleID, rule.BaseRuleID, rule.Name, rule.Description,
		rule.BuiltIn, rule.DetectionType, rule.Severity, rule.Confidence,
		rule.Enabled, rule.Scope, rule.TenantID, definition, rule.UpdatedBy,
		expectedRevision).Scan(&rule.Revision, &rule.CreatedAt, &rule.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if scanErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_detection_rules WHERE id=$1)`, rule.ID).Scan(&exists); scanErr != nil {
			return model.SecurityDetectionRule{}, scanErr
		}
		if exists {
			return model.SecurityDetectionRule{}, ErrConflict
		}
		return model.SecurityDetectionRule{}, ErrNotFound
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return model.SecurityDetectionRule{}, ErrConflict
		}
		return model.SecurityDetectionRule{}, err
	}
	rule.Override, rule.Locked = rule.BaseRuleID != "", rule.BuiltIn
	snapshot, err := json.Marshal(rule)
	if err != nil {
		return model.SecurityDetectionRule{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO security_detection_rule_revisions (rule_id,revision,snapshot,actor) VALUES ($1,$2,$3,$4)`, rule.ID, rule.Revision, snapshot, rule.UpdatedBy); err != nil {
		return model.SecurityDetectionRule{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.SecurityDetectionRule{}, err
	}
	return rule, nil
}

func (s *PG) SecurityDetectionRuleRevisions(ctx context.Context, id string) ([]model.SecurityDetectionRuleRevision, error) {
	rows, err := s.pool.Query(ctx, `SELECT rule_id,revision,snapshot,actor,created_at FROM security_detection_rule_revisions WHERE rule_id=$1 ORDER BY revision DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityDetectionRuleRevision
	for rows.Next() {
		var revision model.SecurityDetectionRuleRevision
		var snapshot []byte
		if err := rows.Scan(&revision.RuleID, &revision.Revision, &snapshot, &revision.Actor, &revision.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(snapshot, &revision.Snapshot); err != nil {
			return nil, err
		}
		out = append(out, revision)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		if _, err := s.SecurityDetectionRule(ctx, id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *PG) PruneSecurityAuditEvents(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM security_audit_events WHERE occurred_at < $1`, before)
	return tag.RowsAffected(), err
}

const offlineInvestigationColumns = `
	id,name,tenant_label,status,progress,detail,created_by,created_at,updated_at,
	analyzed_at,period_start,period_end,event_count,detection_count,high_priority_count,storyline_count,coverage`

func scanOfflineInvestigation(row pgx.Row) (model.OfflineInvestigation, error) {
	var investigation model.OfflineInvestigation
	var analyzedAt, periodStart, periodEnd sql.NullTime
	var coverage []byte
	err := row.Scan(
		&investigation.ID, &investigation.Name, &investigation.TenantLabel, &investigation.Status,
		&investigation.Progress, &investigation.Detail, &investigation.CreatedBy, &investigation.CreatedAt,
		&investigation.UpdatedAt, &analyzedAt, &periodStart, &periodEnd, &investigation.EventCount,
		&investigation.DetectionCount, &investigation.HighPriorityCount, &investigation.StorylineCount, &coverage,
	)
	if err != nil {
		return model.OfflineInvestigation{}, err
	}
	if analyzedAt.Valid {
		investigation.AnalyzedAt = analyzedAt.Time
	}
	if periodStart.Valid {
		investigation.PeriodStart = periodStart.Time
	}
	if periodEnd.Valid {
		investigation.PeriodEnd = periodEnd.Time
	}
	if err := json.Unmarshal(coverage, &investigation.Coverage); err != nil {
		return model.OfflineInvestigation{}, err
	}
	if investigation.Coverage == nil {
		investigation.Coverage = []model.OfflineEvidenceCoverage{}
	}
	return investigation, nil
}

func (s *PG) OfflineInvestigations(ctx context.Context) ([]model.OfflineInvestigation, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+offlineInvestigationColumns+` FROM offline_investigations ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var investigations []model.OfflineInvestigation
	for rows.Next() {
		investigation, err := scanOfflineInvestigation(rows)
		if err != nil {
			return nil, err
		}
		investigations = append(investigations, investigation)
	}
	return investigations, rows.Err()
}

func (s *PG) OfflineInvestigation(ctx context.Context, id string) (model.OfflineInvestigation, error) {
	investigation, err := scanOfflineInvestigation(s.pool.QueryRow(ctx, `SELECT `+offlineInvestigationColumns+` FROM offline_investigations WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.OfflineInvestigation{}, ErrNotFound
	}
	return investigation, err
}

func (s *PG) CreateOfflineInvestigation(ctx context.Context, input NewOfflineInvestigation) (model.OfflineInvestigation, error) {
	investigation := model.OfflineInvestigation{
		ID: "offinv_" + randID(), Name: input.Name, TenantLabel: input.TenantLabel,
		Status: "draft", CreatedBy: input.CreatedBy, Coverage: []model.OfflineEvidenceCoverage{},
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO offline_investigations (id,name,tenant_label,created_by)
		VALUES ($1,$2,$3,$4) RETURNING created_at,updated_at`,
		investigation.ID, investigation.Name, investigation.TenantLabel, investigation.CreatedBy).
		Scan(&investigation.CreatedAt, &investigation.UpdatedAt)
	return investigation, err
}

func (s *PG) DeleteOfflineInvestigation(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM offline_investigations WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *PG) OfflineInvestigationFiles(ctx context.Context, id string) ([]model.OfflineInvestigationFile, error) {
	if _, err := s.OfflineInvestigation(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,investigation_id,name,media_type,evidence_type,size_bytes,sha256,status,record_count,uploaded_at
		FROM offline_investigation_files WHERE investigation_id=$1 ORDER BY uploaded_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []model.OfflineInvestigationFile
	for rows.Next() {
		var file model.OfflineInvestigationFile
		if err := rows.Scan(&file.ID, &file.InvestigationID, &file.Name, &file.MediaType, &file.EvidenceType,
			&file.SizeBytes, &file.SHA256, &file.Status, &file.RecordCount, &file.UploadedAt); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

func (s *PG) OfflineInvestigationEvidenceFiles(ctx context.Context, id string) ([]model.OfflineInvestigationFile, error) {
	if _, err := s.OfflineInvestigation(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id,investigation_id,name,media_type,evidence_type,size_bytes,sha256,status,record_count,uploaded_at,sealed_content
		FROM offline_investigation_files WHERE investigation_id=$1 ORDER BY uploaded_at`, id)
	if err != nil {
		return nil, err
	}
	var files []model.OfflineInvestigationFile
	var legacySealed []string
	for rows.Next() {
		var file model.OfflineInvestigationFile
		var sealed string
		if err := rows.Scan(&file.ID, &file.InvestigationID, &file.Name, &file.MediaType, &file.EvidenceType,
			&file.SizeBytes, &file.SHA256, &file.Status, &file.RecordCount, &file.UploadedAt, &sealed); err != nil {
			return nil, err
		}
		files = append(files, file)
		legacySealed = append(legacySealed, sealed)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for index := range files {
		if legacySealed[index] != "" {
			content, err := s.protector.Open(legacySealed[index])
			if err != nil {
				return nil, err
			}
			files[index].Content = []byte(content)
			continue
		}
		chunkRows, err := s.pool.Query(ctx, `
			SELECT sealed_content FROM offline_investigation_file_chunks
			WHERE file_id=$1 ORDER BY chunk_index`, files[index].ID)
		if err != nil {
			return nil, err
		}
		var content bytes.Buffer
		if files[index].SizeBytes > 0 {
			content.Grow(int(files[index].SizeBytes))
		}
		for chunkRows.Next() {
			var sealed string
			if err := chunkRows.Scan(&sealed); err != nil {
				chunkRows.Close()
				return nil, err
			}
			plain, err := s.protector.Open(sealed)
			if err != nil {
				chunkRows.Close()
				return nil, err
			}
			_, _ = content.WriteString(plain)
		}
		if err := chunkRows.Err(); err != nil {
			chunkRows.Close()
			return nil, err
		}
		chunkRows.Close()
		files[index].Content = content.Bytes()
	}
	return files, nil
}

func (s *PG) AddOfflineInvestigationFile(ctx context.Context, id string, file model.OfflineInvestigationFile) (model.OfflineInvestigationFile, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.OfflineInvestigationFile{}, err
	}
	defer tx.Rollback(ctx)
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM offline_investigations WHERE id=$1 FOR UPDATE`, id).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return model.OfflineInvestigationFile{}, ErrNotFound
	} else if err != nil {
		return model.OfflineInvestigationFile{}, err
	}
	if status == "queued" || status == "analyzing" {
		return model.OfflineInvestigationFile{}, ErrConflict
	}
	var fileCount, totalRecords int
	var totalBytes int64
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*)::int,COALESCE(SUM(size_bytes),0)::bigint,COALESCE(SUM(record_count),0)::int
		FROM offline_investigation_files WHERE investigation_id=$1`, id).Scan(&fileCount, &totalBytes, &totalRecords); err != nil {
		return model.OfflineInvestigationFile{}, err
	}
	if fileCount+1 > OfflineInvestigationMaxFiles || totalBytes+file.SizeBytes > OfflineInvestigationMaxBytes || totalRecords+file.RecordCount > OfflineInvestigationMaxRecords {
		return model.OfflineInvestigationFile{}, ErrLimitExceeded
	}
	file.ID, file.InvestigationID = "offile_"+randID(), id
	if file.Status == "" {
		file.Status = "ready"
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO offline_investigation_files
		(id,investigation_id,name,media_type,evidence_type,size_bytes,sha256,status,record_count,sealed_content)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING uploaded_at`,
		file.ID, id, file.Name, file.MediaType, file.EvidenceType, file.SizeBytes, file.SHA256,
		file.Status, file.RecordCount, "").Scan(&file.UploadedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return model.OfflineInvestigationFile{}, ErrConflict
		}
		return model.OfflineInvestigationFile{}, err
	}
	for start, chunkIndex := 0, 0; start < len(file.Content); start, chunkIndex = start+offlineEvidenceChunkBytes, chunkIndex+1 {
		end := min(start+offlineEvidenceChunkBytes, len(file.Content))
		sealed, err := s.protector.Seal(string(file.Content[start:end]))
		if err != nil {
			return model.OfflineInvestigationFile{}, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO offline_investigation_file_chunks (file_id,chunk_index,sealed_content)
			VALUES ($1,$2,$3)`, file.ID, chunkIndex, sealed); err != nil {
			return model.OfflineInvestigationFile{}, err
		}
	}
	for _, table := range []string{"offline_investigation_storylines", "offline_investigation_detections", "offline_investigation_events"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE investigation_id=$1`, id); err != nil {
			return model.OfflineInvestigationFile{}, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE offline_investigations SET status='ready',progress=0,detail='',updated_at=now(),analyzed_at=NULL,
		period_start=NULL,period_end=NULL,event_count=0,detection_count=0,high_priority_count=0,storyline_count=0,coverage='[]'::jsonb
		WHERE id=$1`, id); err != nil {
		return model.OfflineInvestigationFile{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.OfflineInvestigationFile{}, err
	}
	return file, nil
}

func (s *PG) UpdateOfflineInvestigationStatus(ctx context.Context, id, status string, progress int, detail string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE offline_investigations SET status=$2,progress=$3,detail=$4,updated_at=now() WHERE id=$1`, id, status, progress, detail)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *PG) ReplaceOfflineInvestigationAnalysis(ctx context.Context, investigation model.OfflineInvestigation, analysis model.OfflineInvestigationAnalysis) error {
	coverage, err := json.Marshal(investigation.Coverage)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, table := range []string{"offline_investigation_storylines", "offline_investigation_detections", "offline_investigation_events"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE investigation_id=$1`, investigation.ID); err != nil {
			return err
		}
	}
	for _, event := range analysis.Events {
		payload, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO offline_investigation_events (investigation_id,id,occurred_at,payload) VALUES ($1,$2,$3,$4)`, investigation.ID, event.ID, event.OccurredAt, payload); err != nil {
			return err
		}
	}
	for _, detection := range analysis.Detections {
		payload, err := json.Marshal(detection)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO offline_investigation_detections (investigation_id,id,occurred_at,payload) VALUES ($1,$2,$3,$4)`, investigation.ID, detection.ID, detection.OccurredAt, payload); err != nil {
			return err
		}
	}
	for _, storyline := range analysis.Storylines {
		payload, err := json.Marshal(storyline)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO offline_investigation_storylines (investigation_id,id,last_seen,payload) VALUES ($1,$2,$3,$4)`, investigation.ID, storyline.ID, storyline.LastSeen, payload); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE offline_investigations SET status=$2,progress=$3,detail=$4,updated_at=$5,analyzed_at=$6,
		period_start=$7,period_end=$8,event_count=$9,detection_count=$10,high_priority_count=$11,storyline_count=$12,coverage=$13
		WHERE id=$1`, investigation.ID, investigation.Status, investigation.Progress, investigation.Detail,
		investigation.UpdatedAt, nullableTime(investigation.AnalyzedAt), nullableTime(investigation.PeriodStart), nullableTime(investigation.PeriodEnd),
		investigation.EventCount, investigation.DetectionCount, investigation.HighPriorityCount, investigation.StorylineCount, coverage)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func (s *PG) OfflineInvestigationAnalysis(ctx context.Context, id string) (model.OfflineInvestigationAnalysis, error) {
	if _, err := s.OfflineInvestigation(ctx, id); err != nil {
		return model.OfflineInvestigationAnalysis{}, err
	}
	analysis := model.OfflineInvestigationAnalysis{Events: []model.SecurityAuditEvent{}, Detections: []model.SecurityNativeDetection{}, Storylines: []model.SecurityStoryline{}}
	for _, query := range []struct {
		sql string
		add func([]byte) error
	}{
		{`SELECT payload FROM offline_investigation_events WHERE investigation_id=$1 ORDER BY occurred_at DESC`, func(payload []byte) error {
			var event model.SecurityAuditEvent
			if err := json.Unmarshal(payload, &event); err != nil {
				return err
			}
			analysis.Events = append(analysis.Events, event)
			return nil
		}},
		{`SELECT payload FROM offline_investigation_detections WHERE investigation_id=$1 ORDER BY occurred_at DESC`, func(payload []byte) error {
			var detection model.SecurityNativeDetection
			if err := json.Unmarshal(payload, &detection); err != nil {
				return err
			}
			analysis.Detections = append(analysis.Detections, detection)
			return nil
		}},
		{`SELECT payload FROM offline_investigation_storylines WHERE investigation_id=$1 ORDER BY last_seen DESC`, func(payload []byte) error {
			var storyline model.SecurityStoryline
			if err := json.Unmarshal(payload, &storyline); err != nil {
				return err
			}
			analysis.Storylines = append(analysis.Storylines, storyline)
			return nil
		}},
	} {
		rows, err := s.pool.Query(ctx, query.sql, id)
		if err != nil {
			return model.OfflineInvestigationAnalysis{}, err
		}
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				rows.Close()
				return model.OfflineInvestigationAnalysis{}, err
			}
			if err := query.add(payload); err != nil {
				rows.Close()
				return model.OfflineInvestigationAnalysis{}, err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return model.OfflineInvestigationAnalysis{}, err
		}
		rows.Close()
	}
	return analysis, nil
}

func (s *PG) Audit(ctx context.Context) ([]model.AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,ts,actor,action,resource,result,correlation_id FROM audit_logs ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var a model.AuditEntry
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.Actor, &a.Action, &a.Resource, &a.Result, &a.CorrelationID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PG) AppendAudit(ctx context.Context, e model.AuditEntry) error {
	if e.ID == "" {
		e.ID = "aud_" + randID()
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().Format("15:04:05")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_logs (id,ts,actor,action,resource,result,correlation_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		e.ID, e.Timestamp, e.Actor, e.Action, e.Resource, e.Result, e.CorrelationID)
	return err
}

// Technicians derives the display list from the real login accounts. Every
// RTM user has access to every managed tenant (no grant model).
func (s *PG) Technicians(ctx context.Context) ([]model.Technician, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, email, role, is_admin, status, must_change_password FROM accounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Technician
	for rows.Next() {
		var (
			t       model.Technician
			isAdmin bool
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.Email, &t.Role, &isAdmin, &t.Status, &t.MustChangePassword); err != nil {
			return nil, err
		}
		t.Tenants = "All"
		_ = isAdmin
		t.LastActive = "—"
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PG) CreateAccount(ctx context.Context, na NewAccount) (Account, error) {
	a := Account{
		ID: "tech_" + randID(), Name: na.Name, Email: na.Email, Role: na.Role,
		IsAdmin: na.IsAdmin, Status: "Active", PasswordHash: na.PasswordHash, MustChange: na.MustChange, CredentialVersion: 0,
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts (id,name,email,role,is_admin,status,password_hash,must_change_password,credential_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		a.ID, a.Name, a.Email, a.Role, a.IsAdmin, a.Status, a.PasswordHash, a.MustChange, a.CredentialVersion); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation (email)
			return Account{}, ErrConflict
		}
		return Account{}, err
	}
	return a, tx.Commit(ctx)
}

func (s *PG) UpdateAccount(ctx context.Context, id string, upd AccountUpdate) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE accounts SET role = COALESCE($2, role), status = COALESCE($3, status), is_admin = COALESCE($4, is_admin) WHERE id=$1`,
		id, upd.Role, upd.Status, upd.IsAdmin)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PG) DeleteAccount(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM accounts WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant_access WHERE account_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE account_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PG) AppSettings(ctx context.Context) ([]model.AppSetting, error) {
	rows, err := s.pool.Query(ctx, `SELECT key,label,description,enabled,locked,value FROM app_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AppSetting
	for rows.Next() {
		var a model.AppSetting
		if err := rows.Scan(&a.Key, &a.Label, &a.Description, &a.Enabled, &a.Locked, &a.Value); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PG) UpdateAppSetting(ctx context.Context, key string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE app_settings SET enabled=$2 WHERE key=$1`, key, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PG) UpdateAppSettingValue(ctx context.Context, key, value string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE app_settings SET value=$2 WHERE key=$1`, key, value)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PG) AccountByEmail(ctx context.Context, email string) (Account, error) {
	var a Account
	err := s.pool.QueryRow(ctx, `SELECT id,name,email,role,is_admin,status,password_hash,must_change_password,credential_version FROM accounts WHERE email=$1`, email).
		Scan(&a.ID, &a.Name, &a.Email, &a.Role, &a.IsAdmin, &a.Status, &a.PasswordHash, &a.MustChange, &a.CredentialVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}

func (s *PG) AccountByID(ctx context.Context, id string) (Account, error) {
	var a Account
	err := s.pool.QueryRow(ctx, `SELECT id,name,email,role,is_admin,status,password_hash,must_change_password,credential_version FROM accounts WHERE id=$1`, id).
		Scan(&a.ID, &a.Name, &a.Email, &a.Role, &a.IsAdmin, &a.Status, &a.PasswordHash, &a.MustChange, &a.CredentialVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}

func (s *PG) SetPassword(ctx context.Context, accountID, passwordHash string) error {
	return s.replaceAccountPassword(ctx, accountID, passwordHash, false)
}

func (s *PG) ResetPassword(ctx context.Context, accountID, passwordHash string) error {
	return s.replaceAccountPassword(ctx, accountID, passwordHash, true)
}

func (s *PG) replaceAccountPassword(ctx context.Context, accountID, passwordHash string, mustChange bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx,
		`UPDATE accounts SET password_hash=$2, must_change_password=$3, credential_version=credential_version+1 WHERE id=$1`,
		accountID, passwordHash, mustChange)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE account_id=$1`, accountID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PG) SetRefreshToken(ctx context.Context, accountID, jti string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (account_id,jti,updated_at) VALUES ($1,$2,now())
		 ON CONFLICT (account_id) DO UPDATE SET jti=EXCLUDED.jti, updated_at=now()`,
		accountID, jti)
	return err
}

func (s *PG) CurrentRefreshToken(ctx context.Context, accountID string) (string, error) {
	var jti string
	err := s.pool.QueryRow(ctx, `SELECT jti FROM refresh_tokens WHERE account_id=$1`, accountID).Scan(&jti)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return jti, err
}

func (s *PG) ClearRefreshToken(ctx context.Context, accountID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE account_id=$1`, accountID)
	return err
}

func (s *PG) Roles(ctx context.Context) ([]model.Role, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.name, r.description, r.permission_keys, COUNT(a.id)::int
		FROM role_policies r
		LEFT JOIN accounts a ON a.role = r.name
		GROUP BY r.name, r.description, r.permission_keys
		ORDER BY CASE r.name WHEN 'Admin' THEN 0 ELSE 1 END, r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []model.Role
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(&role.Name, &role.Description, &role.PermissionKeys, &role.Assigned); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (s *PG) Role(ctx context.Context, name string) (model.Role, error) {
	var role model.Role
	err := s.pool.QueryRow(ctx, `SELECT name, description, permission_keys FROM role_policies WHERE name=$1`, name).
		Scan(&role.Name, &role.Description, &role.PermissionKeys)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Role{}, ErrNotFound
	}
	return role, err
}

func (s *PG) UpdateRole(ctx context.Context, name, description string, permissionKeys []string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE role_policies
		SET description=$2, permission_keys=$3, updated_at=now()
		WHERE name=$1`, name, description, permissionKeys)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Approvals: the approval engine isn't built yet — always empty.
func (s *PG) Approvals(context.Context) ([]model.Approval, error) {
	return []model.Approval{}, nil
}

func randID() string {
	return fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
}
