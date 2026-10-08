// Package store persists RTM-owned entities. Two implementations satisfy the
// same interface: an in-memory store (used when no database is configured, so
// `make run` works offline) and a Postgres store (pgx) used in real
// deployments. Microsoft-sourced data lives behind the graph.Provider, not here.
package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a create collides with an existing record
// (e.g. duplicate account email).
var ErrConflict = errors.New("already exists")

// ErrLimitExceeded protects durable offline-evidence storage from an
// unbounded case even when multiple uploads arrive concurrently.
var ErrLimitExceeded = errors.New("storage limit exceeded")

const (
	OfflineInvestigationMaxFiles   = 20
	OfflineInvestigationMaxBytes   = int64(10 << 30)
	OfflineInvestigationMaxRecords = 50_000_000
)

const securitySemanticDedupWindow = 10 * time.Second

func securityEventSemanticKey(event model.SecurityAuditEvent) string {
	operation, actor := semanticField(event.Operation), semanticField(event.Actor)
	if event.TenantID == "" || operation == "" || actor == "" || event.OccurredAt.IsZero() {
		return ""
	}
	return strings.Join([]string{
		event.TenantID, operation, actor, semanticField(event.ObjectID),
		semanticField(event.ClientIP), semanticField(event.ResultStatus),
	}, "|")
}

func semanticField(value string) string {
	var normalized strings.Builder
	for _, character := range strings.ToLower(strings.TrimSpace(value)) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			normalized.WriteRune(character)
		}
	}
	return normalized.String()
}

func withinSecurityDedupWindow(left, right time.Time) bool {
	delta := left.Sub(right)
	if delta < 0 {
		delta = -delta
	}
	return delta <= securitySemanticDedupWindow
}

// Account is an RTM operator credential record (for auth).
type Account struct {
	ID                string
	Name              string
	Email             string
	Role              string
	IsAdmin           bool
	PasswordHash      string
	Status            string
	MustChange        bool // must rotate password before using the API
	CredentialVersion int  // invalidates every older access/refresh token
}

// NewAccount is the input to CreateAccount (technician invite). The password
// arrives pre-hashed — plaintext never crosses the store boundary. Every
// account has access to every managed tenant (no grant model).
type NewAccount struct {
	Name         string
	Email        string
	Role         string
	IsAdmin      bool
	PasswordHash string
	MustChange   bool
}

// AccountUpdate carries the editable technician fields; nil = leave as is.
type AccountUpdate struct {
	Role    *string
	Status  *string
	IsAdmin *bool
}

// NewWorkingSet is the input to CreateWorkingSet.
type NewWorkingSet struct {
	Name        string
	Description string
	TenantID    string
	Tenant      string
	UserIDs     []string
	CreatedBy   string
}

// WorkingSetUpdate carries the editable user-set fields. Working Sets remain
// bound to their original tenant so an edit cannot silently cross scope.
type WorkingSetUpdate struct {
	Name        string
	Description string
	UserIDs     []string
}

// NewOfflineInvestigation is the immutable identity of an uploaded evidence
// workspace. Imported evidence is case-scoped and never joins the live
// Security Operations event tables.
type NewOfflineInvestigation struct {
	Name        string
	TenantLabel string
	CreatedBy   string
}

// NewTenant is the input to CreateTenant. ClientID/ClientSecret are the
// tenant's own Entra (Graph) app credentials; empty means "use the global
// app". The Exchange* / SharePoint* fields are optional dedicated app
// registrations for the Exchange Online and SharePoint admin APIs; empty means
// "reuse the Graph app". All secrets are write-only.
type NewTenant struct {
	Name              string
	Domain            string
	MicrosoftTenantID string
	ClientID          string
	ClientSecret      string

	ExchangeClientID       string
	ExchangeClientSecret   string
	SharePointClientID     string
	SharePointClientSecret string
	SharePointAdminURL     string
}

// TenantUpdate is a patch contract. Nil fields preserve the stored value;
// secrets are removed only by an explicit Clear* flag.
type TenantUpdate struct {
	Name, Domain, MicrosoftTenantID        *string
	ClientID, ClientSecret                 *string
	ExchangeClientID, ExchangeClientSecret *string
	SharePointAdminURL                     *string
	ClearGraph, ClearExchange              bool
}

// TenantCreds is what the Microsoft integration layer needs to token against a
// managed tenant. Never serialized into API responses. The Exchange* /
// SharePoint* fields carry the dedicated service app registrations (empty =
// reuse the Graph app / global app).
type TenantCreds struct {
	MicrosoftTenantID string
	Domain            string
	ClientID          string
	ClientSecret      string

	ExchangeClientID       string
	ExchangeClientSecret   string
	SharePointClientID     string
	SharePointClientSecret string
	SharePointAdminURL     string
}

// ThreatLockerGlobalConfig is the encrypted, RTM-owned MSP parent connection.
// It is never serialized; API responses expose only its configured state.
type ThreatLockerGlobalConfig struct {
	Instance    string
	Token       string
	ParentOrgID string
}

// Authority is the Entra authority to token against for this tenant: the
// Microsoft directory (tenant) ID, falling back to the verified domain.
func (c TenantCreds) Authority() string {
	if c.MicrosoftTenantID != "" {
		return c.MicrosoftTenantID
	}
	return c.Domain
}

// Resolved applies the credential fallback chain used across the Microsoft
// integrations: an Exchange Online or SharePoint admin app registration that
// is unset inherits the tenant's Graph app credentials (which in turn fall
// back to the global app in the Graph client). The SharePoint admin URL has no
// fallback. SharePoint inventory and permission management also require the
// tenant's SharePoint admin URL; authentication comes from RTM's central
// certificate application.
func (c TenantCreds) Resolved() TenantCreds {
	r := c
	if r.ExchangeClientID == "" {
		r.ExchangeClientID, r.ExchangeClientSecret = c.ClientID, c.ClientSecret
	}
	if r.SharePointClientID == "" {
		r.SharePointClientID, r.SharePointClientSecret = c.ClientID, c.ClientSecret
	}
	return r
}

// connectionsFor derives the per-tenant integration flags shown in the API
// from stored credentials (dedicated app present = true).
func connectionsFor(c TenantCreds) model.TenantConnections {
	return model.TenantConnections{
		Graph:      c.ClientID != "",
		Exchange:   c.ExchangeClientID != "",
		SharePoint: c.SharePointAdminURL != "",
	}
}

type Store interface {
	// Tenants
	Tenants(ctx context.Context) ([]model.Tenant, error)
	Tenant(ctx context.Context, id string) (model.Tenant, error)
	CreateTenant(ctx context.Context, t NewTenant) (model.Tenant, error)
	UpdateTenant(ctx context.Context, id string, update TenantUpdate) (model.Tenant, error)
	DeleteTenant(ctx context.Context, id string) error
	UpdateTenantStatus(ctx context.Context, id, status, lastGraphTest string) error
	TenantPreflight(ctx context.Context, tenantID string) (model.Preflight, error)
	UpsertTenantPreflight(ctx context.Context, tenantID string, preflight model.Preflight) error
	// TenantCreds returns the connection material for the Graph layer.
	TenantCreds(ctx context.Context, id string) (TenantCreds, error)
	ThreatLockerGlobalConfig(ctx context.Context) (ThreatLockerGlobalConfig, error)
	UpdateThreatLockerGlobalConfig(ctx context.Context, c ThreatLockerGlobalConfig) error
	// ThreatLocker cleanup operations are written before the first portal
	// mutation. Active fingerprints prevent resubmission until reconciled.
	TLAppCleanupOperations(ctx context.Context, tenantID string) ([]model.TLAppCleanupOperation, error)
	ActiveTLAppCleanupOperation(ctx context.Context, fingerprint string) (model.TLAppCleanupOperation, error)
	CreateTLAppCleanupOperation(ctx context.Context, operation model.TLAppCleanupOperation) (model.TLAppCleanupOperation, error)
	UpdateTLAppCleanupOperation(ctx context.Context, id, status string, result model.TLAppCleanupResult, errorMessage string) error

	// SharePoint inventory: scans are durable operational records and each
	// completed scan atomically replaces the latest snapshot for its scope.
	CreateSharePointScan(ctx context.Context, scan model.SharePointScan) (model.SharePointScan, error)
	CompleteSharePointScan(ctx context.Context, scan model.SharePointScan, nodes []model.SharePointInventoryNode) error
	SharePointScans(ctx context.Context, tenantID string) ([]model.SharePointScan, error)
	SharePointInventory(ctx context.Context, tenantID, scope string) (model.SharePointInventory, error)

	// Working sets
	WorkingSets(ctx context.Context) ([]model.WorkingSet, error)
	WorkingSet(ctx context.Context, id string) (model.WorkingSet, error)
	CreateWorkingSet(ctx context.Context, ws NewWorkingSet) (model.WorkingSet, error)
	UpdateWorkingSet(ctx context.Context, id string, update WorkingSetUpdate) (model.WorkingSet, error)

	// Jobs
	Jobs(ctx context.Context) ([]model.Job, error)
	CreateJob(ctx context.Context, j model.Job) (model.Job, error)
	UpdateJobStatus(ctx context.Context, id, status string, progress int) error
	// CompleteJob finalizes a job with its outcome and wall-clock duration.
	CompleteJob(ctx context.Context, id, status, duration string) error
	AcknowledgeJob(ctx context.Context, id string) error

	// Change history: records are appended by the worker when a job actually
	// executes, with full before/after/log detail and the revert payload.
	Changes(ctx context.Context) ([]model.Change, error)
	Change(ctx context.Context, id string) (model.ChangeDetail, error)
	AppendChange(ctx context.Context, c model.ChangeDetail) error
	UpdateChangeRevert(ctx context.Context, id, revert string) error

	// Security Operations keeps durable first-received times and RTM-local
	// triage overlays plus immutable, tenant-scoped Management Activity events
	// and versioned detections.
	SecurityIncidentStates(ctx context.Context) ([]model.SecurityIncidentState, error)
	ObserveSecurityIncident(ctx context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error)
	UpsertSecurityIncidentState(ctx context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error)
	SecurityAuditCheckpoints(ctx context.Context) ([]model.SecurityAuditCheckpoint, error)
	SecurityAuditCheckpoint(ctx context.Context, tenantID, contentType string) (model.SecurityAuditCheckpoint, error)
	SecurityHistoryImports(ctx context.Context) ([]model.SecurityHistoryImport, error)
	SecurityHistoryImport(ctx context.Context, tenantID string) (model.SecurityHistoryImport, error)
	UpsertSecurityHistoryImport(ctx context.Context, history model.SecurityHistoryImport) (model.SecurityHistoryImport, error)
	SecurityAuditEventsSince(ctx context.Context, since time.Time) ([]model.SecurityAuditEvent, error)
	SecurityAuditEventsByIDs(ctx context.Context, eventIDs []string) ([]model.SecurityAuditEvent, error)
	SearchSecurityAuditEvents(ctx context.Context, query model.SecurityAuditEventSearch) ([]model.SecurityAuditEvent, bool, error)
	SecurityAuditEvent(ctx context.Context, tenantID, eventID string) (model.SecurityAuditEvent, error)
	SecurityAuditEventEvidence(ctx context.Context, tenantID, eventID string) ([]model.SecurityAuditEventEvidence, error)
	StoreSecurityAuditBatch(ctx context.Context, checkpoint model.SecurityAuditCheckpoint, events []model.SecurityAuditEvent, detections []model.SecurityNativeDetection) (int, error)
	StoreSecurityNativeDetections(ctx context.Context, detections []model.SecurityNativeDetection) (int, error)
	SecurityDetectionReplayCompleted(ctx context.Context, packVersion int) (bool, error)
	MarkSecurityDetectionReplay(ctx context.Context, packVersion, eventsScanned, detectionsInserted int) error
	SecurityNativeDetections(ctx context.Context) ([]model.SecurityNativeDetection, error)
	SecurityNativeDetectionsSince(ctx context.Context, since time.Time) ([]model.SecurityNativeDetection, error)
	SecurityNativeDetectionsByIDs(ctx context.Context, detectionIDs []string) ([]model.SecurityNativeDetection, error)
	SecurityNativeDetection(ctx context.Context, tenantID, id string) (model.SecurityNativeDetection, error)
	SecurityNativeDetectionsForEvent(ctx context.Context, tenantID, eventID string) ([]model.SecurityNativeDetection, error)
	SecurityStorylines(ctx context.Context) ([]model.SecurityStoryline, error)
	SecurityStoryline(ctx context.Context, id string) (model.SecurityStoryline, error)
	UpsertSecurityStorylines(ctx context.Context, storylines []model.SecurityStoryline) error
	UpdateSecurityStorylineState(ctx context.Context, id, status, owner, actor string) (model.SecurityStoryline, error)
	SecurityDetectionRules(ctx context.Context) ([]model.SecurityDetectionRule, error)
	SecurityDetectionRule(ctx context.Context, id string) (model.SecurityDetectionRule, error)
	CreateSecurityDetectionRule(ctx context.Context, rule model.SecurityDetectionRule) (model.SecurityDetectionRule, error)
	UpdateSecurityDetectionRule(ctx context.Context, rule model.SecurityDetectionRule, expectedRevision int) (model.SecurityDetectionRule, error)
	SecurityDetectionRuleRevisions(ctx context.Context, id string) ([]model.SecurityDetectionRuleRevision, error)
	PruneSecurityAuditEvents(ctx context.Context, before time.Time) (int64, error)

	// Offline investigations keep uploaded evidence and derived analysis in a
	// separate namespace so replayed logs cannot create live incidents.
	OfflineInvestigations(ctx context.Context) ([]model.OfflineInvestigation, error)
	OfflineInvestigation(ctx context.Context, id string) (model.OfflineInvestigation, error)
	CreateOfflineInvestigation(ctx context.Context, input NewOfflineInvestigation) (model.OfflineInvestigation, error)
	DeleteOfflineInvestigation(ctx context.Context, id string) error
	OfflineInvestigationFiles(ctx context.Context, id string) ([]model.OfflineInvestigationFile, error)
	OfflineInvestigationEvidenceFiles(ctx context.Context, id string) ([]model.OfflineInvestigationFile, error)
	AddOfflineInvestigationFile(ctx context.Context, id string, file model.OfflineInvestigationFile) (model.OfflineInvestigationFile, error)
	UpdateOfflineInvestigationStatus(ctx context.Context, id, status string, progress int, detail string) error
	ReplaceOfflineInvestigationAnalysis(ctx context.Context, investigation model.OfflineInvestigation, analysis model.OfflineInvestigationAnalysis) error
	OfflineInvestigationAnalysis(ctx context.Context, id string) (model.OfflineInvestigationAnalysis, error)

	// Audit
	Audit(ctx context.Context) ([]model.AuditEntry, error)
	AppendAudit(ctx context.Context, e model.AuditEntry) error

	// Admin: technicians are the real login accounts.
	Technicians(ctx context.Context) ([]model.Technician, error)
	CreateAccount(ctx context.Context, a NewAccount) (Account, error)
	UpdateAccount(ctx context.Context, id string, upd AccountUpdate) error
	DeleteAccount(ctx context.Context, id string) error
	Roles(ctx context.Context) ([]model.Role, error)
	Role(ctx context.Context, name string) (model.Role, error)
	UpdateRole(ctx context.Context, name, description string, permissionKeys []string) error
	AppSettings(ctx context.Context) ([]model.AppSetting, error)
	UpdateAppSetting(ctx context.Context, key string, enabled bool) error
	UpdateAppSettingValue(ctx context.Context, key, value string) error

	// Approvals: the approval engine isn't built yet, so this is always empty
	// (never fabricated).
	Approvals(ctx context.Context) ([]model.Approval, error)

	// Auth
	AccountByEmail(ctx context.Context, email string) (Account, error)
	AccountByID(ctx context.Context, id string) (Account, error)
	// SetPassword replaces the account's password hash and clears the
	// must-change flag. Both password operations revoke every prior session.
	SetPassword(ctx context.Context, accountID, passwordHash string) error
	// ResetPassword installs an admin-generated temporary password and sets the
	// must-change flag so the operator must choose their own on next login.
	ResetPassword(ctx context.Context, accountID, passwordHash string) error

	// Refresh-token rotation: the currently-valid refresh jti per account.
	SetRefreshToken(ctx context.Context, accountID, jti string) error
	CurrentRefreshToken(ctx context.Context, accountID string) (string, error)
	ClearRefreshToken(ctx context.Context, accountID string) error

	Close()
}
