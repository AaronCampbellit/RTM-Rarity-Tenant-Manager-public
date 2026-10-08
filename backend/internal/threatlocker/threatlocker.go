// Package threatlocker is the ThreatLocker integration layer — RTM's first
// non-Microsoft module. ThreatLocker-sourced data (devices, approval requests,
// policies) is read through the Provider interface so the rest of the app
// never talks to the portal API directly, mirroring internal/graph.
//
// Unlike Graph there is no sample implementation: a deployment without a
// configured MSP parent connection gets ErrNotConnected, which handlers
// surface as NOT_CONNECTED.
package threatlocker

import (
	"context"
	"errors"
	"fmt"

	"github.com/rarity/rtm/internal/model"
)

// ErrNotConnected marks a deployment with no usable global ThreatLocker
// parent connection.
var ErrNotConnected = errors.New("threatlocker: global workspace is not connected")

// ErrNotSupported marks a write action the public ThreatLocker portal API does
// not expose (lockdown, isolation, tamper-protection toggles). Handlers map it
// to NOT_IMPLEMENTED.
var ErrNotSupported = errors.New("threatlocker: this action is not available through the ThreatLocker portal API")

// APIError is a non-2xx answer from the ThreatLocker portal API. Never
// contains the API token.
type APIError struct {
	Status  int
	Message string
	Path    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("threatlocker: %s returned HTTP %d: %s", e.Path, e.Status, e.Message)
}

// Device protection modes (model.Device.Mode). "secured" is full protection;
// everything else is a temporary state RTM's write actions manage.
const (
	ModeSecured      = "secured"
	ModeMonitorOnly  = "monitor_only"
	ModeLearning     = "learning"
	ModeInstallation = "installation"
	ModeMaintenance  = "maintenance" // protection disabled
	ModeLockdown     = "lockdown"
	ModeIsolated     = "isolated"
)

// Maintenance types accepted by enter_maintenance_mode. disable_protection is
// the highest-risk state (nothing is enforced or learned).
const (
	MaintenanceMonitorOnly       = "monitor_only"
	MaintenanceLearning          = "learning"
	MaintenanceInstallation      = "installation"
	MaintenanceDisableProtection = "disable_protection"
)

// ModeForMaintenance maps a maintenance type to the device mode it puts the
// device in.
func ModeForMaintenance(maintenanceType string) string {
	if maintenanceType == MaintenanceDisableProtection {
		return ModeMaintenance
	}
	return maintenanceType
}

// Approval-request permit scopes: how wide the policy created by an approval
// applies.
const (
	ScopeComputer     = "computer"
	ScopeGroup        = "group"
	ScopeOrganization = "organization"
)

// Approval-request statuses.
const (
	RequestPending  = "pending"
	RequestApproved = "approved"
	RequestDenied   = "denied"
)

// Provider is the ThreatLocker integration consumed by handlers, reports, and
// the job worker. Calls use the global MSP parent connection and include child
// organizations where supported.
type Provider interface {
	Devices(ctx context.Context, tenantID string) ([]model.Device, error)
	Device(ctx context.Context, tenantID, deviceID string) (model.Device, error)
	DeviceGroups(ctx context.Context, tenantID string) ([]model.DeviceGroup, error)
	Applications(ctx context.Context, tenantID string, req AppSearchRequest) ([]model.TLApplication, error)
	Application(ctx context.Context, tenantID, appID string) (model.TLApplicationDetail, error)
	ApplicationFiles(ctx context.Context, tenantID, appID string, osType int) ([]model.TLApplicationFile, error)
	ApplicationFilesForAuth(ctx context.Context, auth Auth, appID string, osType int) ([]model.TLApplicationFile, error)
	UpdateApplication(ctx context.Context, tenantID string, patch model.TLApplicationPatch) (model.TLApplicationDetail, error)
	CreateApplication(ctx context.Context, auth Auth, detail model.TLApplicationDetail) (model.TLApplicationDetail, error)
	// GlobalComputerGroup returns the parent organization's exact "Global"
	// destination. It fails closed rather than selecting an arbitrary parent
	// group when Global is absent.
	GlobalComputerGroup(ctx context.Context, auth Auth) (model.TLComputerGroup, error)
	// PromoteApplicationPolicy queues one child-owned policy to Global. When no
	// parent application exists, ThreatLocker materializes it as part of this
	// lifecycle.
	PromoteApplicationPolicy(ctx context.Context, auth Auth, promotion model.TLAppParentPromotion) error
	// MergeApplications submits ThreatLocker's native merge in the parent
	// context after refreshing every source in its owning organization.
	MergeApplications(ctx context.Context, auth Auth, target model.TLApplication, sources []model.TLApplication, finalName string) (model.TLApplicationDetail, error)
	InsertApplicationFile(ctx context.Context, auth Auth, file model.TLApplicationFile) error
	DeleteApplication(ctx context.Context, tenantID string, app model.TLApplication, confirm bool) error
	PoliciesForApplication(ctx context.Context, tenantID, appID string) ([]model.TLPolicy, error)
	PoliciesForApplicationForAuth(ctx context.Context, auth Auth, appID string) ([]model.TLPolicy, error)
	// DeletePolicies removes the given policies. Each policy row must carry the
	// OrganizationID it lives in when known: PolicyGetForViewPoliciesByApplicationId
	// returns policies from child organizations too, and the portal only serves
	// PolicyGetById / PolicyUpdateForDeleteByIds when the managedOrganizationId
	// header names the owning organization.
	DeletePolicies(ctx context.Context, tenantID string, policies []model.TLPolicy) error
	DeployPolicies(ctx context.Context, auth Auth) error
	// ApprovalRequests lists requests with the given status ("" = pending).
	ApprovalRequests(ctx context.Context, tenantID, status string) ([]model.ApprovalRequest, error)
	ApprovalRequest(ctx context.Context, tenantID, requestID string) (model.ApprovalRequest, error)
	// Policies lists the organization's policies.
	Policies(ctx context.Context, tenantID string) ([]model.TLPolicy, error)
	Policy(ctx context.Context, tenantID, policyID string) (model.TLPolicyDetail, error)
	UpdatePolicy(ctx context.Context, tenantID string, patch model.TLPolicyPatch) (model.TLPolicyDetail, error)
	CreatePolicy(ctx context.Context, tenantID string, detail model.TLPolicyDetail) (model.TLPolicyDetail, error)
	// *ForAuth variants target the organization named by auth directly. The
	// app-cleanup flow uses them with the MSP parent auth so the retained
	// global policy is written in the parent org (where the retained app
	// lives), not the active tenant's org.
	UpdatePolicyForAuth(ctx context.Context, auth Auth, patch model.TLPolicyPatch) (model.TLPolicyDetail, error)
	CreatePolicyForAuth(ctx context.Context, auth Auth, detail model.TLPolicyDetail) (model.TLPolicyDetail, error)
	// PolicyForAuth reads one policy in the organization named by auth, falling
	// back to fallbackOrgIDs (tried in order) when the portal cannot serve the
	// policy in that organization — a policy attached to a parent app may live
	// in a child organization.
	PolicyForAuth(ctx context.Context, auth Auth, policyID string, fallbackOrgIDs ...string) (model.TLPolicyDetail, error)
	// PolicyInOrg reads one policy addressed in orgID (child organizations
	// included), falling back to the tenant's own organization scope.
	PolicyInOrg(ctx context.Context, tenantID, policyID, orgID string) (model.TLPolicyDetail, error)
	TestConnection(ctx context.Context, tenantID string) error
	TestConnectionForAuth(ctx context.Context, auth Auth) error

	// Writes (executed by the job worker after the What-If gate, one device /
	// request per call so partial failure is per target).
	SetMaintenanceMode(ctx context.Context, tenantID, deviceID, maintenanceType string, durationMinutes int) error
	SecureDevice(ctx context.Context, tenantID, deviceID string) error
	SetLockdown(ctx context.Context, tenantID, deviceID string, enabled bool) error
	SetIsolation(ctx context.Context, tenantID, deviceID string, enabled bool) error
	SetTamperProtection(ctx context.Context, tenantID, deviceID string, enabled bool) error
	RestartAgent(ctx context.Context, tenantID, deviceID string) error
	// ApproveRequest permits the application behind a pending request. scope is
	// Scope*; expiresAt (RFC3339, optional) makes the permit temporary.
	ApproveRequest(ctx context.Context, tenantID, requestID, scope, expiresAt string) error
	DenyRequest(ctx context.Context, tenantID, requestID, reason string) error

	// Mode reports the integration mode for diagnostics ("live").
	Mode() string
}

// Auth is the global MSP parent connection: portal instance, API token, and
// parent organization GUID (sent as managedOrganizationId).
type Auth struct {
	Instance string
	Token    string
	OrgID    string
}

// AppSearchRequest maps RTM's Apps tab filters onto ThreatLocker's
// Application/ApplicationGetByParameters body.
type AppSearchRequest struct {
	SearchText                string
	SearchBy                  string // "app" | "full" | "process" | "hash" | "cert"
	OSType                    int
	IncludeBuiltIn            bool
	IncludeChildOrganizations bool
	IncludeHidden             bool
	IncludeUnused             bool
	Source                    string // "" | "tenant" | "parent"
}

type AppCleanupRequest struct {
	AppIDs           []string
	RetainedAppID    string
	RetainedPolicyID string
	Name             string
	ConfirmDelete    bool
}

// GlobalAuthResolver supplies a database-backed MSP parent connection. A zero
// Auth leaves the environment configuration as the fallback.
type GlobalAuthResolver func(ctx context.Context) (Auth, error)

// Config carries the global fallback credentials (RTM_THREATLOCKER_*) and an
// optional base-URL override for tests (used verbatim instead of the
// portalapi.{instance}.threatlocker.com scheme).
type Config struct {
	Instance    string
	Token       string
	ParentOrgID string
	BaseURL     string
	GlobalAuth  GlobalAuthResolver
}

// NewProvider builds the live ThreatLocker client. There is deliberately no
// sample mode: all calls use the single MSP parent connection.
func NewProvider(cfg Config) Provider {
	return newClient(cfg)
}
