// Package seed holds the bootstrap dataset: the example tenant, the login
// accounts (default admin + demo technicians), and the app-setting defaults. Operational data — jobs, changes, audit, working
// sets, dashboards — is never seeded: those tables only ever contain what the
// platform actually did.
package seed

import "github.com/rarity/rtm/internal/model"

var modules = []string{"Users", "Groups", "Exchange", "SharePoint", "Licensing"}

// DemoPassword is the shared password for the seeded technician accounts
// (demo only).
const DemoPassword = "RtmDemo!2026"

// Default admin bootstrap credentials. The account is seeded with
// MustChange=true, so the first GUI login forces a password rotation before
// anything else can be done (Security Spec: no long-lived well-known creds).
const (
	DefaultAdminEmail    = "admin@rtm.local"
	DefaultAdminPassword = "ChangeMe!2026"
)

// Account holds a seeded operator. Passwords are hashed at seed time.
type Account struct {
	ID         string
	Name       string
	Email      string
	Role       string
	IsAdmin    bool
	Status     string
	Password   string
	MustChange bool
}

// Tenants seeds a single example tenant. Real tenants are connected from the
// GUI (POST /tenants) with their own Entra app credentials.
var Tenants = []model.Tenant{
	{ID: "ten_1", Name: "Contoso Ltd", Domain: "contoso.onmicrosoft.com", MicrosoftTenantID: "a1f4c9d2-7b3e-4a18-9f8d-2c4e7a1b6d05", Status: "Connected", Users: 482, LastGraphTest: "2m ago", Modules: modules},
}

// Accounts are the seeded login accounts: the bootstrap admin (forced to
// rotate its password on first login) plus two demo technicians.
var Accounts = []Account{
	{ID: "admin_1", Name: "RTM Administrator", Email: DefaultAdminEmail, Role: RoleAdmin, IsAdmin: true, Status: "Active", Password: DefaultAdminPassword, MustChange: true},
	{ID: "tech_2", Name: "Aisha Rivera", Email: "aisha.rivera@rarity.io", Role: RoleTechnician, IsAdmin: false, Status: "Active", Password: DemoPassword},
	{ID: "tech_3", Name: "David Chen", Email: "david.chen@rarity.io", Role: RoleTechnician, IsAdmin: false, Status: "Active", Password: DemoPassword},
}

// The two RTM roles. Every RTM user has access to every managed tenant —
// there is no per-tenant grant model. Admin adds platform administration
// (tenant lifecycle, technician management, write execution, settings).
const (
	RoleAdmin                    = "Admin"
	RoleTechnician               = "Technician"
	PermissionManageTenants      = "tenants.manage"
	PermissionManageTechnicians  = "technicians.manage"
	PermissionManageRoles        = "roles.manage"
	PermissionManageSettings     = "settings.manage"
	PermissionExecuteChanges     = "changes.execute"
	PermissionManageSecurity     = "security.manage"
	PermissionManageThreatLocker = "threatlocker.manage"
)

var ElevatedPermissions = []string{
	PermissionManageTenants,
	PermissionManageTechnicians,
	PermissionManageRoles,
	PermissionManageSettings,
	PermissionExecuteChanges,
	PermissionManageSecurity,
	PermissionManageThreatLocker,
}

// Roles are the product's permission-level definitions (static catalog, not
// data).
var Roles = []model.Role{
	{Name: RoleAdmin, Description: "Everything across all tenants, plus platform administration: connect/remove tenants, manage technicians, execute write actions, change settings.", Permissions: "All permissions", PermissionKeys: append([]string(nil), ElevatedPermissions...), LockedPermissionKeys: append([]string(nil), ElevatedPermissions...), Level: "Privileged", LevelTone: "danger", Assigned: 1},
	{Name: RoleTechnician, Description: "Work across all tenants: inventory, Exchange/SharePoint/ThreatLocker detail, reports, jobs, and change history.", Permissions: "Read across all tenants", PermissionKeys: []string{}, Level: "Read", LevelTone: "warning", Assigned: 2},
}

// AppSettings are the platform controls with their defaults. Most are
// toggles; session_timeout carries a bounded minute value. require_approval
// ships off because the approval engine is not built yet.
var AppSettings = []model.AppSetting{
	{Key: "require_whatif", Label: "Require What If preview for all write actions", Description: "No change executes without a generated preview.", Enabled: true, Locked: true},
	{Key: "require_approval", Label: "Require approval before execution", Description: "A second authorized user must approve each change.", Enabled: false},
	{Key: "tenant_isolation", Label: "Enforce tenant isolation on every request", Description: "Server-side tenant authorization check.", Enabled: true, Locked: true},
	{Key: "audit_exports", Label: "Audit all report exports", Description: "Log actor, tenant, and correlation ID on export.", Enabled: true},
	{Key: "engineer_export", Label: "Allow CSV export for Engineers", Description: "Read-Only and Auditor roles can always export.", Enabled: false},
	{Key: "session_timeout", Label: "Session timeout", Description: "Access tokens expire after the selected duration. Changes apply to new sign-ins and refreshed sessions.", Enabled: true, Value: "30"},
}
