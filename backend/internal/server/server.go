// Package server wires HTTP routes (chi) to handlers backed by the Store
// (RTM-owned data) and the Graph provider (Microsoft-sourced data). Routes
// mirror `specs/RTM API Specification.md` — versioned under /api/v1, resource +
// workflow-action endpoints, async actions return a job.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/sync/singleflight"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/config"
	"github.com/rarity/rtm/internal/exchangebootstrap"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/httpx"
	"github.com/rarity/rtm/internal/jobs"
	"github.com/rarity/rtm/internal/m365audit"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/offlineinvestigations"
	"github.com/rarity/rtm/internal/reports"
	"github.com/rarity/rtm/internal/securityops"
	"github.com/rarity/rtm/internal/seed"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

type Server struct {
	cfg               *config.Config
	log               *slog.Logger
	store             store.Store
	graph             graph.Provider
	tl                threatlocker.Provider
	auth              *auth.Service
	jobs              jobs.Enqueuer
	reports           *reports.Service
	security          *securityops.Service
	offline           *offlineinvestigations.Service
	audit             m365audit.Provider
	exchangeBootstrap *exchangebootstrap.Service

	templateMu      sync.Mutex
	approvalMu      sync.Mutex
	approvals       map[string]writeApproval
	policyTemplates map[string]model.TLPolicyTemplate
	nextTemplateSeq int

	// Share Detective investigations: ephemeral operational state, like
	// pending approvals (a fresh scan beats trusting a stale one).
	sdMu             sync.Mutex
	sdInvestigations map[string]*model.ShareInvestigation

	tlAppsMu         sync.Mutex
	tlApps           []model.TLApplication
	tlAppsExpiresAt  time.Time
	tlAppsGeneration uint64
	tlAppsFlight     singleflight.Group
}

// SetM365AuditProvider adds the separately-tokened Office 365 Management API
// diagnostics to tenant preflight without widening the core constructor used
// by offline tests.
func (s *Server) SetM365AuditProvider(provider m365audit.Provider) {
	s.audit = provider
}

// SetOfflineInvestigationService supplies the case analyzer used by API and
// worker startup without widening the constructor shared by older tests.
func (s *Server) SetOfflineInvestigationService(service *offlineinvestigations.Service) {
	s.offline = service
}

func New(cfg *config.Config, log *slog.Logger, st store.Store, gp graph.Provider, tlp threatlocker.Provider, au *auth.Service, jq jobs.Enqueuer) *Server {
	s := &Server{
		cfg: cfg, log: log, store: st, graph: gp, tl: tlp, auth: au, jobs: jq,
		reports: reports.New(st, gp, tlp, log), policyTemplates: map[string]model.TLPolicyTemplate{}, approvals: map[string]writeApproval{},
		security:         securityops.New(st, gp, log),
		offline:          offlineinvestigations.New(st, log),
		sdInvestigations: map[string]*model.ShareInvestigation{},
	}
	s.exchangeBootstrap = exchangebootstrap.New(exchangebootstrap.Config{}, func(ctx context.Context, tenantID string) (exchangebootstrap.RuntimeAuth, error) {
		creds, err := st.TenantCreds(ctx, tenantID)
		if err != nil {
			return exchangebootstrap.RuntimeAuth{}, err
		}
		resolved := creds.Resolved()
		clientID, clientSecret := resolved.ExchangeClientID, resolved.ExchangeClientSecret
		if clientID == "" {
			clientID, clientSecret = cfg.EntraClientID, cfg.EntraClientSecret
		}
		return exchangebootstrap.RuntimeAuth{DirectoryID: resolved.Authority(), ClientID: clientID, ClientSecret: clientSecret}, nil
	})
	return s
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(httpx.Recover(s.log))
	r.Use(httpx.Correlation)
	r.Use(rejectEmptyTenantPath)
	r.Use(httpx.Logger(s.log))
	r.Use(httpx.CORS(s.cfg.CORSOrigin))

	// Unauthenticated
	r.Get("/healthz", s.health)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/version", s.version)
		// Microsoft returns here after the one-use delegated Exchange RBAC
		// authorization. State + PKCE authenticate the callback; no RTM bearer
		// token or Microsoft token is accepted from the browser.
		r.With(httpx.RateLimit(30, time.Minute)).Post("/microsoft/exchange/bootstrap/callback", s.completeExchangeBootstrap)

		// Auth (unauthenticated, rate-limited per IP)
		r.With(httpx.RateLimit(10, time.Minute)).Post("/auth/login", s.login)
		r.With(httpx.RateLimit(20, time.Minute)).Post("/auth/refresh", s.refresh)

		// Everything below requires a valid bearer token.
		r.Group(func(r chi.Router) {
			r.Use(s.auth.Middleware)

			// The only routes reachable while a password change is pending:
			// identify yourself and rotate the password.
			r.Get("/auth/me", s.me)
			r.With(httpx.RateLimit(10, time.Minute)).Post("/auth/change-password", s.changePassword)

			r.Group(func(r chi.Router) {
				r.Use(s.auth.RequirePasswordChanged)

				// Tenants: every authenticated operator can see and work every
				// managed tenant (no per-tenant grant model). Connecting,
				// changing connections, and removing tenants is admin-only.
				r.Get("/tenants", s.listTenants)
				r.With(s.auth.RequirePermission(seed.PermissionManageTenants)).Post("/tenants", s.createTenant)
				r.Route("/tenants/{tenantId}", func(r chi.Router) {
					r.Get("/", s.getTenant)
					r.With(s.auth.RequirePermission(seed.PermissionManageTenants)).Put("/", s.updateTenantSettings)
					r.With(s.auth.RequirePermission(seed.PermissionManageTenants)).Delete("/", s.deleteTenant)
					r.Post("/test", s.testTenant)
					// Preflight probes the tenant's Graph permissions per
					// feature area. GET returns the last durable snapshot;
					// POST performs and saves a fresh diagnostic run.
					r.Get("/preflight", s.getPreflight)
					r.Post("/preflight", s.runPreflight)
					r.With(s.auth.RequirePermission(seed.PermissionManageTenants), httpx.RateLimit(10, time.Minute)).Post("/exchange/bootstrap/preview", s.previewExchangeBootstrap)
					r.With(s.auth.RequirePermission(seed.PermissionManageTenants), httpx.RateLimit(10, time.Minute)).Post("/exchange/bootstrap", s.startExchangeBootstrap)
					r.Get("/users", s.listUsers)
					// Full directory object for one user (audited PII read).
					r.Get("/users/{userId}/raw", s.getUserRaw)
					// Share Detective: read-only shared-access investigation;
					// revoking findings is admin-only behind What-If approval.
					r.Route("/share-detective", func(r chi.Router) {
						r.Get("/investigations", s.listShareInvestigations)
						r.Post("/investigations", s.startShareInvestigation)
						r.Get("/investigations/{invId}", s.getShareInvestigation)
						r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/investigations/{invId}/revoke-preview", s.previewShareRevoke)
						r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/investigations/{invId}/revoke", s.executeShareRevoke)
					})
					r.Get("/groups", s.listGroups)
					r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/groups", s.createGroup)
					r.Get("/groups/{groupId}/members", s.listGroupMembers)
					r.Get("/licenses", s.listLicenses)
					r.Get("/exchange/mailboxes", s.listMailboxes)
					r.Get("/exchange/mailboxes/{mailboxId}/settings", s.getMailboxSettings)
					r.Get("/exchange/mailboxes/{mailboxId}/permissions", s.listMailboxPermissions)
					r.Get("/sharepoint/sites", s.listSites)
					r.Get("/sharepoint/sites/{siteId}/permissions", s.listSitePermissions)
					r.Get("/sharepoint/inventory", s.getSharePointInventory)
					r.Get("/sharepoint/scans", s.listSharePointScans)
					r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/sharepoint/scans", s.startSharePointScan)
					r.Get("/sharepoint/permissions", s.getSharePointScopePermissions)
					r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/sharepoint/permissions/preview", s.previewSharePointPermission)
					r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/sharepoint/permissions/execute", s.executeSharePointPermission)
					r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/sharepoint/permissions/revert", s.revertSharePointPermission)
				})

				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policy-templates/promote", s.promoteTLPolicyTemplate)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policy-templates/merge", s.mergeTLPolicyTemplate)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policy-templates/{templateId}/deploy", s.deployTLPolicyTemplate)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policy-templates/{templateId}/deploy/preview", s.previewTLPolicyTemplateDeploy)
				r.Get("/threatlocker/devices", s.listDevices)
				r.Get("/threatlocker/devices/{deviceId}", s.getDevice)
				r.Get("/threatlocker/device-groups", s.listDeviceGroups)
				r.Get("/threatlocker/approval-requests", s.listApprovalRequests)
				r.Get("/threatlocker/approval-requests/{requestId}", s.getApprovalRequest)
				r.Get("/threatlocker/apps", s.listTLApps)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Get("/threatlocker/apps/cleanup-candidates", s.listTLAppCleanupCandidates)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/apps/cleanup-preview", s.previewTLAppCleanup)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/apps/cleanup-parent-promote", s.promoteTLAppCleanupParent)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/apps/cleanup-execute", s.executeTLAppCleanup)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Get("/threatlocker/apps/cleanup-operations", s.listTLAppCleanupOperations)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/apps/cleanup-operations/{operationId}/verify", s.verifyTLAppCleanupOperation)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/apps/cleanup-operations/{operationId}/reconcile", s.reconcileTLAppCleanupOperation)
				r.Get("/threatlocker/apps/{appId}", s.getTLApp)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/apps/{appId}/preview", s.previewTLAppUpdate)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Patch("/threatlocker/apps/{appId}", s.updateTLApp)
				r.Get("/threatlocker/policies", s.listTLPolicies)
				r.Get("/threatlocker/policies/{policyId}", s.getTLPolicy)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policies/{policyId}/preview", s.previewTLPolicyUpdate)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Patch("/threatlocker/policies/{policyId}", s.updateTLPolicy)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policies/{policyId}/promote-global", s.promoteTLPolicyGlobal)
				r.With(s.auth.RequirePermission(seed.PermissionManageThreatLocker)).Post("/threatlocker/policies/{policyId}/promote-global/preview", s.previewTLPolicyPromote)

				// Operations
				r.Get("/security/operations", s.securityOperations)
				r.Get("/security/storylines/{storylineId}", s.getSecurityStoryline)
				r.Patch("/security/storylines/{storylineId}", s.triageSecurityStoryline)
				r.Patch("/security/incidents", s.bulkTriageSecurityIncidents)
				r.Get("/security/incidents/{tenantId}/{incidentId}", s.getSecurityIncident)
				r.Patch("/security/incidents/{tenantId}/{incidentId}", s.triageSecurityIncident)
				r.Get("/security/events", s.searchSecurityEvents)
				r.Get("/security/events/{tenantId}/{eventId}", s.getSecurityEvent)
				r.Get("/security/offline-investigations", s.listOfflineInvestigations)
				r.Post("/security/offline-investigations", s.createOfflineInvestigation)
				r.Route("/security/offline-investigations/{investigationId}", func(r chi.Router) {
					r.Get("/", s.getOfflineInvestigation)
					r.With(s.auth.RequirePermission(seed.PermissionManageSecurity)).Delete("/", s.deleteOfflineInvestigation)
					r.With(httpx.RateLimit(30, time.Minute)).Post("/files", s.uploadOfflineInvestigationFile)
					r.With(httpx.RateLimit(10, time.Minute)).Post("/analyze", s.analyzeOfflineInvestigation)
				})
				r.Get("/security/detection-rules", s.listSecurityDetectionRules)
				r.Get("/security/detection-rules/options", s.listSecurityRuleConditionOptions)
				r.With(s.auth.RequirePermission(seed.PermissionManageSecurity)).Post("/security/detection-rules/preview", s.previewSecurityDetectionRule)
				r.With(s.auth.RequirePermission(seed.PermissionManageSecurity)).Post("/security/detection-rules", s.createSecurityDetectionRule)
				r.Get("/security/detection-rules/{ruleId}", s.getSecurityDetectionRule)
				r.Get("/security/detection-rules/{ruleId}/revisions", s.listSecurityDetectionRuleRevisions)
				r.With(s.auth.RequirePermission(seed.PermissionManageSecurity)).Put("/security/detection-rules/{ruleId}", s.updateSecurityDetectionRule)
				r.With(s.auth.RequirePermission(seed.PermissionManageSecurity)).Post("/security/detection-rules/{ruleId}/revisions/{revision}/restore", s.restoreSecurityDetectionRuleRevision)
				r.Get("/working-sets", s.listWorkingSets)
				r.Post("/working-sets", s.createWorkingSet)
				r.Get("/working-sets/{workingSetId}", s.getWorkingSet)
				r.Put("/working-sets/{workingSetId}", s.updateWorkingSet)
				r.Get("/jobs", s.listJobs)
				r.Post("/jobs/{jobId}/acknowledge", s.acknowledgeJob)
				r.Get("/changes", s.listChanges)
				r.Get("/changes/{id}", s.getChange)

				// Workflow actions (async → job) use the editable role policy.
				r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/changes/preview", s.previewChange)
				r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/changes/execute", s.executeChange)
				r.With(s.auth.RequirePermission(seed.PermissionExecuteChanges)).Post("/changes/revert", s.revertChange)

				// Governance
				r.Get("/global-reports/{type}", s.globalReport)
				r.Post("/exports/generate", s.generateExport)
				r.Get("/audit", s.listAudit)

				// Admin
				r.With(s.auth.RequirePermission(seed.PermissionManageTechnicians)).Get("/admin/technicians", s.adminTechnicians)
				r.With(s.auth.RequirePermission(seed.PermissionManageTechnicians)).Post("/admin/technicians", s.createTechnician)
				r.With(s.auth.RequirePermission(seed.PermissionManageTechnicians)).Patch("/admin/technicians/{id}", s.updateTechnician)
				r.With(s.auth.RequirePermission(seed.PermissionManageTechnicians), httpx.RateLimit(10, time.Minute)).Post("/admin/technicians/{id}/reset-password", s.resetTechnicianPassword)
				r.With(s.auth.RequirePermission(seed.PermissionManageTechnicians)).Delete("/admin/technicians/{id}", s.deleteTechnician)
				r.With(s.auth.RequirePermission(seed.PermissionManageRoles)).Get("/admin/roles", s.adminRoles)
				r.With(s.auth.RequirePermission(seed.PermissionManageRoles)).Put("/admin/roles/{name}", s.updateRole)
				r.With(s.auth.RequirePermission(seed.PermissionManageSettings)).Get("/admin/settings", s.adminSettings)
				r.With(s.auth.RequirePermission(seed.PermissionManageSettings)).Patch("/admin/settings/{key}", s.updateSetting)
				r.With(s.auth.RequirePermission(seed.PermissionManageSettings)).Get("/admin/threatlocker", s.adminThreatLocker)
				r.With(s.auth.RequirePermission(seed.PermissionManageSettings)).Put("/admin/threatlocker", s.updateAdminThreatLocker)

				// Dashboard
				r.Get("/dashboard/stats", s.dashboardStats)
				r.Get("/dashboard/approvals", s.dashboardApprovals)
			})
		})
	})

	return r
}

func rejectEmptyTenantPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.EscapedPath(), "/tenants//") {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.CodeValidationFailed, "A non-empty tenant ID is required.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
