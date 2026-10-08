package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
	"golang.org/x/crypto/bcrypt"
)

// Mem is the in-memory Store used when no database is configured. Operational
// data (jobs, changes, audit, working sets) starts empty — it only ever holds
// what the platform actually did.
type Mem struct {
	mu                    sync.RWMutex
	tenants               []model.Tenant
	tenantCreds           map[string]TenantCreds // tenantID → Entra creds ("" fields = global app)
	tenantPreflights      map[string]model.Preflight
	workingSets           []model.WorkingSet
	jobs                  []model.Job
	changes               []model.Change
	details               map[string]model.ChangeDetail          // changeID → full detail
	securityStates        map[string]model.SecurityIncidentState // tenantID|incidentID → receipt + local triage
	securityCheckpoints   map[string]model.SecurityAuditCheckpoint
	securityHistory       map[string]model.SecurityHistoryImport
	securityEvents        map[string]model.SecurityAuditEvent           // tenantID|providerRecordID → event
	securityEventAliases  map[string]string                             // provider event ID → canonical event ID
	securityEvidence      map[string][]model.SecurityAuditEventEvidence // canonical event ID → source payloads
	securityDetections    map[string]model.SecurityNativeDetection
	securityStorylines    map[string]model.SecurityStoryline
	securityReplays       map[int]bool
	securityRules         map[string]model.SecurityDetectionRule
	securityRevisions     map[string][]model.SecurityDetectionRuleRevision
	offlineInvestigations map[string]model.OfflineInvestigation
	offlineFiles          map[string][]model.OfflineInvestigationFile
	offlineAnalysis       map[string]model.OfflineInvestigationAnalysis
	audit                 []model.AuditEntry
	accounts              map[string]Account // by lowercased email
	roles                 []model.Role
	refresh               map[string]string // accountID → current refresh jti
	settings              []model.AppSetting
	globalTL              ThreatLockerGlobalConfig
	spScans               []model.SharePointScan
	spInventory           map[string]model.SharePointInventory // tenantID|scope → latest
	tlCleanupOperations   []model.TLAppCleanupOperation
	seq                   int
}

// NewMem builds an in-memory store seeded with the bootstrap dataset.
func NewMem() *Mem {
	accounts := map[string]Account{}
	for _, a := range seed.Accounts {
		hash, _ := bcrypt.GenerateFromPassword([]byte(a.Password), bcrypt.DefaultCost)
		accounts[a.Email] = Account{
			ID: a.ID, Name: a.Name, Email: a.Email, Role: a.Role, IsAdmin: a.IsAdmin,
			Status: a.Status, PasswordHash: string(hash), MustChange: a.MustChange,
		}
	}
	return &Mem{
		tenants:               append([]model.Tenant(nil), seed.Tenants...),
		tenantCreds:           map[string]TenantCreds{},
		tenantPreflights:      map[string]model.Preflight{},
		details:               map[string]model.ChangeDetail{},
		securityStates:        map[string]model.SecurityIncidentState{},
		securityCheckpoints:   map[string]model.SecurityAuditCheckpoint{},
		securityHistory:       map[string]model.SecurityHistoryImport{},
		securityEvents:        map[string]model.SecurityAuditEvent{},
		securityEventAliases:  map[string]string{},
		securityEvidence:      map[string][]model.SecurityAuditEventEvidence{},
		securityDetections:    map[string]model.SecurityNativeDetection{},
		securityStorylines:    map[string]model.SecurityStoryline{},
		securityReplays:       map[int]bool{},
		securityRules:         map[string]model.SecurityDetectionRule{},
		securityRevisions:     map[string][]model.SecurityDetectionRuleRevision{},
		offlineInvestigations: map[string]model.OfflineInvestigation{},
		offlineFiles:          map[string][]model.OfflineInvestigationFile{},
		offlineAnalysis:       map[string]model.OfflineInvestigationAnalysis{},
		accounts:              accounts,
		roles:                 cloneRoles(seed.Roles),
		refresh:               map[string]string{},
		settings:              append([]model.AppSetting(nil), seed.AppSettings...),
		spInventory:           map[string]model.SharePointInventory{},
	}
}

func (m *Mem) Close() {}

// ---- Tenants ----

func (m *Mem) Tenants(context.Context) ([]model.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Tenant, len(m.tenants))
	for i, t := range m.tenants {
		t.Connections = connectionsFor(m.tenantCreds[t.ID])
		out[i] = t
	}
	return out, nil
}

func (m *Mem) Tenant(_ context.Context, id string) (model.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tenants {
		if t.ID == id {
			t.Connections = connectionsFor(m.tenantCreds[id])
			return t, nil
		}
	}
	return model.Tenant{}, ErrNotFound
}

func (m *Mem) TenantPreflight(_ context.Context, tenantID string) (model.Preflight, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	preflight, ok := m.tenantPreflights[tenantID]
	if !ok {
		return model.Preflight{}, ErrNotFound
	}
	preflight.Checks = append([]model.PreflightCheck(nil), preflight.Checks...)
	return preflight, nil
}

func (m *Mem) UpsertTenantPreflight(_ context.Context, tenantID string, preflight model.Preflight) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for _, tenant := range m.tenants {
		if tenant.ID == tenantID {
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	preflight.Checks = append([]model.PreflightCheck(nil), preflight.Checks...)
	m.tenantPreflights[tenantID] = preflight
	return nil
}

func (m *Mem) CreateTenant(_ context.Context, nt NewTenant) (model.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	created := model.Tenant{
		ID: fmt.Sprintf("ten_new_%d", m.seq), Name: nt.Name, Domain: nt.Domain,
		MicrosoftTenantID: nt.MicrosoftTenantID, Status: "Disconnected",
		Users: 0, LastGraphTest: "—",
		Modules: []string{"Users", "Groups", "Exchange", "SharePoint", "Licensing"},
	}
	m.tenants = append(m.tenants, created)
	creds := TenantCreds{
		MicrosoftTenantID: nt.MicrosoftTenantID, Domain: nt.Domain,
		ClientID: nt.ClientID, ClientSecret: nt.ClientSecret,
		ExchangeClientID: nt.ExchangeClientID, ExchangeClientSecret: nt.ExchangeClientSecret,
		SharePointClientID: nt.SharePointClientID, SharePointClientSecret: nt.SharePointClientSecret,
		SharePointAdminURL: nt.SharePointAdminURL,
	}
	m.tenantCreds[created.ID] = creds
	created.Connections = connectionsFor(creds)
	return created, nil
}

func (m *Mem) UpdateTenant(_ context.Context, id string, update TenantUpdate) (model.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.tenants {
		if m.tenants[i].ID != id {
			continue
		}
		tenant := m.tenants[i]
		creds := m.tenantCreds[id]
		if creds.MicrosoftTenantID == "" {
			creds.MicrosoftTenantID, creds.Domain = tenant.MicrosoftTenantID, tenant.Domain
		}
		applyTenantUpdate(&tenant, &creds, update)
		m.tenants[i], m.tenantCreds[id] = tenant, creds
		tenant.Connections = connectionsFor(creds)
		return tenant, nil
	}
	return model.Tenant{}, ErrNotFound
}

func applyTenantUpdate(t *model.Tenant, c *TenantCreds, u TenantUpdate) {
	if u.Name != nil {
		t.Name = *u.Name
	}
	if u.Domain != nil {
		t.Domain, c.Domain = *u.Domain, *u.Domain
	}
	if u.MicrosoftTenantID != nil {
		t.MicrosoftTenantID, c.MicrosoftTenantID = *u.MicrosoftTenantID, *u.MicrosoftTenantID
	}
	if u.ClearGraph {
		c.ClientID, c.ClientSecret = "", ""
	} else {
		if u.ClientID != nil {
			c.ClientID = *u.ClientID
		}
		if u.ClientSecret != nil && *u.ClientSecret != "" {
			c.ClientSecret = *u.ClientSecret
		}
	}
	if u.ClearExchange {
		c.ExchangeClientID, c.ExchangeClientSecret = "", ""
	} else {
		if u.ExchangeClientID != nil {
			c.ExchangeClientID = *u.ExchangeClientID
		}
		if u.ExchangeClientSecret != nil && *u.ExchangeClientSecret != "" {
			c.ExchangeClientSecret = *u.ExchangeClientSecret
		}
	}
	if u.SharePointAdminURL != nil {
		c.SharePointAdminURL = *u.SharePointAdminURL
	}
}

func (m *Mem) DeleteTenant(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tenants {
		if t.ID == id {
			m.tenants = append(m.tenants[:i], m.tenants[i+1:]...)
			delete(m.tenantCreds, id)
			delete(m.tenantPreflights, id)
			keptWorkingSets := m.workingSets[:0]
			for _, workingSet := range m.workingSets {
				if workingSet.TenantID != id {
					keptWorkingSets = append(keptWorkingSets, workingSet)
				}
			}
			m.workingSets = keptWorkingSets
			for key, state := range m.securityStates {
				if state.TenantID == id {
					delete(m.securityStates, key)
				}
			}
			for key, checkpoint := range m.securityCheckpoints {
				if checkpoint.TenantID == id {
					delete(m.securityCheckpoints, key)
				}
			}
			for key, event := range m.securityEvents {
				if event.TenantID == id {
					delete(m.securityEvidence, event.ID)
					delete(m.securityEvents, key)
				}
			}
			for key, detection := range m.securityDetections {
				if detection.TenantID == id {
					delete(m.securityDetections, key)
				}
			}
			for key, storyline := range m.securityStorylines {
				if containsString(storyline.TenantIDs, id, "") {
					delete(m.securityStorylines, key)
				}
			}
			for ruleID, rule := range m.securityRules {
				if rule.Scope == "tenant" && rule.TenantID == id {
					delete(m.securityRules, ruleID)
					delete(m.securityRevisions, ruleID)
				}
			}
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) UpdateTenantStatus(_ context.Context, id, status, lastGraphTest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.tenants {
		if m.tenants[i].ID == id {
			m.tenants[i].Status = status
			m.tenants[i].LastGraphTest = lastGraphTest
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) TenantCreds(_ context.Context, id string) (TenantCreds, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if c, ok := m.tenantCreds[id]; ok {
		return c, nil
	}
	// Seeded tenants have no stored creds; fall back to the tenant record so
	// the Graph layer still gets the authority.
	for _, t := range m.tenants {
		if t.ID == id {
			return TenantCreds{MicrosoftTenantID: t.MicrosoftTenantID, Domain: t.Domain}, nil
		}
	}
	return TenantCreds{}, ErrNotFound
}

func (m *Mem) ThreatLockerGlobalConfig(context.Context) (ThreatLockerGlobalConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.globalTL, nil
}

func (m *Mem) UpdateThreatLockerGlobalConfig(_ context.Context, c ThreatLockerGlobalConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalTL = c
	return nil
}

func (m *Mem) TLAppCleanupOperations(_ context.Context, tenantID string) ([]model.TLAppCleanupOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.TLAppCleanupOperation, 0, len(m.tlCleanupOperations))
	for _, operation := range m.tlCleanupOperations {
		if operation.TenantID == tenantID {
			out = append(out, operation)
		}
	}
	return out, nil
}

func (m *Mem) ActiveTLAppCleanupOperation(_ context.Context, fingerprint string) (model.TLAppCleanupOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, operation := range m.tlCleanupOperations {
		if operation.Fingerprint == fingerprint && activeTLCleanupStatus(operation.Status) {
			return operation, nil
		}
	}
	return model.TLAppCleanupOperation{}, ErrNotFound
}

func (m *Mem) CreateTLAppCleanupOperation(_ context.Context, operation model.TLAppCleanupOperation) (model.TLAppCleanupOperation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.tlCleanupOperations {
		if existing.Fingerprint == operation.Fingerprint && activeTLCleanupStatus(existing.Status) {
			return model.TLAppCleanupOperation{}, ErrConflict
		}
	}
	if operation.ID == "" {
		m.seq++
		operation.ID = fmt.Sprintf("tlop_%d", m.seq)
	}
	now := time.Now().UTC()
	if operation.CreatedAt.IsZero() {
		operation.CreatedAt = now
	}
	if operation.UpdatedAt.IsZero() {
		operation.UpdatedAt = operation.CreatedAt
	}
	m.tlCleanupOperations = append([]model.TLAppCleanupOperation{operation}, m.tlCleanupOperations...)
	return operation, nil
}

func (m *Mem) UpdateTLAppCleanupOperation(_ context.Context, id, status string, result model.TLAppCleanupResult, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.tlCleanupOperations {
		if m.tlCleanupOperations[i].ID == id {
			m.tlCleanupOperations[i].Status = status
			m.tlCleanupOperations[i].Result = result
			m.tlCleanupOperations[i].Error = errorMessage
			m.tlCleanupOperations[i].UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return ErrNotFound
}

func activeTLCleanupStatus(status string) bool {
	return status == model.TLCleanupSubmitted ||
		status == model.TLCleanupVerificationPending ||
		status == model.TLCleanupNeedsReconciliation
}

// ---- SharePoint inventory ----

func (m *Mem) CreateSharePointScan(_ context.Context, scan model.SharePointScan) (model.SharePointScan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	if scan.ID == "" {
		scan.ID = fmt.Sprintf("spscan_%d", m.seq)
	}
	if scan.StartedAt == "" {
		scan.StartedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if scan.Coverage == "" {
		scan.Coverage = "pending"
	}
	m.spScans = append([]model.SharePointScan{scan}, m.spScans...)
	return scan, nil
}

func (m *Mem) CompleteSharePointScan(_ context.Context, scan model.SharePointScan, nodes []model.SharePointInventoryNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for i := range m.spScans {
		if m.spScans[i].ID == scan.ID {
			m.spScans[i] = scan
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	copied := append([]model.SharePointInventoryNode(nil), nodes...)
	m.spInventory[scan.TenantID+"|"+scan.Scope] = model.SharePointInventory{Scan: scan, Nodes: copied}
	return nil
}

func (m *Mem) SharePointScans(_ context.Context, tenantID string) ([]model.SharePointScan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SharePointScan, 0, len(m.spScans))
	for _, scan := range m.spScans {
		if scan.TenantID == tenantID {
			copyScan := scan
			copyScan.Warnings = append([]string(nil), scan.Warnings...)
			out = append(out, copyScan)
		}
	}
	return out, nil
}

func (m *Mem) SharePointInventory(_ context.Context, tenantID, scope string) (model.SharePointInventory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	inv, ok := m.spInventory[tenantID+"|"+scope]
	if !ok {
		return model.SharePointInventory{}, ErrNotFound
	}
	inv.Scan.Warnings = append([]string(nil), inv.Scan.Warnings...)
	inv.Nodes = append([]model.SharePointInventoryNode(nil), inv.Nodes...)
	return inv, nil
}

// ---- Working sets ----

func (m *Mem) WorkingSets(context.Context) ([]model.WorkingSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]model.WorkingSet(nil), m.workingSets...)
	for i := range out {
		out[i].UserIDs = append([]string(nil), out[i].UserIDs...)
	}
	return out, nil
}

func (m *Mem) WorkingSet(_ context.Context, id string) (model.WorkingSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ws := range m.workingSets {
		if ws.ID == id {
			ws.UserIDs = append([]string(nil), ws.UserIDs...)
			return ws, nil
		}
	}
	return model.WorkingSet{}, ErrNotFound
}

func (m *Mem) CreateWorkingSet(_ context.Context, ws NewWorkingSet) (model.WorkingSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	created := model.WorkingSet{
		ID: fmt.Sprintf("ws_new_%d", m.seq), Name: ws.Name, Description: ws.Description, Type: "Users",
		Items: len(ws.UserIDs), TenantID: ws.TenantID, Tenant: ws.Tenant,
		UserIDs: append([]string(nil), ws.UserIDs...), CreatedBy: ws.CreatedBy, LastUsed: "just now",
	}
	m.workingSets = append([]model.WorkingSet{created}, m.workingSets...)
	created.UserIDs = append([]string(nil), created.UserIDs...)
	return created, nil
}

func (m *Mem) UpdateWorkingSet(_ context.Context, id string, update WorkingSetUpdate) (model.WorkingSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for index := range m.workingSets {
		if m.workingSets[index].ID != id {
			continue
		}
		m.workingSets[index].Name = update.Name
		m.workingSets[index].Description = update.Description
		m.workingSets[index].UserIDs = append([]string(nil), update.UserIDs...)
		m.workingSets[index].Items = len(update.UserIDs)
		updated := m.workingSets[index]
		updated.UserIDs = append([]string(nil), updated.UserIDs...)
		return updated, nil
	}
	return model.WorkingSet{}, ErrNotFound
}

// ---- Jobs ----

func (m *Mem) Jobs(context.Context) ([]model.Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.Job(nil), m.jobs...), nil
}

func (m *Mem) CreateJob(_ context.Context, j model.Job) (model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j.ID == "" {
		m.seq++
		j.ID = fmt.Sprintf("job_new_%d", m.seq)
	}
	m.jobs = append([]model.Job{j}, m.jobs...)
	return j, nil
}

func (m *Mem) UpdateJobStatus(_ context.Context, id, status string, progress int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.jobs {
		if m.jobs[i].ID == id {
			m.jobs[i].Status = status
			m.jobs[i].Progress = progress
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) CompleteJob(_ context.Context, id, status, duration string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.jobs {
		if m.jobs[i].ID == id {
			m.jobs[i].Status = status
			m.jobs[i].Progress = 100
			m.jobs[i].Duration = duration
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) AcknowledgeJob(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.jobs {
		if m.jobs[i].ID == id {
			m.jobs[i].Acknowledged = true
			return nil
		}
	}
	return ErrNotFound
}

// ---- Change history ----

func (m *Mem) Changes(context.Context) ([]model.Change, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.Change(nil), m.changes...), nil
}

func (m *Mem) Change(_ context.Context, id string) (model.ChangeDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if d, ok := m.details[id]; ok {
		return d, nil
	}
	return model.ChangeDetail{}, ErrNotFound
}

func (m *Mem) AppendChange(_ context.Context, c model.ChangeDetail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.ID == "" {
		m.seq++
		c.ID = fmt.Sprintf("chg_new_%d", m.seq)
		c.Change.ID = c.ID
	}
	m.changes = append([]model.Change{c.Change}, m.changes...)
	m.details[c.ID] = c
	return nil
}

func (m *Mem) UpdateChangeRevert(_ context.Context, id, revert string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.changes {
		if m.changes[i].ID == id {
			m.changes[i].Revert = revert
			d := m.details[id]
			d.Revert = revert
			m.details[id] = d
			return nil
		}
	}
	return ErrNotFound
}

// ---- Security Operations triage overlays ----

func (m *Mem) SecurityIncidentStates(context.Context) ([]model.SecurityIncidentState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityIncidentState, 0, len(m.securityStates))
	for _, state := range m.securityStates {
		out = append(out, state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (m *Mem) ObserveSecurityIncident(_ context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.securityIncidentTenantExists(state.TenantID) {
		return model.SecurityIncidentState{}, ErrNotFound
	}
	key := state.TenantID + "|" + state.IncidentID
	if existing, ok := m.securityStates[key]; ok {
		return existing, nil
	}
	if state.Status == "" {
		state.Status = model.SecurityTriageNew
	}
	if state.ReceivedAt.IsZero() {
		state.ReceivedAt = time.Now().UTC()
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = state.ReceivedAt
	}
	m.securityStates[key] = state
	return state, nil
}

func (m *Mem) UpsertSecurityIncidentState(_ context.Context, state model.SecurityIncidentState) (model.SecurityIncidentState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.securityIncidentTenantExists(state.TenantID) {
		return model.SecurityIncidentState{}, ErrNotFound
	}
	key := state.TenantID + "|" + state.IncidentID
	if existing, ok := m.securityStates[key]; ok && state.ReceivedAt.IsZero() {
		state.ReceivedAt = existing.ReceivedAt
	}
	if state.ReceivedAt.IsZero() {
		state.ReceivedAt = time.Now().UTC()
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	m.securityStates[key] = state
	return state, nil
}

// securityIncidentTenantExists is called only while m.mu is held.
func (m *Mem) securityIncidentTenantExists(tenantID string) bool {
	for _, tenant := range m.tenants {
		if tenant.ID == tenantID {
			return true
		}
	}
	return false
}

func securityCheckpointKey(tenantID, contentType string) string {
	return tenantID + "|" + contentType
}

func securityEventKey(tenantID, providerRecordID string) string {
	return tenantID + "|" + providerRecordID
}

func (m *Mem) SecurityAuditCheckpoints(context.Context) ([]model.SecurityAuditCheckpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityAuditCheckpoint, 0, len(m.securityCheckpoints))
	for _, checkpoint := range m.securityCheckpoints {
		out = append(out, checkpoint)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID == out[j].TenantID {
			return out[i].ContentType < out[j].ContentType
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out, nil
}

func (m *Mem) SecurityAuditCheckpoint(_ context.Context, tenantID, contentType string) (model.SecurityAuditCheckpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	checkpoint, ok := m.securityCheckpoints[securityCheckpointKey(tenantID, contentType)]
	if !ok {
		return model.SecurityAuditCheckpoint{}, ErrNotFound
	}
	return checkpoint, nil
}

func (m *Mem) SecurityHistoryImports(context.Context) ([]model.SecurityHistoryImport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityHistoryImport, 0, len(m.securityHistory))
	for _, history := range m.securityHistory {
		for _, tenant := range m.tenants {
			if tenant.ID == history.TenantID {
				history.TenantName = tenant.Name
				break
			}
		}
		out = append(out, history)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out, nil
}

func (m *Mem) SecurityHistoryImport(_ context.Context, tenantID string) (model.SecurityHistoryImport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	history, ok := m.securityHistory[tenantID]
	if !ok {
		return model.SecurityHistoryImport{}, ErrNotFound
	}
	for _, tenant := range m.tenants {
		if tenant.ID == tenantID {
			history.TenantName = tenant.Name
			break
		}
	}
	return history, nil
}

func (m *Mem) UpsertSecurityHistoryImport(_ context.Context, history model.SecurityHistoryImport) (model.SecurityHistoryImport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tenant := range m.tenants {
		if tenant.ID == history.TenantID {
			history.TenantName = tenant.Name
			m.securityHistory[history.TenantID] = history
			return history, nil
		}
	}
	return model.SecurityHistoryImport{}, ErrNotFound
}

func (m *Mem) SecurityAuditEventsSince(_ context.Context, since time.Time) ([]model.SecurityAuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityAuditEvent, 0, len(m.securityEvents))
	for _, event := range m.securityEvents {
		if event.OccurredAt.Before(since) {
			continue
		}
		event.Raw = append([]byte(nil), event.Raw...)
		event.Sources = append([]string(nil), event.Sources...)
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if len(out) > 50000 {
		out = out[:50000]
	}
	return out, nil
}

func (m *Mem) SecurityAuditEventsByIDs(_ context.Context, eventIDs []string) ([]model.SecurityAuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	wanted := make(map[string]struct{}, len(eventIDs))
	for _, id := range eventIDs {
		wanted[id] = struct{}{}
	}
	out := make([]model.SecurityAuditEvent, 0, len(wanted))
	for _, event := range m.securityEvents {
		if _, ok := wanted[event.ID]; !ok {
			continue
		}
		event.Raw = append([]byte(nil), event.Raw...)
		event.Sources = append([]string(nil), event.Sources...)
		out = append(out, event)
	}
	return out, nil
}

func (m *Mem) SearchSecurityAuditEvents(_ context.Context, query model.SecurityAuditEventSearch) ([]model.SecurityAuditEvent, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := query.Limit
	if limit < 1 || limit > 100 {
		limit = 50
	}
	var matches []model.SecurityAuditEvent
	needle := strings.ToLower(strings.TrimSpace(query.Query))
	for _, event := range m.securityEvents {
		if !query.From.IsZero() && event.OccurredAt.Before(query.From) || !query.To.IsZero() && event.OccurredAt.After(query.To) {
			continue
		}
		if query.TenantID != "" && event.TenantID != query.TenantID ||
			query.Workload != "" && !strings.EqualFold(event.Workload, query.Workload) ||
			query.Operation != "" && !strings.Contains(strings.ToLower(event.Operation), strings.ToLower(query.Operation)) ||
			query.Actor != "" && !strings.Contains(strings.ToLower(event.Actor), strings.ToLower(query.Actor)) ||
			query.ClientIP != "" && !strings.Contains(strings.ToLower(event.ClientIP), strings.ToLower(query.ClientIP)) ||
			query.Result != "" && !strings.EqualFold(event.ResultStatus, query.Result) {
			continue
		}
		if needle != "" {
			haystack := strings.ToLower(strings.Join([]string{event.Workload, event.Operation, event.Actor, event.ClientIP, event.ObjectID, event.ResultStatus}, " "))
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		event.Raw = append([]byte(nil), event.Raw...)
		event.Sources = append([]string(nil), event.Sources...)
		matches = append(matches, event)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].OccurredAt.After(matches[j].OccurredAt) })
	if query.Offset >= len(matches) {
		return []model.SecurityAuditEvent{}, false, nil
	}
	end := query.Offset + limit
	hasMore := end < len(matches)
	if end > len(matches) {
		end = len(matches)
	}
	return matches[query.Offset:end], hasMore, nil
}

func (m *Mem) SecurityAuditEvent(_ context.Context, tenantID, eventID string) (model.SecurityAuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, event := range m.securityEvents {
		if event.TenantID == tenantID && event.ID == eventID {
			event.Raw = append([]byte(nil), event.Raw...)
			event.Sources = append([]string(nil), event.Sources...)
			return event, nil
		}
	}
	return model.SecurityAuditEvent{}, ErrNotFound
}

func (m *Mem) SecurityAuditEventEvidence(_ context.Context, tenantID, eventID string) ([]model.SecurityAuditEventEvidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	canonicalID := m.securityEventAliases[eventID]
	if canonicalID == "" {
		canonicalID = eventID
	}
	found := false
	for _, event := range m.securityEvents {
		if event.TenantID == tenantID && event.ID == canonicalID {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	evidence := m.securityEvidence[canonicalID]
	out := make([]model.SecurityAuditEventEvidence, len(evidence))
	for i := range evidence {
		out[i] = evidence[i]
		out[i].Raw = append([]byte(nil), evidence[i].Raw...)
	}
	return out, nil
}

func (m *Mem) StoreSecurityAuditBatch(_ context.Context, checkpoint model.SecurityAuditCheckpoint, events []model.SecurityAuditEvent, detections []model.SecurityNativeDetection) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tenantFound := false
	for _, tenant := range m.tenants {
		if tenant.ID == checkpoint.TenantID {
			tenantFound = true
			break
		}
	}
	if !tenantFound {
		return 0, ErrNotFound
	}
	inserted := 0
	insertedEventIDs := map[string]struct{}{}
	canonicalEventIDs := map[string]string{}
	for _, event := range events {
		if event.AvailableAt.IsZero() {
			event.AvailableAt = event.IngestedAt
		}
		if len(event.Sources) == 0 {
			event.Sources = []string{"m365_audit"}
		}
		key := securityEventKey(event.TenantID, event.ProviderRecordID)
		existing, exists := m.securityEvents[key]
		if !exists {
			semanticKey := securityEventSemanticKey(event)
			if semanticKey != "" {
				for candidateKey, candidate := range m.securityEvents {
					if securityEventSemanticKey(candidate) == semanticKey && withinSecurityDedupWindow(candidate.OccurredAt, event.OccurredAt) {
						key, existing, exists = candidateKey, candidate, true
						break
					}
				}
			}
		}
		if exists {
			if existing.AvailableAt.IsZero() || !event.AvailableAt.IsZero() && event.AvailableAt.Before(existing.AvailableAt) {
				existing.AvailableAt = event.AvailableAt
			}
			if existing.IngestedAt.IsZero() || !event.IngestedAt.IsZero() && event.IngestedAt.Before(existing.IngestedAt) {
				existing.IngestedAt = event.IngestedAt
			}
			seen := map[string]bool{}
			for _, source := range existing.Sources {
				seen[source] = true
			}
			for _, source := range event.Sources {
				if !seen[source] {
					existing.Sources = append(existing.Sources, source)
					seen[source] = true
				}
			}
			if hasString(event.Sources, "m365_audit") {
				existing.ContentType, existing.Workload, existing.Raw = event.ContentType, event.Workload, append([]byte(nil), event.Raw...)
				if event.Operation != "" {
					existing.Operation = event.Operation
				}
				if event.Actor != "" {
					existing.Actor = event.Actor
				}
				if event.ClientIP != "" {
					existing.ClientIP = event.ClientIP
				}
				if event.ObjectID != "" {
					existing.ObjectID = event.ObjectID
				}
				if event.ResultStatus != "" {
					existing.ResultStatus = event.ResultStatus
				}
			}
			m.securityEvents[key] = existing
			canonicalEventIDs[event.ID] = existing.ID
			m.securityEventAliases[event.ID] = existing.ID
			m.storeSecurityEventEvidence(existing.ID, event)
			continue
		}
		event.Raw = append([]byte(nil), event.Raw...)
		event.Sources = append([]string(nil), event.Sources...)
		m.securityEvents[key] = event
		canonicalEventIDs[event.ID] = event.ID
		m.securityEventAliases[event.ID] = event.ID
		m.storeSecurityEventEvidence(event.ID, event)
		insertedEventIDs[event.ID] = struct{}{}
		inserted++
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
		var equivalentID string
		for id, existing := range m.securityDetections {
			if existing.TenantID == detection.TenantID && existing.EventID == detection.EventID && existing.RuleID == detection.RuleID && existing.RuleVersion == detection.RuleVersion {
				equivalentID = id
				break
			}
		}
		if equivalentID != "" {
			existing := m.securityDetections[equivalentID]
			existing.EventIDs = mergeStringValues(existing.EventIDs, detection.EventIDs, existing.EventID)
			m.securityDetections[equivalentID] = existing
			continue
		}
		if existing, exists := m.securityDetections[detection.ID]; exists {
			existing.EventIDs = mergeStringValues(existing.EventIDs, detection.EventIDs, existing.EventID)
			m.securityDetections[detection.ID] = existing
			continue
		}
		if detection.DetectionType == "" {
			detection.DetectionType = "direct"
		}
		if detection.Confidence == "" {
			detection.Confidence = "medium"
		}
		if _, justInserted := insertedEventIDs[detection.EventID]; !justInserted {
			found := false
			for _, event := range m.securityEvents {
				if event.ID == detection.EventID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		detection.Entities = append([]model.SecurityEntity(nil), detection.Entities...)
		detection.EventIDs = append([]string(nil), detection.EventIDs...)
		if len(detection.EventIDs) == 0 {
			detection.EventIDs = []string{detection.EventID}
		}
		m.securityDetections[detection.ID] = detection
	}
	checkpoint.EventsInserted = inserted
	if checkpoint.ContentType != "" {
		m.securityCheckpoints[securityCheckpointKey(checkpoint.TenantID, checkpoint.ContentType)] = checkpoint
	}
	return inserted, nil
}

func (m *Mem) storeSecurityEventEvidence(canonicalID string, event model.SecurityAuditEvent) {
	for _, source := range event.Sources {
		if source == "historical_backfill" {
			continue
		}
		evidence := model.SecurityAuditEventEvidence{
			Source: source, ProviderRecordID: event.ProviderRecordID, ContentType: event.ContentType,
			AvailableAt: event.AvailableAt, IngestedAt: event.IngestedAt, Raw: append([]byte(nil), event.Raw...),
		}
		items := m.securityEvidence[canonicalID]
		updated := false
		for i := range items {
			if items[i].Source == source && items[i].ProviderRecordID == event.ProviderRecordID {
				if !items[i].AvailableAt.IsZero() && (evidence.AvailableAt.IsZero() || items[i].AvailableAt.Before(evidence.AvailableAt)) {
					evidence.AvailableAt = items[i].AvailableAt
				}
				if !items[i].IngestedAt.IsZero() && (evidence.IngestedAt.IsZero() || items[i].IngestedAt.Before(evidence.IngestedAt)) {
					evidence.IngestedAt = items[i].IngestedAt
				}
				items[i] = evidence
				updated = true
				break
			}
		}
		if !updated {
			items = append(items, evidence)
		}
		m.securityEvidence[canonicalID] = items
	}
}

func hasString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (m *Mem) StoreSecurityNativeDetections(_ context.Context, detections []model.SecurityNativeDetection) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	eventIDs := make(map[string]struct{}, len(m.securityEvents))
	for _, event := range m.securityEvents {
		eventIDs[event.ID] = struct{}{}
	}
	inserted := 0
	for _, detection := range detections {
		if canonicalID := m.securityEventAliases[detection.EventID]; canonicalID != "" {
			detection.EventID = canonicalID
		}
		for index, eventID := range detection.EventIDs {
			if canonicalID := m.securityEventAliases[eventID]; canonicalID != "" {
				detection.EventIDs[index] = canonicalID
			}
		}
		detection.EventIDs = mergeStringValues(nil, detection.EventIDs, detection.EventID)
		var equivalentID string
		for id, existing := range m.securityDetections {
			if existing.TenantID == detection.TenantID && existing.EventID == detection.EventID && existing.RuleID == detection.RuleID && existing.RuleVersion == detection.RuleVersion {
				equivalentID = id
				break
			}
		}
		if equivalentID != "" {
			existing := m.securityDetections[equivalentID]
			existing.EventIDs = mergeStringValues(existing.EventIDs, detection.EventIDs, existing.EventID)
			m.securityDetections[equivalentID] = existing
			continue
		}
		if existing, exists := m.securityDetections[detection.ID]; exists {
			existing.EventIDs = mergeStringValues(existing.EventIDs, detection.EventIDs, existing.EventID)
			m.securityDetections[detection.ID] = existing
			continue
		}
		if _, exists := eventIDs[detection.EventID]; !exists {
			continue
		}
		if detection.DetectionType == "" {
			detection.DetectionType = "direct"
		}
		if detection.Confidence == "" {
			detection.Confidence = "medium"
		}
		detection.Entities = append([]model.SecurityEntity(nil), detection.Entities...)
		detection.EventIDs = append([]string(nil), detection.EventIDs...)
		if len(detection.EventIDs) == 0 {
			detection.EventIDs = []string{detection.EventID}
		}
		m.securityDetections[detection.ID] = detection
		inserted++
	}
	return inserted, nil
}

func (m *Mem) SecurityDetectionReplayCompleted(_ context.Context, packVersion int) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.securityReplays[packVersion], nil
}

func (m *Mem) MarkSecurityDetectionReplay(_ context.Context, packVersion, _, _ int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.securityReplays[packVersion] = true
	return nil
}

func (m *Mem) SecurityNativeDetections(context.Context) ([]model.SecurityNativeDetection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityNativeDetection, 0, len(m.securityDetections))
	for _, detection := range m.securityDetections {
		out = append(out, cloneSecurityDetection(detection))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	return out, nil
}

func (m *Mem) SecurityNativeDetectionsSince(_ context.Context, since time.Time) ([]model.SecurityNativeDetection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.SecurityNativeDetection
	for _, detection := range m.securityDetections {
		if !detection.OccurredAt.Before(since) {
			out = append(out, cloneSecurityDetection(detection))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	return out, nil
}

func (m *Mem) SecurityNativeDetectionsByIDs(_ context.Context, detectionIDs []string) ([]model.SecurityNativeDetection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityNativeDetection, 0, len(detectionIDs))
	for _, id := range detectionIDs {
		if detection, ok := m.securityDetections[id]; ok {
			out = append(out, cloneSecurityDetection(detection))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.Before(out[j].OccurredAt) })
	return out, nil
}

func (m *Mem) SecurityNativeDetection(_ context.Context, tenantID, id string) (model.SecurityNativeDetection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	detection, ok := m.securityDetections[id]
	if !ok || detection.TenantID != tenantID {
		return model.SecurityNativeDetection{}, ErrNotFound
	}
	return cloneSecurityDetection(detection), nil
}

func (m *Mem) SecurityNativeDetectionsForEvent(_ context.Context, tenantID, eventID string) ([]model.SecurityNativeDetection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.SecurityNativeDetection
	for _, detection := range m.securityDetections {
		if detection.TenantID == tenantID && containsString(detection.EventIDs, eventID, detection.EventID) {
			out = append(out, cloneSecurityDetection(detection))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	return out, nil
}

func cloneSecurityDetection(detection model.SecurityNativeDetection) model.SecurityNativeDetection {
	detection.Entities = append([]model.SecurityEntity(nil), detection.Entities...)
	detection.EventIDs = append([]string(nil), detection.EventIDs...)
	return detection
}

func containsString(values []string, wanted, fallback string) bool {
	if len(values) == 0 {
		return fallback == wanted
	}
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func mergeStringValues(existing, incoming []string, fallback string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(incoming)+1)
	for _, values := range [][]string{existing, incoming, {fallback}} {
		for _, value := range values {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func (m *Mem) SecurityStorylines(context.Context) ([]model.SecurityStoryline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityStoryline, 0, len(m.securityStorylines))
	for _, storyline := range m.securityStorylines {
		out = append(out, cloneSecurityStoryline(storyline))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RiskScore != out[j].RiskScore {
			return out[i].RiskScore > out[j].RiskScore
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out, nil
}

func (m *Mem) SecurityStoryline(_ context.Context, id string) (model.SecurityStoryline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	storyline, ok := m.securityStorylines[id]
	if !ok {
		return model.SecurityStoryline{}, ErrNotFound
	}
	return cloneSecurityStoryline(storyline), nil
}

func (m *Mem) UpsertSecurityStorylines(_ context.Context, storylines []model.SecurityStoryline) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, storyline := range storylines {
		if existing, ok := m.securityStorylines[storyline.ID]; ok {
			storyline.Status, storyline.Owner = existing.Status, existing.Owner
		}
		m.securityStorylines[storyline.ID] = cloneSecurityStoryline(storyline)
	}
	return nil
}

func (m *Mem) UpdateSecurityStorylineState(_ context.Context, id, status, owner, _ string) (model.SecurityStoryline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	storyline, ok := m.securityStorylines[id]
	if !ok {
		return model.SecurityStoryline{}, ErrNotFound
	}
	storyline.Status, storyline.Owner, storyline.UpdatedAt = status, owner, time.Now().UTC()
	m.securityStorylines[id] = storyline
	return cloneSecurityStoryline(storyline), nil
}

func cloneSecurityStoryline(storyline model.SecurityStoryline) model.SecurityStoryline {
	storyline.TenantIDs = append([]string(nil), storyline.TenantIDs...)
	storyline.TenantNames = append([]string(nil), storyline.TenantNames...)
	storyline.Entities = append([]model.SecurityStorylineEntity(nil), storyline.Entities...)
	storyline.Stages = append([]string(nil), storyline.Stages...)
	storyline.Workloads = append([]string(nil), storyline.Workloads...)
	storyline.DetectionIDs = append([]string(nil), storyline.DetectionIDs...)
	storyline.EventIDs = append([]string(nil), storyline.EventIDs...)
	storyline.Reasons = append([]string(nil), storyline.Reasons...)
	storyline.WeakEvidence = append([]string(nil), storyline.WeakEvidence...)
	storyline.RecommendedActions = append([]string(nil), storyline.RecommendedActions...)
	return storyline
}

func cloneSecurityRule(rule model.SecurityDetectionRule) model.SecurityDetectionRule {
	rule.Definition.Workloads = append([]string(nil), rule.Definition.Workloads...)
	rule.Definition.Operations = append([]string(nil), rule.Definition.Operations...)
	rule.Definition.Actors = append([]string(nil), rule.Definition.Actors...)
	rule.Definition.ClientIPs = append([]string(nil), rule.Definition.ClientIPs...)
	rule.Definition.Results = append([]string(nil), rule.Definition.Results...)
	rule.Definition.ObjectContains = append([]string(nil), rule.Definition.ObjectContains...)
	rule.Definition.RawContains = append([]string(nil), rule.Definition.RawContains...)
	rule.Definition.Exclusions = append([]model.SecurityRuleExclusion(nil), rule.Definition.Exclusions...)
	return rule
}

func (m *Mem) SecurityDetectionRules(context.Context) ([]model.SecurityDetectionRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.SecurityDetectionRule, 0, len(m.securityRules))
	for _, rule := range m.securityRules {
		out = append(out, cloneSecurityRule(rule))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (m *Mem) SecurityDetectionRule(_ context.Context, id string) (model.SecurityDetectionRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rule, ok := m.securityRules[id]
	if !ok {
		return model.SecurityDetectionRule{}, ErrNotFound
	}
	return cloneSecurityRule(rule), nil
}

func (m *Mem) CreateSecurityDetectionRule(_ context.Context, rule model.SecurityDetectionRule) (model.SecurityDetectionRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.securityRules[rule.ID]; exists {
		return model.SecurityDetectionRule{}, ErrConflict
	}
	for _, existing := range m.securityRules {
		if existing.RuleID == rule.RuleID && existing.Scope == rule.Scope && existing.TenantID == rule.TenantID {
			return model.SecurityDetectionRule{}, ErrConflict
		}
	}
	now := time.Now().UTC()
	rule.Revision, rule.CreatedAt, rule.UpdatedAt = 1, now, now
	rule = cloneSecurityRule(rule)
	m.securityRules[rule.ID] = rule
	m.securityRevisions[rule.ID] = []model.SecurityDetectionRuleRevision{{
		RuleID: rule.ID, Revision: 1, Snapshot: cloneSecurityRule(rule), Actor: rule.UpdatedBy, CreatedAt: now,
	}}
	return cloneSecurityRule(rule), nil
}

func (m *Mem) UpdateSecurityDetectionRule(_ context.Context, rule model.SecurityDetectionRule, expectedRevision int) (model.SecurityDetectionRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.securityRules[rule.ID]
	if !ok {
		return model.SecurityDetectionRule{}, ErrNotFound
	}
	if current.Revision != expectedRevision {
		return model.SecurityDetectionRule{}, ErrConflict
	}
	for id, existing := range m.securityRules {
		if id != rule.ID && existing.RuleID == rule.RuleID && existing.Scope == rule.Scope && existing.TenantID == rule.TenantID {
			return model.SecurityDetectionRule{}, ErrConflict
		}
	}
	rule.Revision = current.Revision + 1
	rule.CreatedAt = current.CreatedAt
	rule.UpdatedAt = time.Now().UTC()
	rule = cloneSecurityRule(rule)
	m.securityRules[rule.ID] = rule
	m.securityRevisions[rule.ID] = append(m.securityRevisions[rule.ID], model.SecurityDetectionRuleRevision{
		RuleID: rule.ID, Revision: rule.Revision, Snapshot: cloneSecurityRule(rule), Actor: rule.UpdatedBy, CreatedAt: rule.UpdatedAt,
	})
	return cloneSecurityRule(rule), nil
}

func (m *Mem) SecurityDetectionRuleRevisions(_ context.Context, id string) ([]model.SecurityDetectionRuleRevision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.securityRules[id]; !ok {
		return nil, ErrNotFound
	}
	revisions := m.securityRevisions[id]
	out := make([]model.SecurityDetectionRuleRevision, len(revisions))
	for i := range revisions {
		out[len(revisions)-1-i] = revisions[i]
		out[len(revisions)-1-i].Snapshot = cloneSecurityRule(out[len(revisions)-1-i].Snapshot)
	}
	return out, nil
}

func (m *Mem) PruneSecurityAuditEvents(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	removedEventIDs := map[string]struct{}{}
	for key, event := range m.securityEvents {
		if event.OccurredAt.Before(before) {
			removedEventIDs[event.ID] = struct{}{}
			delete(m.securityEvidence, event.ID)
			delete(m.securityEvents, key)
			deleted++
		}
	}
	for id, detection := range m.securityDetections {
		if _, removed := removedEventIDs[detection.EventID]; removed {
			delete(m.securityDetections, id)
		}
	}
	return deleted, nil
}

// ---- Offline investigations ----

func cloneOfflineInvestigation(investigation model.OfflineInvestigation) model.OfflineInvestigation {
	investigation.Coverage = append([]model.OfflineEvidenceCoverage(nil), investigation.Coverage...)
	for i := range investigation.Coverage {
		investigation.Coverage[i].Fields = append([]string(nil), investigation.Coverage[i].Fields...)
		investigation.Coverage[i].MissingFields = append([]string(nil), investigation.Coverage[i].MissingFields...)
	}
	return investigation
}

func cloneOfflineFile(file model.OfflineInvestigationFile) model.OfflineInvestigationFile {
	file.Content = append([]byte(nil), file.Content...)
	return file
}

func cloneOfflineAnalysis(analysis model.OfflineInvestigationAnalysis) model.OfflineInvestigationAnalysis {
	analysis.Events = append([]model.SecurityAuditEvent(nil), analysis.Events...)
	for i := range analysis.Events {
		analysis.Events[i].Raw = append([]byte(nil), analysis.Events[i].Raw...)
		analysis.Events[i].Sources = append([]string(nil), analysis.Events[i].Sources...)
	}
	analysis.Detections = append([]model.SecurityNativeDetection(nil), analysis.Detections...)
	for i := range analysis.Detections {
		analysis.Detections[i] = cloneSecurityDetection(analysis.Detections[i])
	}
	analysis.Storylines = append([]model.SecurityStoryline(nil), analysis.Storylines...)
	for i := range analysis.Storylines {
		analysis.Storylines[i] = cloneSecurityStoryline(analysis.Storylines[i])
	}
	return analysis
}

func (m *Mem) OfflineInvestigations(context.Context) ([]model.OfflineInvestigation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.OfflineInvestigation, 0, len(m.offlineInvestigations))
	for _, investigation := range m.offlineInvestigations {
		out = append(out, cloneOfflineInvestigation(investigation))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (m *Mem) OfflineInvestigation(_ context.Context, id string) (model.OfflineInvestigation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	investigation, ok := m.offlineInvestigations[id]
	if !ok {
		return model.OfflineInvestigation{}, ErrNotFound
	}
	return cloneOfflineInvestigation(investigation), nil
}

func (m *Mem) CreateOfflineInvestigation(_ context.Context, input NewOfflineInvestigation) (model.OfflineInvestigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	now := time.Now().UTC()
	investigation := model.OfflineInvestigation{
		ID: fmt.Sprintf("offinv_%d", m.seq), Name: input.Name, TenantLabel: input.TenantLabel,
		Status: "draft", CreatedBy: input.CreatedBy, CreatedAt: now, UpdatedAt: now,
		Coverage: []model.OfflineEvidenceCoverage{},
	}
	m.offlineInvestigations[investigation.ID] = investigation
	return cloneOfflineInvestigation(investigation), nil
}

func (m *Mem) DeleteOfflineInvestigation(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.offlineInvestigations[id]; !ok {
		return ErrNotFound
	}
	delete(m.offlineInvestigations, id)
	delete(m.offlineFiles, id)
	delete(m.offlineAnalysis, id)
	return nil
}

func (m *Mem) OfflineInvestigationFiles(_ context.Context, id string) ([]model.OfflineInvestigationFile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.offlineInvestigations[id]; !ok {
		return nil, ErrNotFound
	}
	files := m.offlineFiles[id]
	out := make([]model.OfflineInvestigationFile, len(files))
	for i := range files {
		out[i] = cloneOfflineFile(files[i])
		out[i].Content = nil
	}
	return out, nil
}

func (m *Mem) OfflineInvestigationEvidenceFiles(_ context.Context, id string) ([]model.OfflineInvestigationFile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.offlineInvestigations[id]; !ok {
		return nil, ErrNotFound
	}
	files := m.offlineFiles[id]
	out := make([]model.OfflineInvestigationFile, len(files))
	for i := range files {
		out[i] = cloneOfflineFile(files[i])
	}
	return out, nil
}

func (m *Mem) AddOfflineInvestigationFile(_ context.Context, id string, file model.OfflineInvestigationFile) (model.OfflineInvestigationFile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	investigation, ok := m.offlineInvestigations[id]
	if !ok {
		return model.OfflineInvestigationFile{}, ErrNotFound
	}
	if investigation.Status == "queued" || investigation.Status == "analyzing" {
		return model.OfflineInvestigationFile{}, ErrConflict
	}
	var totalBytes int64
	var totalRecords int
	for _, existing := range m.offlineFiles[id] {
		if existing.SHA256 == file.SHA256 {
			return model.OfflineInvestigationFile{}, ErrConflict
		}
		totalBytes += existing.SizeBytes
		totalRecords += existing.RecordCount
	}
	if len(m.offlineFiles[id])+1 > OfflineInvestigationMaxFiles || totalBytes+file.SizeBytes > OfflineInvestigationMaxBytes || totalRecords+file.RecordCount > OfflineInvestigationMaxRecords {
		return model.OfflineInvestigationFile{}, ErrLimitExceeded
	}
	m.seq++
	file.ID, file.InvestigationID = fmt.Sprintf("offile_%d", m.seq), id
	if file.Status == "" {
		file.Status = "ready"
	}
	file.UploadedAt = time.Now().UTC()
	m.offlineFiles[id] = append(m.offlineFiles[id], cloneOfflineFile(file))
	investigation.Status, investigation.Progress, investigation.Detail = "ready", 0, ""
	investigation.UpdatedAt = file.UploadedAt
	investigation.AnalyzedAt = time.Time{}
	investigation.EventCount, investigation.DetectionCount = 0, 0
	investigation.HighPriorityCount, investigation.StorylineCount = 0, 0
	investigation.Coverage = []model.OfflineEvidenceCoverage{}
	m.offlineInvestigations[id] = investigation
	delete(m.offlineAnalysis, id)
	return cloneOfflineFile(file), nil
}

func (m *Mem) UpdateOfflineInvestigationStatus(_ context.Context, id, status string, progress int, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	investigation, ok := m.offlineInvestigations[id]
	if !ok {
		return ErrNotFound
	}
	investigation.Status, investigation.Progress, investigation.Detail = status, progress, detail
	investigation.UpdatedAt = time.Now().UTC()
	m.offlineInvestigations[id] = investigation
	return nil
}

func (m *Mem) ReplaceOfflineInvestigationAnalysis(_ context.Context, investigation model.OfflineInvestigation, analysis model.OfflineInvestigationAnalysis) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.offlineInvestigations[investigation.ID]; !ok {
		return ErrNotFound
	}
	m.offlineInvestigations[investigation.ID] = cloneOfflineInvestigation(investigation)
	m.offlineAnalysis[investigation.ID] = cloneOfflineAnalysis(analysis)
	return nil
}

func (m *Mem) OfflineInvestigationAnalysis(_ context.Context, id string) (model.OfflineInvestigationAnalysis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.offlineInvestigations[id]; !ok {
		return model.OfflineInvestigationAnalysis{}, ErrNotFound
	}
	return cloneOfflineAnalysis(m.offlineAnalysis[id]), nil
}

// ---- Audit ----

func (m *Mem) Audit(context.Context) ([]model.AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.AuditEntry(nil), m.audit...), nil
}

func (m *Mem) AppendAudit(_ context.Context, e model.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.ID == "" {
		m.seq++
		e.ID = fmt.Sprintf("aud_new_%d", m.seq)
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().Format("15:04:05")
	}
	m.audit = append([]model.AuditEntry{e}, m.audit...)
	return nil
}

// ---- Admin: technicians are the real accounts ----

func technicianOf(a Account) model.Technician {
	// Every RTM user has access to every managed tenant (no grant model).
	return model.Technician{
		ID: a.ID, Name: a.Name, Email: a.Email, Role: a.Role,
		Tenants: "All", Status: a.Status, LastActive: "—", MustChangePassword: a.MustChange,
	}
}

func (m *Mem) Technicians(context.Context) ([]model.Technician, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Technician, 0, len(m.accounts))
	for _, a := range m.accounts {
		out = append(out, technicianOf(a))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Mem) CreateAccount(_ context.Context, na NewAccount) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.accounts[na.Email]; exists {
		return Account{}, ErrConflict
	}
	m.seq++
	a := Account{
		ID: fmt.Sprintf("tech_new_%d", m.seq), Name: na.Name, Email: na.Email,
		Role: na.Role, IsAdmin: na.IsAdmin, Status: "Active",
		PasswordHash: na.PasswordHash, MustChange: na.MustChange,
	}
	m.accounts[na.Email] = a
	return a, nil
}

func (m *Mem) UpdateAccount(_ context.Context, id string, upd AccountUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for email, a := range m.accounts {
		if a.ID == id {
			if upd.Role != nil {
				a.Role = *upd.Role
			}
			if upd.Status != nil {
				a.Status = *upd.Status
			}
			if upd.IsAdmin != nil {
				a.IsAdmin = *upd.IsAdmin
			}
			m.accounts[email] = a
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) DeleteAccount(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for email, a := range m.accounts {
		if a.ID == id {
			delete(m.accounts, email)
			delete(m.refresh, id)
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) Roles(context.Context) ([]model.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	roles := cloneRoles(m.roles)
	for i := range roles {
		roles[i].Assigned = 0
		for _, account := range m.accounts {
			if account.Role == roles[i].Name {
				roles[i].Assigned++
			}
		}
	}
	return roles, nil
}

func (m *Mem) Role(_ context.Context, name string) (model.Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, role := range m.roles {
		if role.Name == name {
			return cloneRole(role), nil
		}
	}
	return model.Role{}, ErrNotFound
}

func (m *Mem) UpdateRole(_ context.Context, name, description string, permissionKeys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.roles {
		if m.roles[i].Name == name {
			m.roles[i].Description = description
			m.roles[i].PermissionKeys = append([]string(nil), permissionKeys...)
			return nil
		}
	}
	return ErrNotFound
}

func cloneRole(role model.Role) model.Role {
	role.PermissionKeys = append([]string(nil), role.PermissionKeys...)
	role.LockedPermissionKeys = append([]string(nil), role.LockedPermissionKeys...)
	return role
}

func cloneRoles(roles []model.Role) []model.Role {
	out := make([]model.Role, len(roles))
	for i, role := range roles {
		out[i] = cloneRole(role)
	}
	return out
}

func (m *Mem) AppSettings(context.Context) ([]model.AppSetting, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.AppSetting(nil), m.settings...), nil
}

func (m *Mem) UpdateAppSetting(_ context.Context, key string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.settings {
		if m.settings[i].Key == key {
			m.settings[i].Enabled = enabled
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) UpdateAppSettingValue(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.settings {
		if m.settings[i].Key == key {
			m.settings[i].Value = value
			return nil
		}
	}
	return ErrNotFound
}

// ---- Approvals (engine not built yet — always empty, never fabricated) ----

func (m *Mem) Approvals(context.Context) ([]model.Approval, error) {
	return []model.Approval{}, nil
}

// ---- Auth ----

func (m *Mem) AccountByEmail(_ context.Context, email string) (Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a, ok := m.accounts[email]; ok {
		return a, nil
	}
	return Account{}, ErrNotFound
}

func (m *Mem) AccountByID(_ context.Context, id string) (Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.accounts {
		if a.ID == id {
			return a, nil
		}
	}
	return Account{}, ErrNotFound
}

func (m *Mem) SetPassword(_ context.Context, accountID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for email, a := range m.accounts {
		if a.ID == accountID {
			a.PasswordHash = passwordHash
			a.MustChange = false
			a.CredentialVersion++
			m.accounts[email] = a
			delete(m.refresh, accountID)
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) ResetPassword(_ context.Context, accountID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for email, a := range m.accounts {
		if a.ID == accountID {
			a.PasswordHash = passwordHash
			a.MustChange = true
			a.CredentialVersion++
			m.accounts[email] = a
			delete(m.refresh, accountID)
			return nil
		}
	}
	return ErrNotFound
}

func (m *Mem) SetRefreshToken(_ context.Context, accountID, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[accountID] = jti
	return nil
}

func (m *Mem) CurrentRefreshToken(_ context.Context, accountID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.refresh[accountID], nil
}

func (m *Mem) ClearRefreshToken(_ context.Context, accountID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refresh, accountID)
	return nil
}
