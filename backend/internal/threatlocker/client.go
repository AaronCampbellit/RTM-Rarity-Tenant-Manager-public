package threatlocker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rarity/rtm/internal/model"
)

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(anyString(values[key])); value != "" {
			return value
		}
	}
	return ""
}

// client is the live ThreatLocker portal API client. Auth is an API-User
// token sent on every request; calls are scoped to the tenant's organization
// via the managedOrganizationId header. Endpoint names follow ThreatLocker's
// public portalAPI (Help → API Documentation swagger); the request/response
// field dialect is pinned by the fake-server tests and verified against the
// swagger during a live pilot.
type client struct {
	cfg  Config
	http *http.Client
}

const maxPortalResponseBytes = 10 << 20

func newClient(cfg Config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: 90 * time.Second}}
}

func (c *client) Mode() string { return "live" }

// auth retains the tenantID parameter for the established provider interface,
// but every call now resolves the single MSP parent connection.
func (c *client) auth(ctx context.Context, _ string) (Auth, error) {
	return c.parentAuth(ctx)
}

func (c *client) baseURL(a Auth) string {
	if c.cfg.BaseURL != "" {
		return strings.TrimRight(c.cfg.BaseURL, "/")
	}
	return fmt.Sprintf("https://portalapi.%s.threatlocker.com/portalapi", a.Instance)
}

// do performs one portal API call. body == nil → GET, else POST with a JSON
// body. The response is decoded into out when out != nil. Errors carry the
// portal's message but never the token.
func (c *client) do(ctx context.Context, a Auth, path string, body, out any) error {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	return c.doMethod(ctx, a, method, path, body, out)
}

func (c *client) doMethod(ctx context.Context, a Auth, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL(a)+"/"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", a.Token)
	req.Header.Set("managedOrganizationId", a.OrgID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("threatlocker request %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxPortalResponseBytes+1))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Message: apiMessage(raw), Path: path}
	}
	if len(raw) > maxPortalResponseBytes {
		return &APIError{Status: http.StatusBadGateway, Message: "response exceeded 10 MiB", Path: path}
	}
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte(`{}`)
	}
	return json.Unmarshal(raw, out)
}

// apiMessage extracts the portal's error message (a "message" field or the
// raw body, truncated) for the error envelope.
func apiMessage(raw []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Message != "" {
		return e.Message
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// listOf decodes the portal's list responses, which arrive either wrapped
// ({"data":[…]}) or as a bare array. An empty/null data field is an empty
// list, not an error.
func listOf[T any](raw json.RawMessage) ([]T, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var plain []T
		err := json.Unmarshal(trimmed, &plain)
		return plain, err
	}
	var wrapped struct {
		Data []T `json:"data"`
	}
	if err := json.Unmarshal(trimmed, &wrapped); err != nil {
		return nil, err
	}
	return wrapped.Data, nil
}

// ---- request bodies (ThreatLocker portalapi DTOs) ----

// computerQuery is the ComputerGetByAllParameters body.
type computerQuery struct {
	PageNumber         int    `json:"pageNumber"`
	PageSize           int    `json:"pageSize"`
	OrderBy            string `json:"orderBy,omitempty"`
	IsAscending        bool   `json:"isAscending"`
	SearchText         string `json:"searchText"`
	ChildOrganizations bool   `json:"childOrganizations"`
	ShowLastCheckIn    bool   `json:"showLastCheckIn"`
}

// approvalQuery is the ApprovalRequestGetByParameters body. statusId 1 =
// pending; requestTypeId 0 = all types.
type approvalQuery struct {
	StatusID               int    `json:"statusId"`
	RequestTypeID          int    `json:"requestTypeId"`
	UserApprovalTierLevel  int    `json:"userApprovalTierLevel"`
	ShowCurrentTierOnly    bool   `json:"showCurrentTierOnly"`
	ShowChildOrganizations bool   `json:"showChildOrganizations"`
	OrderBy                string `json:"orderBy,omitempty"`
	IsAscending            bool   `json:"isAscending"`
	PageNumber             int    `json:"pageNumber"`
	PageSize               int    `json:"pageSize"`
}

// applicationQuery is the Application/ApplicationGetByParameters body. The
// portal validates searchText as non-empty, so callers normalize blank search
// to a single space for an unfiltered library-style query.
type applicationQuery struct {
	SearchText                string   `json:"searchText"`
	SearchBy                  string   `json:"searchBy"`
	OrderBy                   string   `json:"orderBy"`
	IsAscending               bool     `json:"isAscending"`
	IncludeMaster             bool     `json:"includeMaster"`
	PermittedApplications     bool     `json:"permittedApplications"`
	IsBuiltInApplication      bool     `json:"isBuiltInApplication"`
	IsHidden                  bool     `json:"isHidden"`
	IsTemporary               bool     `json:"isTemporary"`
	Category                  int      `json:"category"`
	OSType                    int      `json:"osType"`
	IncludeChildOrganizations bool     `json:"includeChildOrganizations"`
	Countries                 []string `json:"countries"`
	Categories                []string `json:"categories"`
	PageNumber                int      `json:"pageNumber"`
	PageSize                  int      `json:"pageSize"`
}

// ---- wire shapes ----

// tlComputer is one row of ComputerGetByAllParameters. Field names verified
// against the live portalapi response.
type tlComputer struct {
	ComputerID            string `json:"computerId"`
	ComputerName          string `json:"computerName"`
	Group                 string `json:"group"`
	ComputerGroupID       string `json:"computerGroupId"`
	OSType                int    `json:"osType"` // 1 Windows, 2 macOS, 3 Linux
	ServiceVersion        string `json:"serviceVersion"`
	ThreatLockerVersion   string `json:"threatLockerVersion"`
	Mode                  string `json:"mode"`   // "Secure" | "MonitorOnly" | "Learning" | "Installation" | …
	Action                string `json:"action"` // same vocabulary as Mode
	MaintenanceTypeID     int    `json:"maintenanceTypeId"`
	MaintenanceEndDate    string `json:"maintenanceEndDate"`
	IsIsolated            bool   `json:"isIsolated"`
	IsIsolationMode       bool   `json:"isIsolationMode"`
	IsLockDownMode        bool   `json:"isLockDownMode"`
	IsLockedOut           bool   `json:"isLockedOut"`
	IsTamperProtectionOff bool   `json:"isTamperProtectionDisabled"`
	LastCheckIn           string `json:"lastCheckin"`
	OrganizationID        string `json:"organizationId"`
}

// onlineWindow: a device that checked in within this window is treated as
// online (the portal API has no explicit online flag on this record).
const onlineWindow = 15 * time.Minute

func (t tlComputer) device() model.Device {
	version := t.ServiceVersion
	if version == "" {
		version = t.ThreatLockerVersion
	}
	online := false
	if last, err := time.Parse(time.RFC3339, t.LastCheckIn); err == nil {
		online = time.Since(last) < onlineWindow
	}
	return model.Device{
		ID: t.ComputerID, OrganizationID: t.OrganizationID, Hostname: t.ComputerName, Group: t.Group,
		OS: osName(t.OSType), AgentVersion: version,
		Mode: t.mode(), ModeExpires: t.MaintenanceEndDate,
		TamperProtection: !t.IsTamperProtectionOff, LastCheckIn: t.LastCheckIn, Online: online,
	}
}

// mode derives the RTM protection mode from the device's containment booleans
// (which take precedence) and its maintenance-mode string.
func (t tlComputer) mode() string {
	switch {
	case t.IsIsolated || t.IsIsolationMode:
		return ModeIsolated
	case t.IsLockDownMode || t.IsLockedOut:
		return ModeLockdown
	}
	return normalizeMode(firstNonEmpty(t.Mode, t.Action))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func osName(t int) string {
	switch t {
	case 2:
		return "mac"
	case 3:
		return "linux"
	default:
		return "windows"
	}
}

// normalizeMode maps the portal's maintenance-mode labels onto the model's
// mode vocabulary.
func normalizeMode(s string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "_", "")) {
	case "monitoronly", "monitor":
		return ModeMonitorOnly
	case "learning", "learningmodehashonly":
		return ModeLearning
	case "installation", "installmode", "installationmode":
		return ModeInstallation
	default:
		return ModeSecured
	}
}

// tlApproval is one row of ApprovalRequestGetByParameters. Field names
// verified against the ApprovalRequestDto schema.
type tlApproval struct {
	RequestID      string `json:"approvalRequestId"`
	OrganizationID string `json:"organizationId"`
	ComputerID     string `json:"computerId"`
	Hostname       string `json:"hostname"`
	Username       string `json:"username"`
	Requestor      string `json:"requestor"`
	Path           string `json:"path"`
	Hash           string `json:"hash"`
	RequestTypeID  int    `json:"requestTypeId"`
	StatusID       int    `json:"statusId"`
	DateTime       string `json:"dateTime"`
}

// Approval-request status ids (1 = pending, 2 = approved, 3 = denied).
const (
	statusPending  = 1
	statusApproved = 2
	statusDenied   = 3
)

func statusName(id int) string {
	switch id {
	case statusApproved:
		return RequestApproved
	case statusDenied:
		return RequestDenied
	default:
		return RequestPending
	}
}

func statusID(name string) int {
	switch name {
	case RequestApproved:
		return statusApproved
	case RequestDenied:
		return statusDenied
	default:
		return statusPending
	}
}

// requestTypeName maps ThreatLocker's requestTypeId to the RTM vocabulary.
// 1 = Application (execution), 2 = Storage, 3 = Elevation.
func requestTypeName(id int) string {
	switch id {
	case 2:
		return "storage"
	case 3:
		return "elevation"
	default:
		return "execution"
	}
}

func (t tlApproval) request() model.ApprovalRequest {
	requester := firstNonEmpty(t.Requestor, t.Username)
	app := t.Path
	if i := strings.LastIndexAny(app, `\/`); i >= 0 {
		app = app[i+1:]
	}
	if app == "" {
		app = "(unknown application)"
	}
	return model.ApprovalRequest{
		ID: t.RequestID, OrganizationID: t.OrganizationID, DeviceID: t.ComputerID, DeviceName: t.Hostname,
		Requester: requester, Application: app, Path: t.Path, Hash: t.Hash,
		RequestType: requestTypeName(t.RequestTypeID), Status: statusName(t.StatusID), RequestedAt: t.DateTime,
	}
}

// ---- reads ----

func (c *client) Devices(ctx context.Context, tenantID string) ([]model.Device, error) {
	const pageSize = 100
	var all []model.Device
	seenPages := map[string]bool{}
	for page := 1; ; page++ {
		rows, err := c.devicePage(ctx, tenantID, page, pageSize, true)
		if err != nil {
			return nil, err
		}
		sig := devicePageSignature(rows)
		if sig != "" && seenPages[sig] {
			break
		}
		seenPages[sig] = true
		all = append(all, rows...)
		if len(rows) < pageSize {
			break
		}
	}
	return all, nil
}

func (c *client) devicePage(ctx context.Context, tenantID string, page, pageSize int, childOrganizations bool) ([]model.Device, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	q := computerQuery{
		PageNumber: page, PageSize: pageSize, OrderBy: "computername",
		IsAscending: true, ChildOrganizations: childOrganizations, ShowLastCheckIn: true,
	}
	if err := c.do(ctx, a, "Computer/ComputerGetByAllParameters", q, &raw); err != nil {
		return nil, err
	}
	rows, err := listOf[tlComputer](raw)
	if err != nil {
		return nil, err
	}
	out := make([]model.Device, len(rows))
	for i, r := range rows {
		out[i] = r.device()
	}
	return out, nil
}

func devicePageSignature(rows []model.Device) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf("%d:%s:%s", len(rows), rows[0].ID, rows[len(rows)-1].ID)
}

// Device returns one device. The portal's per-device edit endpoint returns a
// different shape, so RTM resolves the device from the list read (one shape,
// always consistent with the table).
func (c *client) Device(ctx context.Context, tenantID, deviceID string) (model.Device, error) {
	devices, err := c.Devices(ctx, tenantID)
	if err != nil {
		return model.Device{}, err
	}
	for _, d := range devices {
		if d.ID == deviceID {
			return d, nil
		}
	}
	return model.Device{}, &APIError{Status: 404, Message: "device not found", Path: "Device"}
}

// DeviceGroups is derived from the device list (name + counts). The portal's
// group endpoints are organization-dropdown shaped and don't carry device
// counts, so aggregating the devices is both simpler and accurate.
func (c *client) DeviceGroups(ctx context.Context, tenantID string) ([]model.DeviceGroup, error) {
	devices, err := c.Devices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	order := []string{}
	counts := map[string]int{}
	for _, d := range devices {
		name := d.Group
		if name == "" {
			name = "Ungrouped"
		}
		if _, seen := counts[name]; !seen {
			order = append(order, name)
		}
		counts[name]++
	}
	out := make([]model.DeviceGroup, 0, len(order))
	for _, name := range order {
		out = append(out, model.DeviceGroup{ID: name, Name: name, DeviceCount: counts[name]})
	}
	return out, nil
}

func (c *client) parentAuth(ctx context.Context) (Auth, error) {
	if c.cfg.GlobalAuth != nil {
		a, err := c.cfg.GlobalAuth(ctx)
		if err != nil {
			return Auth{}, err
		}
		if a.Instance != "" && a.Token != "" && a.OrgID != "" {
			return a, nil
		}
	}
	a := Auth{Instance: c.cfg.Instance, Token: c.cfg.Token, OrgID: c.cfg.ParentOrgID}
	if a.Instance == "" || a.Token == "" || a.OrgID == "" {
		return Auth{}, ErrNotConnected
	}
	return a, nil
}

// effectiveParentOrgID resolves the MSP parent organization ID used to label
// app/policy source. The GUI-configured global config (GlobalAuth) wins over
// the RTM_THREATLOCKER_PARENT_ORG_ID env value, matching auth resolution —
// otherwise parent-org objects get mislabeled "tenant" whenever the parent org
// is configured in the database only.
func (c *client) effectiveParentOrgID(ctx context.Context) string {
	if a, err := c.parentAuth(ctx); err == nil && a.OrgID != "" {
		return a.OrgID
	}
	return c.cfg.ParentOrgID
}

func (c *client) Applications(ctx context.Context, tenantID string, req AppSearchRequest) ([]model.TLApplication, error) {
	switch req.Source {
	case "parent":
		a, err := c.parentAuth(ctx)
		if err != nil {
			return nil, err
		}
		return c.applicationsForAuth(ctx, a, req)
	case "tenant":
		a, err := c.auth(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		return c.applicationsForAuth(ctx, a, req)
	default:
		a, err := c.auth(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		out, err := c.applicationsForAuth(ctx, a, req)
		if err != nil {
			return nil, err
		}
		parent, err := c.parentAuth(ctx)
		if err == nil && parent.OrgID != a.OrgID {
			parentRows, err := c.applicationsForAuth(ctx, parent, req)
			if err != nil {
				return nil, err
			}
			out = append(out, parentRows...)
		}
		return out, nil
	}
}

func (c *client) applicationsForAuth(ctx context.Context, a Auth, req AppSearchRequest) ([]model.TLApplication, error) {
	const pageSize = 500
	search := strings.TrimSpace(req.SearchText)
	if search == "" {
		search = " "
	}
	searchBy := req.SearchBy
	if searchBy == "" {
		searchBy = "app"
	}
	osType := req.OSType
	if osType == 0 {
		osType = 1
	}
	category := 1 // custom apps
	if req.IncludeBuiltIn {
		category = 0
	}
	parentOrgID := c.effectiveParentOrgID(ctx)
	var all []model.TLApplication
	seenPages := map[string]bool{}
	for page := 1; ; page++ {
		var raw json.RawMessage
		q := applicationQuery{
			SearchText: search, SearchBy: searchBy, OrderBy: "name", IsAscending: true,
			IncludeMaster: true, PermittedApplications: !req.IncludeUnused,
			IsBuiltInApplication: req.IncludeBuiltIn, IsHidden: req.IncludeHidden,
			IsTemporary: false, Category: category, OSType: osType,
			IncludeChildOrganizations: req.IncludeChildOrganizations,
			Countries:                 []string{}, Categories: []string{}, PageNumber: page, PageSize: pageSize,
		}
		if err := c.do(ctx, a, "Application/ApplicationGetByParameters", q, &raw); err != nil {
			return nil, err
		}
		rows, err := listOf[map[string]any](raw)
		if err != nil {
			return nil, err
		}
		sig := appPageSignature(rows)
		if sig != "" && seenPages[sig] {
			break
		}
		seenPages[sig] = true
		for _, row := range rows {
			all = append(all, applicationSummary(row, parentOrgID))
		}
		if len(rows) < pageSize {
			break
		}
	}
	return all, nil
}

func appPageSignature(rows []map[string]any) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf("%d:%s:%s", len(rows), appID(rows[0]), appID(rows[len(rows)-1]))
}

func (c *client) Application(ctx context.Context, tenantID, appID string) (model.TLApplicationDetail, error) {
	a, err := c.authForApplication(ctx, tenantID, appID)
	if err != nil {
		return model.TLApplicationDetail{}, err
	}
	return c.applicationForAuth(ctx, a, appID)
}

func (c *client) authForApplication(ctx context.Context, tenantID, appID string) (Auth, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return Auth{}, err
	}
	apps, err := c.applicationsForAuth(ctx, a, AppSearchRequest{
		SearchText: " ", SearchBy: "app", IncludeChildOrganizations: true, IncludeUnused: true,
	})
	if err != nil {
		return Auth{}, err
	}
	for _, app := range apps {
		if app.ID == appID {
			if orgID := strings.TrimSpace(app.OrganizationID); orgID != "" {
				a.OrgID = orgID
			}
			return a, nil
		}
	}
	return Auth{}, &APIError{Status: http.StatusNotFound, Message: "application not found", Path: "ApplicationGetByParameters"}
}

func (c *client) applicationForAuth(ctx context.Context, a Auth, id string) (model.TLApplicationDetail, error) {
	var raw map[string]any
	if err := c.do(ctx, a, "Application/ApplicationGetById?applicationId="+url.QueryEscape(id), nil, &raw); err != nil {
		return model.TLApplicationDetail{}, err
	}
	if nested, ok := raw["application"].(map[string]any); ok {
		raw = nested
	} else if nested, ok := raw["data"].(map[string]any); ok {
		raw = nested
	}
	return applicationDetail(raw, c.effectiveParentOrgID(ctx)), nil
}

// applicationFileQuery is the ApplicationFile/ApplicationFileGetByParameters
// body. osType is required and validated by the portal (a missing/blank value
// returns 417 "Invalid Operating System Type"), so it must be the owning
// application's OS type.
type applicationFileQuery struct {
	ApplicationID string `json:"applicationId"`
	SearchText    string `json:"searchText"`
	OrderBy       string `json:"orderBy"`
	IsAscending   bool   `json:"isAscending"`
	OSType        int    `json:"osType"`
	PageNumber    int    `json:"pageNumber"`
	PageSize      int    `json:"pageSize"`
}

func (c *client) ApplicationFiles(ctx context.Context, tenantID, appID string, osType int) ([]model.TLApplicationFile, error) {
	a, err := c.authForApplication(ctx, tenantID, appID)
	if err != nil {
		return nil, err
	}
	return c.applicationFilesForAuth(ctx, a, appID, osType)
}

func (c *client) ApplicationFilesForAuth(ctx context.Context, a Auth, appID string, osType int) ([]model.TLApplicationFile, error) {
	return c.applicationFilesForAuth(ctx, a, appID, osType)
}

// applicationFilesForAuth lists an application's file rules via
// ApplicationFile/ApplicationFileGetByParameters (POST). The legacy
// ApplicationFileGetByApplicationId GET endpoint 500s on the live portal.
func (c *client) applicationFilesForAuth(ctx context.Context, a Auth, appID string, osType int) ([]model.TLApplicationFile, error) {
	if osType == 0 {
		osType = 1 // default to Windows; the portal rejects a missing osType
	}
	const pageSize = 500
	var out []model.TLApplicationFile
	seenPages := map[string]bool{}
	for page := 1; ; page++ {
		var raw json.RawMessage
		q := applicationFileQuery{
			ApplicationID: appID, SearchText: " ", OrderBy: "name", IsAscending: true,
			OSType: osType, PageNumber: page, PageSize: pageSize,
		}
		if err := c.do(ctx, a, "ApplicationFile/ApplicationFileGetByParameters", q, &raw); err != nil {
			return nil, err
		}
		rows, err := listOf[map[string]any](raw)
		if err != nil {
			return nil, err
		}
		sig := appFilePageSignature(rows)
		if sig != "" && seenPages[sig] {
			break
		}
		seenPages[sig] = true
		for _, row := range rows {
			out = append(out, applicationFile(row))
		}
		if len(rows) < pageSize {
			break
		}
	}
	return out, nil
}

func appFilePageSignature(rows []map[string]any) string {
	if len(rows) == 0 {
		return ""
	}
	first, last := anyString(rows[0]["applicationFileId"]), anyString(rows[len(rows)-1]["applicationFileId"])
	return fmt.Sprintf("%d:%s:%s", len(rows), first, last)
}

func appID(raw map[string]any) string {
	return firstNonEmpty(anyString(raw["applicationId"]), anyString(raw["id"]))
}

func applicationSummary(raw map[string]any, parentOrgID string) model.TLApplication {
	orgID := anyString(raw["organizationId"])
	source := "tenant"
	if parentOrgID != "" && orgID == parentOrgID {
		source = "parent"
	}
	status := "Enabled"
	if v := raw["status"]; v != nil {
		switch x := v.(type) {
		case string:
			status = x
		case float64:
			if x == 0 {
				status = "Disabled"
			}
		case json.Number:
			if x.String() == "0" {
				status = "Disabled"
			}
		}
	}
	return model.TLApplication{
		ID:             appID(raw),
		Name:           firstNonEmpty(anyString(raw["name"]), anyString(raw["applicationName"])),
		Description:    anyString(raw["description"]),
		OrganizationID: orgID,
		Organization:   firstNonEmpty(anyString(raw["organizationName"]), anyString(raw["organization"])),
		Source:         source,
		OSType:         anyInt(raw["osType"]),
		OS:             osName(anyInt(raw["osType"])),
		Status:         status,
		BuiltIn:        anyBool(raw["isBuiltIn"]) || anyBool(raw["isBuiltInApplication"]),
		Hidden:         anyBool(raw["isHidden"]),
		// ApplicationGetByParameters reports policies per scope, not a single
		// count. Sum computer/group/organization policy counts (older field
		// names kept as fallbacks for the fake-server tests / other endpoints).
		PolicyCount: firstNonZero(
			anyInt(raw["policyCount"]),
			anyInt(raw["computerPolicyCounts"])+anyInt(raw["groupPolicyCounts"])+anyInt(raw["organizationPolicyCounts"]),
			rawCount(anyRaw(raw["policies"])),
		),
		FileCount: firstNonZero(anyInt(raw["applicationFileCount"]), anyInt(raw["fileCount"]), rawCount(anyRaw(raw["applicationFiles"]))),
		UpdatedAt: firstNonEmpty(anyString(raw["modifiedDate"]), anyString(raw["updatedAt"]), anyString(raw["lastModifiedDate"])),
	}
}

func applicationDetail(raw map[string]any, parentOrgID string) model.TLApplicationDetail {
	d := model.TLApplicationDetail{TLApplication: applicationSummary(raw, parentOrgID), Raw: raw}
	if rows, ok := raw["applicationFiles"].([]any); ok {
		for _, row := range rows {
			if m, ok := row.(map[string]any); ok {
				d.Files = append(d.Files, applicationFile(m))
			}
		}
	}
	return d
}

func applicationFile(raw map[string]any) model.TLApplicationFile {
	fileID := int64(anyInt(raw["applicationFileId"]))
	return model.TLApplicationFile{
		ID:                firstNonEmpty(anyString(raw["id"]), anyString(raw["applicationFileId"])),
		ApplicationFileID: fileID,
		ApplicationID:     anyString(raw["applicationId"]),
		Name:              firstNonEmpty(anyString(raw["name"]), anyString(raw["applicationName"])),
		FullPath:          anyString(raw["fullPath"]),
		ProcessPath:       anyString(raw["processPath"]),
		Cert:              anyString(raw["cert"]),
		Hash:              anyString(raw["hash"]),
		Notes:             anyString(raw["notes"]),
		InstalledBy:       anyString(raw["installedBy"]),
		OSType:            anyInt(raw["osType"]),
		KeyFile:           anyBool(raw["keyFile"]),
		IsHashOnly:        anyBool(raw["isHashOnly"]),
	}
}

func anyRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *client) ApprovalRequests(ctx context.Context, tenantID, status string) ([]model.ApprovalRequest, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	q := approvalQuery{StatusID: statusID(status), OrderBy: "dateTime", PageNumber: 1, PageSize: 500}
	if err := c.do(ctx, a, "ApprovalRequest/ApprovalRequestGetByParameters", q, &raw); err != nil {
		return nil, err
	}
	rows, err := listOf[tlApproval](raw)
	if err != nil {
		return nil, err
	}
	out := make([]model.ApprovalRequest, len(rows))
	for i, r := range rows {
		out[i] = r.request()
	}
	return out, nil
}

func (c *client) ApprovalRequest(ctx context.Context, tenantID, requestID string) (model.ApprovalRequest, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return model.ApprovalRequest{}, err
	}
	var row tlApproval
	if err := c.do(ctx, a, "ApprovalRequest/ApprovalRequestGetById?approvalRequestId="+requestID, nil, &row); err != nil {
		return model.ApprovalRequest{}, err
	}
	return row.request(), nil
}

// policyQuery is the Policy/PolicyGetByParameters body (KB → /portalAPI/Policy/*):
// filter is required (empty = no filter), showAllPolicies widens the scope to
// everything affecting the organization.
type policyQuery struct {
	Filter             string `json:"filter"`
	SearchText         string `json:"searchText"`
	PageNumber         int    `json:"pageNumber"`
	PageSize           int    `json:"pageSize"`
	ShowAllPolicies    bool   `json:"showAllPolicies"`
	ChildOrganizations bool   `json:"childOrganizations"`
	ActiveOnly         bool   `json:"activeOnly"`
}

// tlPolicy is one row of PolicyGetByParameters. Field names verified against
// the live portal response; a couple of alternate spellings are also accepted
// so the mapping is robust across portal versions. Note the portal returns
// status as an integer (1 = enabled), so enabled state is read from the
// isEnabled boolean.
type tlPolicy struct {
	PolicyID         string `json:"policyId"`
	PolicyName       string `json:"policyName"`
	Name             string `json:"name"`
	PolicyAction     string `json:"policyAction"`
	PolicyActionID   int    `json:"policyActionId"`
	Action           string `json:"action"`
	AppliesTo        string `json:"appliesTo"`
	AppliesToName    string `json:"appliesToName"`
	GroupName        string `json:"groupName"`
	Ringfence        bool   `json:"ringfence"`
	IsEnabled        *bool  `json:"isEnabled"`
	Status           any    `json:"status"`
	ApplicationCount int    `json:"applicationCount"`
	UserCount        int    `json:"userCount"`
	AllUserGroups    bool   `json:"allUserGroups"`
	LastMatchedAt    string `json:"lastMatchDateTime"`
	MonitorMode      int    `json:"monitorMode"`
	OrganizationID   string `json:"organizationId"`
}

func (t *tlPolicy) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	t.PolicyID = rawString(raw["policyId"])
	t.PolicyName = rawString(raw["policyName"])
	t.Name = rawString(raw["name"])
	t.PolicyAction = rawString(raw["policyAction"])
	t.PolicyActionID = rawInt(raw["policyActionId"])
	t.Action = rawString(raw["action"])
	t.AppliesTo = rawString(raw["appliesTo"])
	t.AppliesToName = rawString(raw["appliesToName"])
	t.GroupName = rawString(raw["groupName"])
	t.Ringfence = rawBool(raw["ringfence"])
	t.IsEnabled = rawBoolPtr(raw["isEnabled"])
	t.ApplicationCount = firstNonZero(rawCount(raw["applicationList"]), rawCount(raw["applicationIdList"]), rawCount(raw["applications"]), rawCount(raw["applicationIds"]))
	t.UserCount = firstNonZero(rawCount(raw["users"]), rawCount(raw["userList"]), rawCount(raw["userIdList"]), rawCount(raw["userGroupList"]), rawCount(raw["userGroupIdList"]), rawCount(raw["userGroupIds"]))
	t.AllUserGroups = rawBool(raw["allUserGroups"])
	t.LastMatchedAt = rawString(raw["lastMatchDateTime"])
	t.MonitorMode = rawInt(raw["monitorMode"])
	t.OrganizationID = rawString(raw["organizationId"])
	if v, ok := raw["status"]; ok {
		_ = json.Unmarshal(v, &t.Status)
	}
	return nil
}

func (t tlPolicy) policy() model.TLPolicy {
	// A ringfenced permit policy is a distinct concept in ThreatLocker, so it
	// is surfaced as "ringfence" rather than the underlying permit action.
	action := strings.ToLower(firstNonEmpty(t.PolicyAction, t.Action))
	if t.Ringfence {
		action = "ringfence"
	}
	return model.TLPolicy{
		ID:               t.PolicyID,
		Name:             firstNonEmpty(t.PolicyName, t.Name),
		Action:           action,
		PolicyActionID:   t.PolicyActionID,
		AppliesTo:        firstNonEmpty(t.AppliesToName, t.GroupName, t.AppliesTo),
		Status:           t.status(),
		ApplicationCount: t.ApplicationCount,
		UserCount:        t.UserCount,
		AllUsers:         t.AllUserGroups,
		LastMatchedAt:    t.LastMatchedAt,
		MonitorMode:      t.MonitorMode,
		OrganizationID:   t.OrganizationID,
	}
}

func (t tlPolicy) status() string {
	if t.IsEnabled != nil {
		if *t.IsEnabled {
			return "Enabled"
		}
		return "Disabled"
	}
	switch v := t.Status.(type) {
	case string:
		if strings.EqualFold(v, "disabled") || v == "0" {
			return "Disabled"
		}
	case float64:
		if v == 0 {
			return "Disabled"
		}
	}
	return "Enabled"
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return strconv.FormatBool(b)
	}
	return ""
}

func rawBool(raw json.RawMessage) bool {
	v := rawBoolPtr(raw)
	return v != nil && *v
}

func rawInt(raw json.RawMessage) int {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		i, _ := strconv.Atoi(n.String())
		return i
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return int(f)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		i, _ := strconv.Atoi(strings.TrimSpace(s))
		return i
	}
	return 0
}

func rawCount(raw json.RawMessage) int {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0
	}
	var xs []any
	if json.Unmarshal(raw, &xs) == nil {
		return len(xs)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		i, _ := strconv.Atoi(n.String())
		return i
	}
	return 0
}

func firstNonZero(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func rawBoolPtr(raw json.RawMessage) *bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return &b
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		v := n.String() != "0"
		return &v
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true", "1", "yes", "enabled":
			v := true
			return &v
		case "false", "0", "no", "disabled":
			v := false
			return &v
		}
	}
	return nil
}

func (c *client) Policies(ctx context.Context, tenantID string) ([]model.TLPolicy, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	const pageSize = 1000
	var all []tlPolicy
	seenPages := map[string]bool{}
	for page := 1; ; page++ {
		var raw json.RawMessage
		q := policyQuery{Filter: "", PageNumber: page, PageSize: pageSize, ShowAllPolicies: true, ChildOrganizations: true}
		if err := c.do(ctx, a, "Policy/PolicyGetByParameters", q, &raw); err != nil {
			return nil, err
		}
		rows, err := listOf[tlPolicy](raw)
		if err != nil {
			return nil, err
		}
		sig := policyPageSignature(rows)
		if sig != "" && seenPages[sig] {
			break
		}
		seenPages[sig] = true
		all = append(all, rows...)
		if len(rows) < pageSize {
			break
		}
	}
	out := make([]model.TLPolicy, len(all))
	for i, r := range all {
		out[i] = r.policy()
	}
	return out, nil
}

func policyPageSignature(rows []tlPolicy) string {
	if len(rows) == 0 {
		return ""
	}
	return fmt.Sprintf("%d:%s:%s", len(rows), rows[0].PolicyID, rows[len(rows)-1].PolicyID)
}

func (c *client) Policy(ctx context.Context, tenantID, policyID string) (model.TLPolicyDetail, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	policies, err := c.Policies(ctx, tenantID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	for _, policy := range policies {
		if policy.ID == policyID && policy.OrganizationID != "" {
			return c.PolicyForAuth(ctx, Auth{Instance: a.Instance, Token: a.Token, OrgID: policy.OrganizationID}, policyID, a.OrgID)
		}
	}
	return c.policyForAuth(ctx, a, policyID)
}

func (c *client) PolicyInOrg(ctx context.Context, tenantID, policyID, orgID string) (model.TLPolicyDetail, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	fallback := a.OrgID
	if orgID = strings.TrimSpace(orgID); orgID != "" {
		a.OrgID = orgID
	}
	return c.PolicyForAuth(ctx, a, policyID, fallback)
}

func (c *client) UpdatePolicy(ctx context.Context, tenantID string, patch model.TLPolicyPatch) (model.TLPolicyDetail, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	current, err := c.Policy(ctx, tenantID, patch.ID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	if current.OrganizationID != "" {
		a.OrgID = current.OrganizationID
	}
	return c.UpdatePolicyForAuth(ctx, a, patch)
}

// UpdatePolicyForAuth updates a policy in the organization named by a. The
// cleanup flow uses this with the MSP parent auth because the retained/global
// policy lives in the parent org, not the active tenant's org — sending the
// tenant's managedOrganizationId makes the portal reject the write with
// "Insufficient permission to update policies in the selected destination".
func (c *client) UpdatePolicyForAuth(ctx context.Context, a Auth, patch model.TLPolicyPatch) (model.TLPolicyDetail, error) {
	if patch.ID == "" {
		return model.TLPolicyDetail{}, &APIError{Status: 400, Message: "policy id is required", Path: "PolicyUpdateById"}
	}
	current, err := c.policyForAuth(ctx, a, patch.ID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	body := patchPolicy(current.Raw, patch, a.OrgID)
	var raw map[string]any
	if err := c.doMethod(ctx, a, http.MethodPut, "Policy/PolicyUpdateById", body, &raw); err != nil {
		return model.TLPolicyDetail{}, err
	}
	return policyDetail(raw), nil
}

func (c *client) policyForAuth(ctx context.Context, a Auth, policyID string) (model.TLPolicyDetail, error) {
	var raw map[string]any
	if err := c.do(ctx, a, "Policy/PolicyGetById?policyId="+url.QueryEscape(policyID), nil, &raw); err != nil {
		return model.TLPolicyDetail{}, err
	}
	return policyDetail(raw), nil
}

// PolicyForAuth reads one policy, trying a.OrgID first and then each fallback
// organization with the same instance/token. The portal only serves
// PolicyGetById when the managedOrganizationId header names the organization
// the policy lives in, and policies attached to a parent app can live in child
// organizations ("Unable to retrieve application policy" otherwise).
func (c *client) PolicyForAuth(ctx context.Context, a Auth, policyID string, fallbackOrgIDs ...string) (model.TLPolicyDetail, error) {
	raw, _, err := c.policyRawInOrgs(ctx, a, policyID, fallbackOrgIDs...)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	return policyDetail(raw), nil
}

// policyRawInOrgs fetches a policy's raw row, trying a.OrgID and then each
// fallback org in order. It returns the row and the org that served it.
func (c *client) policyRawInOrgs(ctx context.Context, a Auth, policyID string, fallbackOrgIDs ...string) (map[string]any, string, error) {
	orgIDs := append([]string{a.OrgID}, fallbackOrgIDs...)
	tried := map[string]bool{}
	var firstErr error
	for _, orgID := range orgIDs {
		orgID = strings.TrimSpace(orgID)
		if orgID == "" || tried[orgID] {
			continue
		}
		tried[orgID] = true
		orgAuth := a
		orgAuth.OrgID = orgID
		var raw map[string]any
		err := c.do(ctx, orgAuth, "Policy/PolicyGetById?policyId="+url.QueryEscape(policyID), nil, &raw)
		if err == nil {
			return raw, orgID, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, "", firstErr
}

func (c *client) CreatePolicy(ctx context.Context, tenantID string, detail model.TLPolicyDetail) (model.TLPolicyDetail, error) {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return model.TLPolicyDetail{}, err
	}
	return c.CreatePolicyForAuth(ctx, a, detail)
}

// CreatePolicyForAuth creates a policy in the organization named by a. Like
// UpdatePolicyForAuth, the cleanup flow passes the parent auth so the new
// global policy is created in the MSP parent org alongside the retained app.
func (c *client) CreatePolicyForAuth(ctx context.Context, a Auth, detail model.TLPolicyDetail) (model.TLPolicyDetail, error) {
	body := clonePolicyBody(detail.Raw, a.OrgID)
	if len(body) == 0 {
		body = map[string]any{}
	}
	if detail.Name != "" {
		body["name"] = detail.Name
	}
	if detail.Description != "" {
		body["description"] = detail.Description
	}
	body["organizationId"] = a.OrgID
	body["managedOrganizationId"] = a.OrgID
	var raw map[string]any
	if err := c.do(ctx, a, "Policy/PolicyInsert", body, &raw); err != nil {
		return model.TLPolicyDetail{}, err
	}
	return policyDetail(raw), nil
}

func (c *client) UpdateApplication(ctx context.Context, tenantID string, patch model.TLApplicationPatch) (model.TLApplicationDetail, error) {
	if patch.ID == "" {
		return model.TLApplicationDetail{}, &APIError{Status: 400, Message: "application id is required", Path: "ApplicationUpdateById"}
	}
	a, err := c.authForApplication(ctx, tenantID, patch.ID)
	if err != nil {
		return model.TLApplicationDetail{}, err
	}
	return c.updateApplicationForAuth(ctx, a, patch)
}

func (c *client) updateApplicationForAuth(ctx context.Context, a Auth, patch model.TLApplicationPatch) (model.TLApplicationDetail, error) {
	current, err := c.applicationForAuth(ctx, a, patch.ID)
	if err != nil {
		return model.TLApplicationDetail{}, err
	}
	body := cloneApplicationBody(current.Raw, a.OrgID)
	body["applicationId"] = patch.ID
	if patch.Name != nil {
		body["name"] = *patch.Name
	}
	if patch.Description != nil {
		body["description"] = *patch.Description
	}
	var raw map[string]any
	if err := c.doMethod(ctx, a, http.MethodPut, "Application/ApplicationUpdateById", body, &raw); err != nil {
		return model.TLApplicationDetail{}, err
	}
	return applicationDetail(raw, c.effectiveParentOrgID(ctx)), nil
}

func (c *client) CreateApplication(ctx context.Context, a Auth, detail model.TLApplicationDetail) (model.TLApplicationDetail, error) {
	// The portal's ApplicationInsert DTO is minimal (KB: name + osType,
	// optionally description and inline file rules) — echoing a GetById DTO
	// back makes the portal 500 with its generic error. File rules are copied
	// afterwards via ApplicationFileInsert, and the target organization comes
	// from the managedOrganizationId header.
	osType := detail.OSType
	if osType == 0 {
		osType = 1
	}
	body := map[string]any{
		"name":                   detail.Name,
		"description":            detail.Description,
		"osType":                 osType,
		"applicationFileUpdates": []any{},
	}
	var raw map[string]any
	if err := c.do(ctx, a, "Application/ApplicationInsert", body, &raw); err != nil {
		return model.TLApplicationDetail{}, err
	}
	created := applicationDetail(raw, c.effectiveParentOrgID(ctx))
	if created.ID == "" {
		// The insert response shape is undocumented; resolve the created app
		// by name so callers always get a usable ID (cleanup fails closed on
		// a missing retained-app ID before any deletion).
		apps, err := c.applicationsForAuth(ctx, a, AppSearchRequest{
			SearchText: detail.Name, SearchBy: "app", OSType: osType, IncludeUnused: true,
		})
		if err != nil {
			return model.TLApplicationDetail{}, err
		}
		for _, app := range apps {
			if strings.EqualFold(strings.TrimSpace(app.Name), strings.TrimSpace(detail.Name)) {
				created.TLApplication = app
				break
			}
		}
	}
	if created.Name == "" {
		created.Name = detail.Name
	}
	return created, nil
}

func (c *client) GlobalComputerGroup(ctx context.Context, a Auth) (model.TLComputerGroup, error) {
	var raw any
	if err := c.do(ctx, a, "ComputerGroup/ComputerGroupGetDropdownWithOrganization?includeAvailableOrganizations=true", nil, &raw); err != nil {
		return model.TLComputerGroup{}, err
	}
	groups := []model.TLComputerGroup{}
	var visit func(any, string)
	visit = func(value any, inheritedOrganizationID string) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				visit(item, inheritedOrganizationID)
			}
		case map[string]any:
			organizationID := firstString(typed, "organizationId", "OrganizationId", "masterOrganizationId", "MasterOrganizationId")
			if organizationID == "" {
				organizationID = inheritedOrganizationID
			}
			id := firstString(typed, "computerGroupId", "ComputerGroupId", "groupId", "GroupId", "value", "Value")
			name := firstString(typed, "computerGroupName", "ComputerGroupName", "groupName", "GroupName", "label", "Label", "text", "Text", "name", "Name", "displayName", "DisplayName")
			if id != "" && name != "" {
				groups = append(groups, model.TLComputerGroup{ID: id, Name: name, OrganizationID: organizationID})
			}
			for _, child := range typed {
				visit(child, organizationID)
			}
		}
	}
	visit(raw, "")
	for _, group := range groups {
		if strings.EqualFold(strings.TrimSpace(group.Name), "Global") &&
			(group.OrganizationID == "" || strings.EqualFold(strings.TrimSpace(group.OrganizationID), strings.TrimSpace(a.OrgID))) {
			group.OrganizationID = a.OrgID
			return group, nil
		}
	}
	return model.TLComputerGroup{}, &APIError{
		Status:  http.StatusUnprocessableEntity,
		Message: `the parent organization does not expose an exact "Global" computer group`,
		Path:    "ComputerGroupGetDropdownWithOrganization",
	}
}

func (c *client) PromoteApplicationPolicy(ctx context.Context, parent Auth, promotion model.TLAppParentPromotion) error {
	sourceAuth := parent
	sourceAuth.OrgID = strings.TrimSpace(promotion.SourceOrganizationID)
	if sourceAuth.OrgID == "" {
		return &APIError{Status: http.StatusBadRequest, Message: "source organization id is required", Path: "PolicyMoveQueueInsert"}
	}
	var promotionModel any
	err := c.do(ctx, sourceAuth,
		"Policy/PolicyGetForPromotePolicyById?policyId="+url.QueryEscape(promotion.PolicyID)+"&osType="+url.QueryEscape(strconv.Itoa(promotion.OSType)),
		nil, &promotionModel)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest ||
			!strings.Contains(strings.ToLower(apiErr.Message), "unable to retrieve application policy") {
			return err
		}
	}
	applicationAuth := parent
	applicationAuth.OrgID = strings.TrimSpace(promotion.ApplicationOrganizationID)
	if applicationAuth.OrgID == "" {
		applicationAuth.OrgID = sourceAuth.OrgID
	}
	var validation any
	if err := c.do(ctx, applicationAuth, "Policy/ShouldPromoteApplication", map[string]any{
		"computerGroupId":   promotion.DestinationGroupID,
		"applicationIdList": []string{promotion.ApplicationID},
	}, &validation); err != nil {
		return err
	}
	return c.do(ctx, sourceAuth, "PolicyMoveQueue/PolicyMoveQueueInsert", map[string]any{
		"policyId":                 promotion.PolicyID,
		"newPolicyComputerGroupId": promotion.DestinationGroupID,
		"applicationId":            promotion.ApplicationID,
		"computersAffected":        -1,
		"parentId":                 promotion.ParentOrganizationID,
		"osType":                   promotion.OSType,
	}, nil)
}

func (c *client) MergeApplications(
	ctx context.Context,
	parent Auth,
	target model.TLApplication,
	sources []model.TLApplication,
	finalName string,
) (model.TLApplicationDetail, error) {
	if target.ID == "" || !strings.EqualFold(strings.TrimSpace(target.OrganizationID), strings.TrimSpace(parent.OrgID)) {
		return model.TLApplicationDetail{}, &APIError{
			Status: http.StatusBadRequest, Message: "merge target must be owned by the parent organization", Path: "ApplicationUpdateForMerge",
		}
	}
	targetDetail, err := c.applicationForAuth(ctx, parent, target.ID)
	if err != nil {
		return model.TLApplicationDetail{}, err
	}
	mergedApplications := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		if source.ID == "" || source.ID == target.ID {
			continue
		}
		sourceAuth := parent
		sourceAuth.OrgID = strings.TrimSpace(source.OrganizationID)
		if sourceAuth.OrgID == "" {
			return model.TLApplicationDetail{}, &APIError{
				Status: http.StatusBadRequest, Message: "merge source organization id is required", Path: "ApplicationUpdateForMerge",
			}
		}
		detail, err := c.applicationForAuth(ctx, sourceAuth, source.ID)
		if err != nil {
			return model.TLApplicationDetail{}, err
		}
		mergedApplications = append(mergedApplications, detail.Raw)
	}
	if len(mergedApplications) == 0 {
		return model.TLApplicationDetail{}, &APIError{
			Status: http.StatusBadRequest, Message: "at least one merge source is required", Path: "ApplicationUpdateForMerge",
		}
	}
	var mergeResult any
	if err := c.do(ctx, parent, "Application/ApplicationUpdateForMerge", map[string]any{
		"mergedApplications": mergedApplications,
		"targetApplication":  targetDetail.Raw,
		"helpDeskTicket":     nil,
		"version":            "",
		"releaseDate":        time.Now().UTC().Format(time.RFC3339),
	}, &mergeResult); err != nil {
		return model.TLApplicationDetail{}, err
	}
	finalName = strings.TrimSpace(finalName)
	if finalName == "" {
		finalName = targetDetail.Name
	}
	updated, err := c.updateApplicationForAuth(ctx, parent, model.TLApplicationPatch{
		ID: target.ID, Name: &finalName,
	})
	if err != nil {
		return model.TLApplicationDetail{}, err
	}
	fresh, err := c.applicationForAuth(ctx, parent, target.ID)
	if err != nil {
		return model.TLApplicationDetail{}, err
	}
	if fresh.Name != finalName {
		return model.TLApplicationDetail{}, &APIError{
			Status:  http.StatusBadGateway,
			Message: fmt.Sprintf("applications merged, but ThreatLocker did not retain the requested name %q", finalName),
			Path:    "ApplicationUpdateById",
		}
	}
	if updated.ID == "" {
		updated = fresh
	}
	return fresh, nil
}

func (c *client) InsertApplicationFile(ctx context.Context, a Auth, file model.TLApplicationFile) error {
	// The KB's file-rule shape requires a note per rule and updateStatus 1
	// for the rule to be applied.
	notes := strings.TrimSpace(file.Notes)
	if notes == "" {
		notes = "Copied by RTM app cleanup"
	}
	osType := file.OSType
	if osType == 0 {
		osType = 1 // the portal rejects a missing osType
	}
	body := map[string]any{
		"applicationFileId":      0,
		"applicationId":          file.ApplicationID,
		"osType":                 osType,
		"notes":                  notes,
		"applicationName":        nil,
		"applicationFileDetails": nil,
		"createdBy":              nil,
		"keyFile":                file.KeyFile,
		"maxSize":                nil,
		"minSize":                nil,
		"name":                   file.Name,
		"organizationId":         nil,
		"originalCert":           nil,
		"originalFullPath":       nil,
		"originalHash":           nil,
		"originalInstalledBy":    nil,
		"originalKeyFile":        false,
		"originalNotes":          nil,
		"originalProcessPath":    nil,
		"updateStatus":           1,
	}
	// A rule matches either by hash alone or by path/created-by/cert — the
	// portal rejects a hash combined with the other condition fields, and a
	// hash sent with isHashOnly false is validated as a non-hash rule with no
	// conditions ("Please enter the Hash only, or …").
	if strings.TrimSpace(file.Hash) != "" {
		body["hash"] = file.Hash
		body["isHashOnly"] = true
		body["cert"] = ""
		body["fullPath"] = ""
		body["processPath"] = ""
		body["installedBy"] = ""
	} else {
		body["hash"] = ""
		body["isHashOnly"] = false
		body["cert"] = file.Cert
		body["fullPath"] = file.FullPath
		body["processPath"] = file.ProcessPath
		body["installedBy"] = file.InstalledBy
	}
	return c.do(ctx, a, "ApplicationFile/ApplicationFileInsert", body, nil)
}

func (c *client) DeleteApplication(ctx context.Context, tenantID string, app model.TLApplication, confirm bool) error {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return err
	}
	path := "Application/ApplicationUpdateForDelete"
	if confirm {
		path = "Application/ApplicationConfirmUpdateForDelete"
	}
	osType := app.OSType
	if osType == 0 {
		osType = 1
	}
	// The KB documents an "applications" array of {applicationId, name,
	// organizationId, osType} for both delete variants.
	body := map[string]any{
		"applications": []map[string]any{{
			"applicationId":  app.ID,
			"name":           app.Name,
			"organizationId": app.OrganizationID,
			"osType":         osType,
		}},
	}
	return c.do(ctx, a, path, body, nil)
}

func (c *client) PoliciesForApplication(ctx context.Context, tenantID, appID string) ([]model.TLPolicy, error) {
	a, err := c.authForApplication(ctx, tenantID, appID)
	if err != nil {
		return nil, err
	}
	return c.PoliciesForApplicationForAuth(ctx, a, appID)
}

func (c *client) PoliciesForApplicationForAuth(ctx context.Context, a Auth, appID string) ([]model.TLPolicy, error) {
	var raw json.RawMessage
	body := map[string]any{"applicationId": appID, "pageNumber": 1, "pageSize": 500}
	if err := c.do(ctx, a, "Policy/PolicyGetForViewPoliciesByApplicationId", body, &raw); err != nil {
		return nil, err
	}
	rows, err := listOf[tlPolicy](raw)
	if err != nil {
		return nil, err
	}
	out := make([]model.TLPolicy, len(rows))
	for i, row := range rows {
		out[i] = row.policy()
	}
	return out, nil
}

func (c *client) DeletePolicies(ctx context.Context, tenantID string, policies []model.TLPolicy) error {
	a, err := c.auth(ctx, tenantID)
	if err != nil {
		return err
	}
	// The endpoint's binder wants a bare array of policy rows
	// (List<PolicyTableDto>) at the JSON root — the portal UI posts the
	// selected table rows back. An object body ({"policyIds": …}) is rejected
	// with an RFC 9110 validation error. Rebuild each row from PolicyGetById.
	//
	// Both PolicyGetById and the delete itself must carry the
	// managedOrganizationId of the organization each policy lives in — a
	// policy attached to a parent app can live in a child organization, and
	// the portal answers "Unable to retrieve application policy" when the
	// header names any other org. Group the rows per owning org and issue one
	// delete per group.
	rowsByOrg := map[string][]map[string]any{}
	orgOrder := []string{}
	for _, p := range policies {
		rowAuth := a
		if orgID := strings.TrimSpace(p.OrganizationID); orgID != "" {
			rowAuth.OrgID = orgID
		}
		raw, servedOrg, err := c.policyRawInOrgs(ctx, rowAuth, p.ID, a.OrgID)
		if err != nil {
			return err
		}
		if _, ok := raw["policyId"]; !ok {
			raw["policyId"] = p.ID
		}
		if len(rowsByOrg[servedOrg]) == 0 {
			orgOrder = append(orgOrder, servedOrg)
		}
		rowsByOrg[servedOrg] = append(rowsByOrg[servedOrg], raw)
	}
	for _, orgID := range orgOrder {
		orgAuth := a
		orgAuth.OrgID = orgID
		if err := c.doMethod(ctx, orgAuth, http.MethodPut, "Policy/PolicyUpdateForDeleteByIds", rowsByOrg[orgID], nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) DeployPolicies(ctx context.Context, a Auth) error {
	body := map[string]any{"organizationId": a.OrgID, "managedOrganizationId": a.OrgID}
	return c.do(ctx, a, "DeployPolicyQueue/DeployPolicies", body, nil)
}

func cloneApplicationBody(raw map[string]any, orgID string) map[string]any {
	body := map[string]any{}
	for k, v := range raw {
		body[k] = v
	}
	body["organizationId"] = orgID
	body["managedOrganizationId"] = orgID
	return body
}

func policyDetail(raw map[string]any) model.TLPolicyDetail {
	isEnabled := anyBool(raw["isEnabled"])
	actionID := anyInt(raw["policyActionId"])
	action := strings.ToLower(firstNonEmpty(anyString(raw["policyAction"]), anyString(raw["action"])))
	if action == "" {
		action = actionName(actionID)
	}
	return model.TLPolicyDetail{
		ID:                   firstNonEmpty(anyString(raw["policyId"]), anyString(raw["id"])),
		Name:                 firstNonEmpty(anyString(raw["name"]), anyString(raw["policyName"])),
		Description:          anyString(raw["description"]),
		Comments:             anyString(raw["comments"]),
		Action:               action,
		PolicyActionID:       actionID,
		AppliesTo:            firstNonEmpty(anyString(raw["appliesToName"]), anyString(raw["groupName"]), anyString(raw["appliesTo"])),
		Status:               enabledStatus(isEnabled),
		IsEnabled:            isEnabled,
		MonitorMode:          anyInt(raw["monitorMode"]),
		OrderBy:              anyInt(raw["orderBy"]),
		NeverExpires:         anyBool(raw["neverExpires"]),
		EndDate:              anyString(raw["endDate"]),
		LogAction:            anyBool(raw["logAction"]),
		NotifyOnMatch:        anyBool(raw["notifyOnMatch"]),
		NotifyOnRequest:      anyBool(raw["notifyOnRequest"]),
		KillRunningProcesses: anyBool(raw["killRunningProcesses"]),
		ApplicationSelection: anyInt(raw["applicationSelection"]),
		ApplicationIDs:       anyStringSlice(raw["applicationIdList"]),
		Applications:         policyApplications(raw),
		OrganizationID:       anyString(raw["organizationId"]),
		Raw:                  raw,
	}
}

func policyApplications(raw map[string]any) []model.TLPolicyApplication {
	seen := map[string]bool{}
	out := []model.TLPolicyApplication{}
	add := func(app model.TLPolicyApplication) {
		if app.ID == "" && app.Name == "" && app.Path == "" {
			return
		}
		key := firstNonEmpty(app.ID, app.Name, app.Path)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, app)
	}
	switch xs := raw["applicationList"].(type) {
	case []any:
		for _, x := range xs {
			if m, ok := x.(map[string]any); ok {
				add(model.TLPolicyApplication{
					ID:   firstNonEmpty(anyString(m["applicationId"]), anyString(m["id"])),
					Name: firstNonEmpty(anyString(m["name"]), anyString(m["applicationName"]), anyString(m["fileName"])),
					Path: firstNonEmpty(anyString(m["path"]), anyString(m["fullPath"]), anyString(m["processPath"])),
				})
			} else if id := anyString(x); id != "" {
				add(model.TLPolicyApplication{ID: id})
			}
		}
	}
	for _, id := range anyStringSlice(raw["applicationIdList"]) {
		add(model.TLPolicyApplication{ID: id})
	}
	return out
}

func patchPolicy(raw map[string]any, patch model.TLPolicyPatch, orgID string) map[string]any {
	body := clonePolicyBody(raw, orgID)
	body["policyId"] = patch.ID
	if patch.Name != nil {
		body["name"] = *patch.Name
	}
	if patch.Description != nil {
		body["description"] = *patch.Description
	}
	if patch.Comments != nil {
		body["comments"] = *patch.Comments
	}
	if patch.IsEnabled != nil {
		body["isEnabled"] = *patch.IsEnabled
	}
	if patch.AllDevices != nil {
		body["allDevices"] = *patch.AllDevices
	}
	if patch.AllUserGroups != nil {
		body["allUserGroups"] = *patch.AllUserGroups
	}
	if patch.ComputerGroupID != nil {
		body["computerGroupId"] = *patch.ComputerGroupID
	}
	if patch.PolicyActionID != nil {
		body["policyActionId"] = *patch.PolicyActionID
	}
	if patch.MonitorMode != nil {
		body["monitorMode"] = *patch.MonitorMode
	}
	if patch.OrderBy != nil {
		body["orderBy"] = *patch.OrderBy
	}
	if patch.NeverExpires != nil {
		body["neverExpires"] = *patch.NeverExpires
	}
	if patch.EndDate != nil {
		body["endDate"] = *patch.EndDate
	}
	if patch.LogAction != nil {
		body["logAction"] = *patch.LogAction
	}
	if patch.NotifyOnMatch != nil {
		body["notifyOnMatch"] = *patch.NotifyOnMatch
	}
	if patch.NotifyOnRequest != nil {
		body["notifyOnRequest"] = *patch.NotifyOnRequest
	}
	if patch.KillRunningProcesses != nil {
		body["killRunningProcesses"] = *patch.KillRunningProcesses
	}
	if patch.ApplicationSelection != nil {
		body["applicationSelection"] = *patch.ApplicationSelection
	}
	if patch.ApplicationIDs != nil {
		body["applicationIdList"] = patch.ApplicationIDs
	}
	return body
}

func clonePolicyBody(raw map[string]any, orgID string) map[string]any {
	body := map[string]any{}
	for k, v := range raw {
		body[k] = v
	}
	body["organizationId"] = orgID
	body["managedOrganizationId"] = orgID
	return body
}

func enabledStatus(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

// actionName maps policyActionId per the portal (verified live and in the
// KB): 1 = Permit, 2 = Deny, 3 = Request.
func actionName(id int) string {
	switch id {
	case 1:
		return "permit"
	case 2:
		return "deny"
	case 3:
		return "request"
	default:
		return ""
	}
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

func anyInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case json.Number:
		n, _ := strconv.Atoi(x.String())
		return n
	default:
		return 0
	}
}

func anyBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case json.Number:
		return x.String() != "0"
	case string:
		return strings.EqualFold(x, "true") || x == "1" || strings.EqualFold(x, "enabled")
	default:
		return false
	}
}

func anyStringSlice(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s := anyString(x); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// TestConnection verifies the tenant's token + org scoping end-to-end with a
// one-row device list.
func (c *client) TestConnection(ctx context.Context, tenantID string) error {
	_, err := c.devicePage(ctx, tenantID, 1, 1, true)
	return err
}

// TestConnectionForAuth validates a proposed global connection without
// changing the active database-backed configuration.
func (c *client) TestConnectionForAuth(ctx context.Context, a Auth) error {
	var raw json.RawMessage
	q := computerQuery{
		PageNumber: 1, PageSize: 1, OrderBy: "computername",
		IsAscending: true, ChildOrganizations: true, ShowLastCheckIn: true,
	}
	return c.do(ctx, a, "Computer/ComputerGetByAllParameters", q, &raw)
}

// ---- writes ----

// maintenanceTypeID maps an RTM maintenance type to the ThreatLocker
// maintenanceModeType id used by ComputerDisableProtection
// (MonitorOnly = 1, Learning = 3). ok=false → the type isn't reachable through
// this endpoint.
func maintenanceTypeID(t string) (int, bool) {
	switch t {
	case MaintenanceMonitorOnly:
		return 1, true
	case MaintenanceLearning:
		return 3, true
	default:
		return 0, false
	}
}

type computerRef struct {
	ComputerID     string `json:"computerId"`
	ComputerName   string `json:"computerName,omitempty"`
	OrganizationID string `json:"organizationId"`
}

type disableProtectionBody struct {
	ComputerDetailDtos  []computerRef `json:"computerDetailDtos"`
	MaintenanceModeType int           `json:"maintenanceModeType"`
	StartDate           string        `json:"startDate"`
	EndDate             string        `json:"endDate"`
}

func (c *client) SetMaintenanceMode(ctx context.Context, tenantID, deviceID, maintenanceType string, durationMinutes int) error {
	a, err := c.authForDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	typeID, ok := maintenanceTypeID(maintenanceType)
	if !ok {
		return &APIError{Status: 400, Message: "unsupported maintenance type: " + maintenanceType, Path: "SetMaintenanceMode"}
	}
	now := time.Now().UTC()
	body := disableProtectionBody{
		ComputerDetailDtos:  []computerRef{{ComputerID: deviceID, OrganizationID: a.OrgID}},
		MaintenanceModeType: typeID,
		StartDate:           now.Format(time.RFC3339),
		EndDate:             now.Add(time.Duration(durationMinutes) * time.Minute).Format(time.RFC3339),
	}
	return c.do(ctx, a, "Computer/ComputerDisableProtection", body, nil)
}

func (c *client) SecureDevice(ctx context.Context, tenantID, deviceID string) error {
	a, err := c.authForDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	body := struct {
		ComputerDetailDtos []computerRef `json:"computerDetailDtos"`
	}{[]computerRef{{ComputerID: deviceID, OrganizationID: a.OrgID}}}
	return c.do(ctx, a, "Computer/ComputerEnableProtection", body, nil)
}

func (c *client) RestartAgent(ctx context.Context, tenantID, deviceID string) error {
	a, err := c.authForDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	body := []computerRef{{ComputerID: deviceID, OrganizationID: a.OrgID}}
	return c.do(ctx, a, "Computer/ComputerUpdateShouldRestartByIds", body, nil)
}

// Lockdown, isolation, and tamper-protection toggles are not exposed by the
// public ThreatLocker portal API, so RTM fails them honestly rather than
// guessing a payload against real endpoints.
func (c *client) SetLockdown(ctx context.Context, tenantID, deviceID string, enabled bool) error {
	return ErrNotSupported
}

func (c *client) SetIsolation(ctx context.Context, tenantID, deviceID string, enabled bool) error {
	return ErrNotSupported
}

func (c *client) SetTamperProtection(ctx context.Context, tenantID, deviceID string, enabled bool) error {
	return ErrNotSupported
}

// ApproveRequest follows the documented permit flow: fetch the request's
// permit application via GetPermitApplicationById, set the policy scope, and
// post it to ApprovalRequestPermitApplication. The portal builds the policy.
func (c *client) ApproveRequest(ctx context.Context, tenantID, requestID, scope, expiresAt string) error {
	a, err := c.authForApproval(ctx, requestID)
	if err != nil {
		return err
	}
	// The permit application object is returned pre-populated; RTM only sets
	// the policy scope (and optional expiry) before posting it back.
	var permit map[string]any
	if err := c.do(ctx, a, "ApprovalRequest/ApprovalRequestGetPermitApplicationById?approvalRequestId="+requestID, nil, &permit); err != nil {
		return err
	}
	permit["policyLevel"] = map[string]any{
		"toEntireOrganization": scope == ScopeOrganization,
		"toComputerGroup":      scope == ScopeGroup,
		"toComputer":           scope == ScopeComputer,
	}
	if expiresAt != "" {
		permit["policyExpirationDate"] = expiresAt
	}
	return c.do(ctx, a, "ApprovalRequest/ApprovalRequestPermitApplication", permit, nil)
}

// DenyRequest rejects the pending request (ApprovalRequestUpdateForReject).
func (c *client) DenyRequest(ctx context.Context, tenantID, requestID, reason string) error {
	a, err := c.authForApproval(ctx, requestID)
	if err != nil {
		return err
	}
	body := map[string]any{
		"approvalRequestDtos": []map[string]any{{"approvalRequestId": requestID}},
		"rejectReason":        reason,
	}
	return c.do(ctx, a, "ApprovalRequest/ApprovalRequestUpdateForReject", body, nil)
}

func (c *client) authForDevice(ctx context.Context, deviceID string) (Auth, error) {
	a, err := c.parentAuth(ctx)
	if err != nil {
		return Auth{}, err
	}
	devices, err := c.Devices(ctx, "")
	if err != nil {
		return Auth{}, err
	}
	for _, device := range devices {
		if device.ID == deviceID {
			if device.OrganizationID != "" {
				a.OrgID = device.OrganizationID
			}
			return a, nil
		}
	}
	return a, nil
}

func (c *client) authForApproval(ctx context.Context, requestID string) (Auth, error) {
	a, err := c.parentAuth(ctx)
	if err != nil {
		return Auth{}, err
	}
	requests, err := c.ApprovalRequests(ctx, "", RequestPending)
	if err != nil {
		return Auth{}, err
	}
	for _, request := range requests {
		if request.ID == requestID {
			if request.OrganizationID != "" {
				a.OrgID = request.OrganizationID
			}
			return a, nil
		}
	}
	return a, nil
}
