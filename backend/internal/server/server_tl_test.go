package server_test

// End-to-end tests for the ThreatLocker module: NOT_CONNECTED gating, tenant
// connection with write-only creds, the six reads, and the write pipeline
// (What-If → execute → change record → revert) against a stateful fake
// portal.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rarity/rtm/internal/auth"
	"github.com/rarity/rtm/internal/config"
	"github.com/rarity/rtm/internal/graph"
	"github.com/rarity/rtm/internal/jobs"
	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/seed"
	"github.com/rarity/rtm/internal/server"
	"github.com/rarity/rtm/internal/store"
	"github.com/rarity/rtm/internal/threatlocker"
)

// fakeTLPortal is a stateful ThreatLocker portal double: device modes and
// approval statuses actually change when the write endpoints are hit, so
// execute/revert can be verified end-to-end.
type fakeTLPortal struct {
	mu              sync.Mutex
	srv             *httptest.Server
	reject          bool
	failAppInsert   bool
	failMerge       bool
	devices         []map[string]any
	requests        []map[string]any
	policies        []map[string]any
	apps            []map[string]any
	computerGroups  []map[string]any
	appFiles        map[string][]map[string]any
	deletedApps     []string
	mergedApps      []string
	appInserts      int
	deletedPolicies []string
	movedPolicies   []string
	deployed        bool
	pathCalls       map[string]int
}

func newFakeTLPortal(t *testing.T) *fakeTLPortal {
	recent := time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339)
	stale := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	f := &fakeTLPortal{
		devices: []map[string]any{
			{"computerId": "dev_1", "computerName": "WS-ALPHA", "group": "Workstations",
				"osType": 1, "serviceVersion": "10.9.1", "mode": "Secure",
				"isTamperProtectionDisabled": false, "lastCheckin": recent, "organizationId": "org-guid"},
			{"computerId": "dev_2", "computerName": "SRV-BRAVO", "group": "Servers",
				"osType": 1, "serviceVersion": "10.8.0", "mode": "Secure",
				"isTamperProtectionDisabled": false, "lastCheckin": stale, "organizationId": "org-guid"},
		},
		requests: []map[string]any{
			{"approvalRequestId": "req_1", "computerId": "dev_1", "hostname": "WS-ALPHA",
				"username": "jdoe", "requestor": "jdoe", "path": "C:\\tools\\putty.exe",
				"hash": "abc123", "requestTypeId": 1, "statusId": 1, "dateTime": "2026-07-01T09:00:00Z"},
		},
		policies: []map[string]any{
			{"policyId": "pol_1", "policyName": "Permit Office", "name": "Permit Office", "policyAction": "Permit",
				"policyActionId": 1, "appliesTo": "WS-ALPHA", "appliesToName": "WS-ALPHA", "computerGroupId": "cg_1",
				"allDevices": false, "allUserGroups": false, "organizationId": "org-guid", "applicationIdList": []string{"app_1"}, "isEnabled": true},
		},
		apps: []map[string]any{
			{"applicationId": "app_parent", "name": "Dell Display Manager", "description": "parent app",
				"organizationId": "org-parent", "organizationName": "Parent", "osType": 1, "status": 1,
				"isBuiltIn": false, "applicationFileCount": 1, "policyCount": 1},
			{"applicationId": "app_1", "name": "Dell Display Manager", "description": "tenant app",
				"organizationId": "org-guid", "organizationName": "Fabrikam", "osType": 1, "status": 1,
				"isBuiltIn": false, "applicationFileCount": 1, "policyCount": 1},
			{"applicationId": "app_2", "name": "Dell Display Manager Helper", "description": "tenant duplicate",
				"organizationId": "org-guid", "organizationName": "Fabrikam", "osType": 1, "status": 1,
				"isBuiltIn": false, "applicationFileCount": 1, "policyCount": 1},
		},
		computerGroups: []map[string]any{
			{"computerGroupId": "cg_global", "computerGroupName": "Global", "organizationId": "org-parent"},
		},
		// Like the live portal, file rows carry no osType or isHashOnly
		// fields, and rules are either hash-only or path/cert.
		appFiles: map[string][]map[string]any{
			"app_parent": {{"applicationFileId": float64(1), "applicationId": "app_parent", "fullPath": "C:\\Program Files\\Dell\\ddm.exe"}},
			"app_1":      {{"applicationFileId": float64(2), "applicationId": "app_1", "fullPath": "C:\\Program Files\\Dell\\ddm.exe"}},
			"app_2": {
				{"applicationFileId": float64(3), "applicationId": "app_2", "fullPath": "C:\\Program Files\\Dell\\helper.exe"},
				{"applicationFileId": float64(4), "applicationId": "app_2", "hash": "662174A7B878FCF2953AEF9D2D12799E"},
			},
		},
		pathCalls: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTLPortal) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rawBody, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(rawBody, &body)
	path := strings.TrimPrefix(r.URL.Path, "/")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	f.pathCalls[path]++
	w.Header().Set("Content-Type", "application/json")
	if f.reject {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API user lacks access to this organization"}`))
		return
	}
	switch path {
	case "Computer/ComputerGetByAllParameters":
		_ = json.NewEncoder(w).Encode(f.devices) // bare array, like the live portal
	case "ApprovalRequest/ApprovalRequestGetByParameters":
		want := int(body["statusId"].(float64))
		out := []map[string]any{}
		for _, q := range f.requests {
			if int(q["statusId"].(int)) == want {
				out = append(out, q)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case "ApprovalRequest/ApprovalRequestGetById", "ApprovalRequest/ApprovalRequestGetPermitApplicationById":
		_ = json.NewEncoder(w).Encode(f.requests[0])
	case "ApprovalRequest/ApprovalRequestPermitApplication":
		f.requests[0]["statusId"] = 2
		_, _ = w.Write([]byte(`{}`))
	case "ApprovalRequest/ApprovalRequestUpdateForReject":
		f.requests[0]["statusId"] = 3
		_, _ = w.Write([]byte(`{}`))
	case "Computer/ComputerDisableProtection":
		typeID := int(body["maintenanceModeType"].(float64))
		f.setMode(body, map[int]string{1: "MonitorOnly", 3: "Learning"}[typeID])
		_, _ = w.Write([]byte(`{}`))
	case "Computer/ComputerEnableProtection":
		f.setMode(body, "Secure")
		_, _ = w.Write([]byte(`{}`))
	case "Computer/ComputerUpdateShouldRestartByIds":
		_, _ = w.Write([]byte(`{}`))
	case "Policy/PolicyGetByParameters":
		_ = json.NewEncoder(w).Encode(f.policies)
	case "Policy/PolicyGetById":
		policyID := r.URL.Query().Get("policyId")
		for _, p := range f.policies {
			if p["policyId"] == policyID {
				// Like the live portal: a policy is only served when the
				// managedOrganizationId header names its owning organization.
				if own, _ := p["organizationId"].(string); own != "" && r.Header.Get("managedOrganizationId") != own {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"Unable to retrieve application policy"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(p)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"policy not found"}`))
	case "Policy/PolicyUpdateById":
		policyID, _ := body["policyId"].(string)
		for i, p := range f.policies {
			if p["policyId"] == policyID {
				for k, v := range body {
					p[k] = v
				}
				if name, _ := p["name"].(string); name != "" {
					p["policyName"] = name
				}
				if all, _ := p["allDevices"].(bool); all {
					p["appliesTo"] = "Global"
					p["appliesToName"] = "Global"
				}
				f.policies[i] = p
				_ = json.NewEncoder(w).Encode(p)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"policy not found"}`))
	case "Policy/PolicyInsert":
		p := map[string]any{}
		for key, value := range body {
			p[key] = value
		}
		p["policyId"] = "pol_new"
		p["policyName"] = body["name"]
		p["organizationId"] = r.Header.Get("managedOrganizationId")
		p["isEnabled"] = true
		if all, _ := body["allDevices"].(bool); all {
			p["appliesTo"] = "Global"
			p["appliesToName"] = "Global"
		}
		f.policies = append(f.policies, p)
		_ = json.NewEncoder(w).Encode(p)
	case "Policy/PolicyGetForViewPoliciesByApplicationId":
		appID, _ := body["applicationId"].(string)
		if app := f.appWithoutLock(appID); app != nil {
			if own, _ := app["organizationId"].(string); own != "" && r.Header.Get("managedOrganizationId") != own {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"Unable to retrieve application policy"}`))
				return
			}
		}
		out := []map[string]any{}
		for _, p := range f.policies {
			for _, id := range stringSliceFromAny(p["applicationIdList"]) {
				if id == appID {
					out = append(out, p)
					break
				}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case "Policy/PolicyGetForPromotePolicyById":
		policyID := r.URL.Query().Get("policyId")
		for _, p := range f.policies {
			if p["policyId"] == policyID {
				_ = json.NewEncoder(w).Encode(p)
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Unable to retrieve application policy"}`))
	case "Policy/ShouldPromoteApplication":
		applicationIDs := stringSliceFromAny(body["applicationIdList"])
		if len(applicationIDs) > 0 {
			if app := f.appWithoutLock(applicationIDs[0]); app != nil {
				if own, _ := app["organizationId"].(string); own != "" && r.Header.Get("managedOrganizationId") != own {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"application validation used the wrong organization"}`))
					return
				}
			}
		}
		_ = json.NewEncoder(w).Encode(false)
	case "PolicyMoveQueue/PolicyMoveQueueInsert":
		policyID, _ := body["policyId"].(string)
		appID, _ := body["applicationId"].(string)
		parentID, _ := body["parentId"].(string)
		groupID, _ := body["newPolicyComputerGroupId"].(string)
		for _, p := range f.policies {
			if p["policyId"] != policyID {
				continue
			}
			p["organizationId"] = parentID
			p["computerGroupId"] = groupID
			p["appliesTo"] = "Global"
			p["appliesToName"] = "Global"
			p["allDevices"] = true
			p["allUserGroups"] = true
			p["applicationIdList"] = []string{appID}
			f.movedPolicies = append(f.movedPolicies, policyID)

			var source map[string]any
			for _, app := range f.apps {
				if app["applicationId"] == appID {
					source = app
					break
				}
			}
			parentExists := false
			for _, app := range f.apps {
				parentExists = parentExists || (source != nil && app["organizationId"] == parentID && app["name"] == source["name"])
			}
			if !parentExists {
				if source != nil {
					parentAppID := "app_promoted_" + appID
					parent := map[string]any{
						"applicationId": parentAppID, "name": source["name"], "description": source["description"],
						"organizationId": parentID, "organizationName": "Parent",
						"osType": source["osType"], "status": 1, "isBuiltIn": false,
					}
					f.apps = append(f.apps, parent)
					f.appFiles[parentAppID] = []map[string]any{}
					p["applicationIdList"] = []string{parentAppID}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"queued": true})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"policy not found"}`))
	case "Policy/PolicyUpdateForDeleteByIds":
		// The live portal wants a bare array of policy rows
		// (List<PolicyTableDto>) at the JSON root.
		var rows []map[string]any
		if err := json.Unmarshal(rawBody, &rows); err != nil || len(rows) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"title":"One or more validation errors occurred.","errors":{"$":["The JSON value could not be converted to System.Collections.Generic.List` + "`" + `1[PortalApi.DTOs.Policy.PolicyTableDto]."]}}`))
			return
		}
		ids := []string{}
		for _, row := range rows {
			// Like the live portal: deletes must be issued in the owning org.
			if own, _ := row["organizationId"].(string); own != "" && r.Header.Get("managedOrganizationId") != own {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"Unable to retrieve application policy"}`))
				return
			}
			// Like the live portal: a copy pushed into a child org by a parent
			// policy ("PARENT\Name") cannot be deleted directly.
			if name, _ := row["name"].(string); strings.Contains(name, `\`) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"You are not authorized to delete policy."}`))
				return
			}
			if id, _ := row["policyId"].(string); id != "" {
				ids = append(ids, id)
			}
		}
		f.deletedPolicies = append(f.deletedPolicies, ids...)
		kept := f.policies[:0]
		for _, p := range f.policies {
			if !stringInSlice(fmt.Sprint(p["policyId"]), ids) {
				kept = append(kept, p)
			}
		}
		f.policies = kept
		_, _ = w.Write([]byte(`{}`))
	case "DeployPolicyQueue/DeployPolicies":
		f.deployed = true
		_, _ = w.Write([]byte(`{}`))
	case "Application/ApplicationGetByParameters":
		orgID := r.Header.Get("managedOrganizationId")
		out := []map[string]any{}
		var includeChildren bool
		if m, ok := body["includeChildOrganizations"].(bool); ok {
			includeChildren = m
		}
		for _, app := range f.apps {
			if app["organizationId"] == orgID || (orgID == "org-parent" && includeChildren) {
				out = append(out, app)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	case "Application/ApplicationGetById":
		appID := r.URL.Query().Get("applicationId")
		for _, app := range f.apps {
			if app["applicationId"] == appID {
				if own, _ := app["organizationId"].(string); own != "" && r.Header.Get("managedOrganizationId") != own {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"application belongs to another organization"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(app)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"application not found"}`))
	case "Application/ApplicationUpdateById":
		appID, _ := body["applicationId"].(string)
		for _, app := range f.apps {
			if app["applicationId"] == appID {
				for k, v := range body {
					app[k] = v
				}
				_ = json.NewEncoder(w).Encode(app)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"application not found"}`))
	case "Application/ApplicationUpdateForMerge":
		if f.failMerge {
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte(`{"message":"merge result is uncertain"}`))
			return
		}
		target, _ := body["targetApplication"].(map[string]any)
		targetID, _ := target["applicationId"].(string)
		merged, _ := body["mergedApplications"].([]any)
		sourceIDs := []string{}
		for _, item := range merged {
			row, _ := item.(map[string]any)
			if id, _ := row["applicationId"].(string); id != "" && id != targetID {
				sourceIDs = append(sourceIDs, id)
			}
		}
		for _, sourceID := range sourceIDs {
			for _, file := range f.appFiles[sourceID] {
				clone := map[string]any{}
				for key, value := range file {
					clone[key] = value
				}
				clone["applicationId"] = targetID
				f.appFiles[targetID] = append(f.appFiles[targetID], clone)
			}
			delete(f.appFiles, sourceID)
		}
		for _, policy := range f.policies {
			ids := stringSliceFromAny(policy["applicationIdList"])
			next := []string{}
			for _, id := range ids {
				if stringInSlice(id, sourceIDs) {
					if !stringInSlice(targetID, next) {
						next = append(next, targetID)
					}
					continue
				}
				next = append(next, id)
			}
			policy["applicationIdList"] = next
		}
		kept := f.apps[:0]
		for _, app := range f.apps {
			if !stringInSlice(fmt.Sprint(app["applicationId"]), sourceIDs) {
				kept = append(kept, app)
			}
		}
		f.apps = kept
		f.mergedApps = append(f.mergedApps, sourceIDs...)
		_ = json.NewEncoder(w).Encode(map[string]any{"merged": true})
	case "Application/ApplicationInsert":
		if f.failAppInsert {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"insert failed"}`))
			return
		}
		f.appInserts++
		id := fmt.Sprintf("app_new_%d", len(f.apps)+1)
		app := map[string]any{
			"applicationId": id, "name": body["name"], "description": body["description"],
			"organizationId": r.Header.Get("managedOrganizationId"), "organizationName": "Parent",
			"osType": body["osType"], "status": 1, "isBuiltIn": false,
		}
		f.apps = append(f.apps, app)
		f.appFiles[id] = []map[string]any{}
		_ = json.NewEncoder(w).Encode(app)
	case "ApplicationFile/ApplicationFileGetByParameters":
		appID, _ := body["applicationId"].(string)
		if app := f.appWithoutLock(appID); app != nil {
			if own, _ := app["organizationId"].(string); own != "" && r.Header.Get("managedOrganizationId") != own {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"application belongs to another organization"}`))
				return
			}
		}
		_ = json.NewEncoder(w).Encode(f.appFiles[appID])
	case "ApplicationFile/ApplicationFileInsert":
		// The live portal rejects inserts without a valid osType, and a rule
		// must be hash-only or carry path/created-by/cert conditions.
		if osType, _ := body["osType"].(float64); osType == 0 {
			w.WriteHeader(http.StatusExpectationFailed)
			_, _ = w.Write([]byte(`{"message":"Invalid Operating System Type"}`))
			return
		}
		hash, _ := body["hash"].(string)
		fullPath, _ := body["fullPath"].(string)
		installedBy, _ := body["installedBy"].(string)
		cert, _ := body["cert"].(string)
		isHashOnly, _ := body["isHashOnly"].(bool)
		hashRule := hash != "" && isHashOnly && fullPath == "" && installedBy == "" && cert == ""
		condRule := hash == "" && (fullPath != "" || installedBy != "" || cert != "")
		if !hashRule && !condRule {
			w.WriteHeader(http.StatusExpectationFailed)
			_, _ = w.Write([]byte(`{"message":"Please enter the Hash only, or enter at least one of the following: Full Path, Created By, Certificate"}`))
			return
		}
		appID, _ := body["applicationId"].(string)
		f.appFiles[appID] = append(f.appFiles[appID], body)
		_, _ = w.Write([]byte(`{}`))
	case "ComputerGroup/ComputerGroupGetDropdownWithOrganization":
		_ = json.NewEncoder(w).Encode(f.computerGroups)
	case "Application/ApplicationUpdateForDelete", "Application/ApplicationConfirmUpdateForDelete":
		// KB shape: {"applications":[{applicationId, name, organizationId,
		// osType}, …]} with every field required.
		apps, _ := body["applications"].([]any)
		ids := []string{}
		for _, v := range apps {
			row, _ := v.(map[string]any)
			id, _ := row["applicationId"].(string)
			name, _ := row["name"].(string)
			org, _ := row["organizationId"].(string)
			osType, _ := row["osType"].(float64)
			if id == "" || name == "" || org == "" || osType == 0 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"title":"One or more validation errors occurred."}`))
				return
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"title":"One or more validation errors occurred."}`))
			return
		}
		f.deletedApps = append(f.deletedApps, ids...)
		kept := f.apps[:0]
		for _, app := range f.apps {
			if !stringInSlice(fmt.Sprint(app["applicationId"]), ids) {
				kept = append(kept, app)
			}
		}
		f.apps = kept
		_, _ = w.Write([]byte(`{}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"unknown endpoint ` + path + `"}`))
	}
}

func stringSliceFromAny(v any) []string {
	switch xs := v.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			out = append(out, fmt.Sprint(x))
		}
		return out
	default:
		return nil
	}
}

func stringInSlice(v string, xs []string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// setMode updates the devices named in a write body's computerDetailDtos.
func (f *fakeTLPortal) setMode(body map[string]any, mode string) {
	refs, _ := body["computerDetailDtos"].([]any)
	for _, r := range refs {
		id := r.(map[string]any)["computerId"]
		for _, d := range f.devices {
			if d["computerId"] == id {
				d["mode"] = mode
			}
		}
	}
}

func (f *fakeTLPortal) deviceMode(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.devices {
		if d["computerId"] == id {
			return d["mode"].(string)
		}
	}
	return ""
}

func (f *fakeTLPortal) setPolicies(policies []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies = policies
}

func (f *fakeTLPortal) setApps(apps []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.apps = apps
}

func (f *fakeTLPortal) setComputerGroups(groups []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.computerGroups = groups
}

// appWithoutLock is only called by handle while the fake portal mutex is
// already held.
func (f *fakeTLPortal) appWithoutLock(id string) map[string]any {
	for _, app := range f.apps {
		if app["applicationId"] == id {
			return app
		}
	}
	return nil
}

func (f *fakeTLPortal) app(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, app := range f.apps {
		if app["applicationId"] == id {
			out := map[string]any{}
			for k, v := range app {
				out[k] = v
			}
			return out
		}
	}
	return nil
}

func (f *fakeTLPortal) insertedAppCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.appInserts
}

func (f *fakeTLPortal) deletedAppIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.deletedApps...)
}

func (f *fakeTLPortal) mergedAppIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.mergedApps...)
}

func (f *fakeTLPortal) deletedPolicyIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.deletedPolicies...)
}

func (f *fakeTLPortal) movedPolicyIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.movedPolicies...)
}

func (f *fakeTLPortal) pathCallCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pathCalls[path]
}

func (f *fakeTLPortal) deployedPolicies() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deployed
}

func (f *fakeTLPortal) policy(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.policies {
		if p["policyId"] == id {
			out := map[string]any{}
			for k, v := range p {
				out[k] = v
			}
			return out
		}
	}
	return nil
}

func (f *fakeTLPortal) policyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.policies)
}

func (f *fakeTLPortal) rejectRequests(reject bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reject = reject
}

// newTestAPIWithTL builds the memory-mode stack with a live ThreatLocker
// client pointed at the fake portal.
func newTestAPIWithTL(t *testing.T) (http.Handler, *store.Mem, *fakeTLPortal) {
	return newTestAPIWithTLParent(t, "org-parent")
}

func newTestAPIWithTLParent(t *testing.T, parentOrgID string) (http.Handler, *store.Mem, *fakeTLPortal) {
	t.Helper()
	portal := newFakeTLPortal(t)
	cfg := &config.Config{
		Env:                     "test",
		CORSOrigin:              "http://localhost:5173",
		ThreatLockerInstance:    "test",
		ThreatLockerToken:       "tl-secret",
		ThreatLockerParentOrgID: parentOrgID,
	}
	log := discardLogger()
	st := store.NewMem()
	gp := graph.NewProvider(graph.Config{}, log, nil)
	tlp := threatlocker.NewProvider(threatlocker.Config{
		BaseURL:     portal.srv.URL,
		Instance:    "test",
		Token:       "tl-secret",
		ParentOrgID: parentOrgID,
	})
	au := auth.NewService(st, []byte("test-signing-key"), log)
	enq := jobs.Inline{Store: st, Graph: gp, ThreatLocker: tlp, Log: log}
	return server.New(cfg, log, st, gp, tlp, au, enq).Handler(), st, portal
}

func newTestAPIWithTLGlobalConfig(t *testing.T) (http.Handler, *store.Mem, *fakeTLPortal) {
	t.Helper()
	portal := newFakeTLPortal(t)
	log := discardLogger()
	st := store.NewMem()
	gp := graph.NewProvider(graph.Config{}, log, nil)
	tlp := threatlocker.NewProvider(threatlocker.Config{BaseURL: portal.srv.URL, GlobalAuth: func(ctx context.Context) (threatlocker.Auth, error) {
		c, err := st.ThreatLockerGlobalConfig(ctx)
		return threatlocker.Auth{Instance: c.Instance, Token: c.Token, OrgID: c.ParentOrgID}, err
	}})
	au := auth.NewService(st, []byte("test-signing-key"), log)
	enq := jobs.Inline{Store: st, Graph: gp, ThreatLocker: tlp, Log: log}
	return server.New(&config.Config{Env: "test", CORSOrigin: "http://localhost:5173"}, log, st, gp, tlp, au, enq).Handler(), st, portal
}

// connectTLTenant creates an ordinary RTM tenant used by workflow tests. The
// ThreatLocker provider itself is configured globally by the test stack.
func connectTLTenant(t *testing.T, h http.Handler, admin string) model.Tenant {
	t.Helper()
	body := `{"name":"Fabrikam","domain":"fabrikam.com","microsoftTenantId":"dir-guid"}`
	var created model.Tenant
	rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, body, &created)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tenant = %d %s", rec.Code, rec.Body.String())
	}
	return created
}

func TestThreatLockerNotConnected(t *testing.T) {
	h, _, _ := newTestAPIWithTLGlobalConfig(t)
	admin := adminToken(t, h)

	rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/devices", admin, "", nil)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "NOT_CONNECTED" {
		t.Fatalf("devices on unconnected tenant = %d %s, want 409 NOT_CONNECTED", rec.Code, rec.Body.String())
	}
	// Writes are gated the same way.
	preview := `{"action":"secure_device","tenantId":"ten_1","deviceIds":["dev_1"]}`
	rec = call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, preview, nil)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "NOT_CONNECTED" {
		t.Fatalf("preview on unconnected tenant = %d %s, want 409 NOT_CONNECTED", rec.Code, rec.Body.String())
	}
}

func TestAdminThreatLockerGlobalConfiguration(t *testing.T) {
	h, st, _ := newTestAPIWithTLGlobalConfig(t)
	admin := adminToken(t, h)

	var status struct {
		Configured      bool   `json:"configured"`
		TokenConfigured bool   `json:"tokenConfigured"`
		Source          string `json:"source"`
		Instance        string `json:"instance"`
		ParentOrgID     string `json:"parentOrganizationId"`
	}
	rec := call(t, h, http.MethodGet, "/api/v1/admin/threatlocker", admin, "", &status)
	if rec.Code != http.StatusOK || status.Configured || status.TokenConfigured || status.Source != "none" {
		t.Fatalf("initial global config = %d %+v", rec.Code, status)
	}

	body := `{"instance":"test","token":"global-token","parentOrganizationId":"org-parent"}`
	rec = call(t, h, http.MethodPut, "/api/v1/admin/threatlocker", admin, body, &status)
	if rec.Code != http.StatusOK || !status.Configured || !status.TokenConfigured || status.Source != "database" || status.Instance != "test" || status.ParentOrgID != "org-parent" {
		t.Fatalf("save global config = %d %+v", rec.Code, status)
	}
	if strings.Contains(rec.Body.String(), "global-token") {
		t.Fatal("global ThreatLocker token leaked into the response")
	}

	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/devices", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("global devices after configuration = %d %s", rec.Code, rec.Body.String())
	}
	entries, err := st.Audit(context.Background())
	foundAudit := false
	for _, entry := range entries {
		foundAudit = foundAudit || entry.Action == "threatlocker.global.configure"
	}
	if err != nil || !foundAudit {
		t.Fatalf("global configuration audit = %+v, %v", entries, err)
	}
}

func TestAdminThreatLockerRejectedReplacementPreservesCurrentConfiguration(t *testing.T) {
	h, st, portal := newTestAPIWithTLGlobalConfig(t)
	admin := adminToken(t, h)

	current := `{"instance":"test","token":"working-token","parentOrganizationId":"org-parent"}`
	if rec := call(t, h, http.MethodPut, "/api/v1/admin/threatlocker", admin, current, nil); rec.Code != http.StatusOK {
		t.Fatalf("initial save = %d %s", rec.Code, rec.Body.String())
	}

	portal.rejectRequests(true)
	replacement := `{"instance":"test","token":"rejected-token","parentOrganizationId":"org-other"}`
	rec := call(t, h, http.MethodPut, "/api/v1/admin/threatlocker", admin, replacement, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rejected replacement = %d %s, want 400", rec.Code, rec.Body.String())
	}

	stored, err := st.ThreatLockerGlobalConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if stored.Token != "working-token" || stored.ParentOrgID != "org-parent" {
		t.Fatalf("stored config changed after rejected replacement: %+v", stored)
	}
}

func TestTenantThreatLockerConfigurationContractIsRetired(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)

	createBody := `{"name":"Fabrikam","domain":"fabrikam.com","microsoftTenantId":"dir-guid","threatLockerOrgId":"org-guid"}`
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, createBody, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant create with ThreatLocker fields = %d %s, want 400", rec.Code, rec.Body.String())
	}

	if rec := call(t, h, http.MethodPut, "/api/v1/tenants/ten_1", admin, `{"threatLockerOrgId":"org-guid"}`, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant settings with ThreatLocker fields = %d %s, want 400", rec.Code, rec.Body.String())
	}

	legacy := `{"threatLockerInstance":"test","threatLockerToken":"token","threatLockerOrgId":"org-guid"}`
	if rec := call(t, h, http.MethodPut, "/api/v1/tenants/ten_1/threatlocker", admin, legacy, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("legacy tenant ThreatLocker endpoint = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

func TestThreatLockerReads(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)
	base := "/api/v1/threatlocker"

	var devices []model.Device
	if rec := call(t, h, http.MethodGet, base+"/devices", admin, "", &devices); rec.Code != http.StatusOK {
		t.Fatalf("devices = %d %s", rec.Code, rec.Body.String())
	}
	if len(devices) != 2 || devices[0].Hostname != "WS-ALPHA" || devices[0].Mode != "secured" {
		t.Fatalf("devices = %+v", devices)
	}

	// dev_1 checked in recently (online); dev_2 is stale (offline).
	if !devices[0].Online || devices[1].Online {
		t.Fatalf("online derivation wrong: %+v", devices)
	}

	var groups []model.DeviceGroup
	call(t, h, http.MethodGet, base+"/device-groups", admin, "", &groups)
	if len(groups) != 2 {
		t.Fatalf("groups = %+v", groups)
	}

	var reqs []model.ApprovalRequest
	call(t, h, http.MethodGet, base+"/approval-requests", admin, "", &reqs)
	if len(reqs) != 1 || reqs[0].Status != "pending" || reqs[0].Application != "putty.exe" {
		t.Fatalf("requests = %+v", reqs)
	}

	var pols []model.TLPolicy
	call(t, h, http.MethodGet, base+"/policies", admin, "", &pols)
	if len(pols) != 1 || pols[0].Action != "permit" || pols[0].Status != "Enabled" {
		t.Fatalf("policies = %+v", pols)
	}

	var tpl model.TLPolicyTemplate
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/policy-templates/promote", admin,
		fmt.Sprintf(`{"tenantId":%q,"policyId":"pol_1"}`, tenant.ID), &tpl)
	if rec.Code != http.StatusOK || tpl.ID == "" {
		t.Fatalf("promote = %d %+v", rec.Code, tpl)
	}
	var deploy model.TLPolicyDeployResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/policy-templates/"+tpl.ID+"/deploy", admin,
		fmt.Sprintf(`{"tenantIds":[%q]}`, tenant.ID), &deploy)
	if rec.Code != http.StatusOK {
		t.Fatalf("deploy = %d %s", rec.Code, rec.Body.String())
	}
	if deploy.Succeeded == nil || deploy.Failed == nil {
		t.Fatalf("deploy slices must be JSON arrays, got succeeded=%#v failed=%#v", deploy.Succeeded, deploy.Failed)
	}
}

func TestThreatLockerPromotePolicyGlobalConsolidatesDuplicates(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.setPolicies([]map[string]any{
		{"policyId": "pol_device", "policyName": "Dell Display and Peripheral Manager (Built-In)", "name": "Dell Display and Peripheral Manager (Built-In)",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "DESKTOP-75V5MS3", "computerGroupId": "cg_desktop",
			"allDevices": false, "allUserGroups": false, "applicationIdList": []string{"app_display"}, "isEnabled": true},
		{"policyId": "pol_group", "policyName": "Dell Display and Peripheral Manager (Built-In)", "name": "Dell Display and Peripheral Manager (Built-In)",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "RSI-PF5RXV9K", "computerGroupId": "cg_group",
			"allDevices": false, "allUserGroups": false, "applicationIdList": []string{"app_peripheral"}, "isEnabled": true},
		{"policyId": "pol_global", "policyName": "Dell Display and Peripheral Manager (Built-In)", "name": "Dell Display and Peripheral Manager (Built-In)",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Global", "computerGroupId": "",
			"allDevices": true, "allUserGroups": true, "applicationIdList": []string{"app_existing"}, "isEnabled": true},
	})

	var result model.TLPolicyConsolidateResult
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/policies/pol_device/promote-global", admin, `{}`, &result)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote global = %d %s", rec.Code, rec.Body.String())
	}
	if result.PolicyID != "pol_device" || result.Status != "Completed" || len(result.MergedPolicyIDs) != 2 || result.DisabledPolicyIDs == nil {
		t.Fatalf("result = %+v", result)
	}
	promoted := portal.policy("pol_device")
	if promoted["allDevices"] != true || promoted["allUserGroups"] != true || promoted["computerGroupId"] != "" || promoted["isEnabled"] != true {
		t.Fatalf("promoted policy not global/enabled: %+v", promoted)
	}
	apps := fmt.Sprint(promoted["applicationIdList"])
	if !strings.Contains(apps, "app_display") || !strings.Contains(apps, "app_peripheral") || !strings.Contains(apps, "app_existing") {
		t.Fatalf("merged apps = %s", apps)
	}
	if portal.policy("pol_group")["isEnabled"] != false || portal.policy("pol_global")["isEnabled"] != false {
		t.Fatalf("duplicates were not disabled: group=%+v global=%+v", portal.policy("pol_group"), portal.policy("pol_global"))
	}
}

func TestThreatLockerDeployTemplateUpdatesExistingPolicyFamily(t *testing.T) {
	h, st, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)
	portal.setPolicies([]map[string]any{
		{"policyId": "pol_source", "policyName": "Dell Touchpad", "name": "Dell Touchpad",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "DESKTOP-A", "computerGroupId": "cg_a",
			"allDevices": false, "allUserGroups": false, "applicationIdList": []string{"app_touchpad"}, "isEnabled": true},
		{"policyId": "pol_duplicate", "policyName": "Dell Touchpad", "name": "Dell Touchpad",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "DESKTOP-B", "computerGroupId": "cg_b",
			"allDevices": false, "allUserGroups": false, "applicationIdList": []string{"app_touchpad_2"}, "isEnabled": true},
	})

	var tpl model.TLPolicyTemplate
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/policy-templates/promote", admin,
		fmt.Sprintf(`{"tenantId":%q,"policyId":"pol_source"}`, tenant.ID), &tpl)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote template = %d %s", rec.Code, rec.Body.String())
	}
	var deploy model.TLPolicyDeployResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/policy-templates/"+tpl.ID+"/deploy", admin,
		fmt.Sprintf(`{"tenantIds":[%q]}`, tenant.ID), &deploy)
	if rec.Code != http.StatusOK || deploy.Status != "Completed" {
		t.Fatalf("deploy = %d %+v %s", rec.Code, deploy, rec.Body.String())
	}
	if got := portal.policyCount(); got != 2 {
		t.Fatalf("policy count = %d, want existing rows only", got)
	}
	if portal.policy("pol_source")["allDevices"] != true || portal.policy("pol_duplicate")["isEnabled"] != false {
		t.Fatalf("deploy did not consolidate existing family: source=%+v duplicate=%+v", portal.policy("pol_source"), portal.policy("pol_duplicate"))
	}
	audit, _ := st.Audit(t.Context())
	foundDeployAudit := false
	for _, a := range audit {
		if a.Action == "threatlocker.policy.template_deploy" && a.Result == "Completed" {
			foundDeployAudit = true
		}
	}
	if !foundDeployAudit {
		t.Fatalf("template deploy audit missing: %+v", audit)
	}
}

func TestThreatLockerAppsListAndRename(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	base := "/api/v1/threatlocker/apps"

	var apps []model.TLApplication
	rec := call(t, h, http.MethodGet, base+"?search=dell", admin, "", &apps)
	if rec.Code != http.StatusOK {
		t.Fatalf("apps list = %d %s", rec.Code, rec.Body.String())
	}
	if len(apps) < 3 {
		t.Fatalf("apps = %+v, want parent and tenant apps", apps)
	}
	var sawParent, sawTenant bool
	for _, app := range apps {
		sawParent = sawParent || app.Source == "parent"
		sawTenant = sawTenant || app.Source == "tenant"
	}
	if !sawParent || !sawTenant {
		t.Fatalf("sources = %+v, want parent and tenant", apps)
	}

	name := "Dell Display Manager - Clean"
	body := fmt.Sprintf(`{"name":%q}`, name)
	var updated model.TLApplicationDetail
	rec = call(t, h, http.MethodPatch, base+"/app_1", admin, body, &updated)
	if rec.Code != http.StatusOK || updated.Name != name {
		t.Fatalf("rename = %d %+v %s", rec.Code, updated, rec.Body.String())
	}
	if portal.app("app_1")["name"] != name {
		t.Fatalf("portal app not renamed: %+v", portal.app("app_1"))
	}

	tech := login(t, h, techEmail, seed.DemoPassword).AccessToken
	rec = call(t, h, http.MethodPatch, base+"/app_1", tech, body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tech rename = %d, want 403", rec.Code)
	}
}

func TestThreatLockerAppsAndCleanupCandidatesShareInventory(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("apps = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps/cleanup-candidates", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("cleanup candidates = %d %s", rec.Code, rec.Body.String())
	}

	portal.mu.Lock()
	calls := portal.pathCalls["Application/ApplicationGetByParameters"]
	portal.mu.Unlock()
	if calls != 1 {
		t.Fatalf("application inventory portal calls = %d, want 1 shared call", calls)
	}
}

func TestThreatLockerAppInventoryForceRefreshBypassesSnapshot(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("apps = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps?refresh=true", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("refreshed apps = %d %s", rec.Code, rec.Body.String())
	}

	portal.mu.Lock()
	calls := portal.pathCalls["Application/ApplicationGetByParameters"]
	portal.mu.Unlock()
	if calls != 2 {
		t.Fatalf("application inventory portal calls = %d, want 2 after forced refresh", calls)
	}
}

func TestThreatLockerAppInventoryDoesNotCachePortalFailure(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	portal.mu.Lock()
	portal.reject = true
	portal.mu.Unlock()
	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps", admin, "", nil); rec.Code == http.StatusOK {
		t.Fatalf("rejected portal request unexpectedly succeeded: %s", rec.Body.String())
	}
	portal.mu.Lock()
	portal.reject = false
	portal.mu.Unlock()
	if rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps", admin, "", nil); rec.Code != http.StatusOK {
		t.Fatalf("retry apps = %d %s", rec.Code, rec.Body.String())
	}

	portal.mu.Lock()
	calls := portal.pathCalls["Application/ApplicationGetByParameters"]
	portal.mu.Unlock()
	if calls != 2 {
		t.Fatalf("application inventory portal calls = %d, want failed call plus retry", calls)
	}
}

func TestThreatLockerAppCleanupRequiresParentOrg(t *testing.T) {
	h, _, _ := newTestAPIWithTLParent(t, "")
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview",
		admin, `{"appIds":["app_1","app_2"]}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("preview without parent org = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

func TestThreatLockerCleanupPreviewDescribesPolicyMovesNotLegacyCreation(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	var preview model.TLAppCleanupPreview
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview", admin,
		`{"appIds":["app_1","app_2"],"retainedAppId":"app_parent","confirmDelete":true}`, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup preview = %d %s", rec.Code, rec.Body.String())
	}
	warnings := strings.Join(preview.Warnings, " ")
	if strings.Contains(warnings, "new global permit policy will be created") ||
		strings.Contains(warnings, "original will be deleted") {
		t.Fatalf("cleanup preview retained legacy policy lifecycle warning: %q", warnings)
	}
	if !strings.Contains(warnings, "moved to the exact Global group") {
		t.Fatalf("cleanup preview policy move warning = %q", warnings)
	}
}

func TestThreatLockerCleanupRequiresPolicyPromotionBeforeNativeMerge(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.setApps([]map[string]any{
		{"applicationId": "app_1", "name": "Dell Display Manager", "description": "first child",
			"organizationId": "org-guid", "organizationName": "Fabrikam", "osType": 1, "status": 1,
			"isBuiltIn": false, "applicationFileCount": 1, "policyCount": 1},
		{"applicationId": "app_2", "name": "Dell Display Manager", "description": "second child",
			"organizationId": "org-child-2", "organizationName": "Contoso", "osType": 1, "status": 1,
			"isBuiltIn": false, "applicationFileCount": 1, "policyCount": 1},
	})
	portal.setPolicies([]map[string]any{
		{"policyId": "pol_1", "policyName": "Dell Display Manager - Fabrikam", "name": "Dell Display Manager - Fabrikam",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Fabrikam Workstations",
			"computerGroupId": "cg_1", "organizationId": "org-guid",
			"applicationIdList": []string{"app_1"}, "isEnabled": true},
		{"policyId": "pol_2", "policyName": "Dell Display Manager - Contoso", "name": "Dell Display Manager - Contoso",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Contoso Workstations",
			"computerGroupId": "cg_2", "organizationId": "org-child-2",
			"applicationIdList": []string{"app_2"}, "isEnabled": true},
	})

	body := `{"appIds":["app_1","app_2"],"retainedAppId":"app_1","name":"Dell Display Manager","confirmDelete":true}`
	appInventoryCalls := portal.pathCallCount("Application/ApplicationGetByParameters")
	var firstPreview map[string]any
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview", admin, body, &firstPreview)
	if rec.Code != http.StatusOK {
		t.Fatalf("first preview = %d %s", rec.Code, rec.Body.String())
	}
	if delta := portal.pathCallCount("Application/ApplicationGetByParameters") - appInventoryCalls; delta != 1 {
		t.Fatalf("cleanup preview application inventory calls = %d, want one shared portfolio read", delta)
	}
	promotion, ok := firstPreview["parentPromotion"].(map[string]any)
	if !ok || promotion["policyId"] != "pol_1" || promotion["applicationId"] != "app_1" ||
		promotion["destinationGroupId"] != "cg_global" || promotion["approvalToken"] == "" {
		t.Fatalf("parent promotion proposal = %+v", firstPreview["parentPromotion"])
	}
	blocked, _ := firstPreview["blocked"].([]any)
	if !strings.Contains(fmt.Sprint(blocked), "parent-owned application") {
		t.Fatalf("first preview blockers = %v", blocked)
	}

	promotionBody, _ := json.Marshal(promotion)
	var promotionResult model.TLAppCleanupResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-parent-promote",
		admin, string(promotionBody), &promotionResult)
	if rec.Code != http.StatusOK || promotionResult.Stage != "parent_promotion" ||
		promotionResult.VerificationStatus != model.TLCleanupVerificationPending {
		t.Fatalf("parent promotion = %d %+v %s", rec.Code, promotionResult, rec.Body.String())
	}
	if portal.insertedAppCount() != 0 || !stringInSlice("pol_1", portal.movedPolicyIDs()) {
		t.Fatalf("parent promotion used wrong lifecycle: inserts=%d moved=%v",
			portal.insertedAppCount(), portal.movedPolicyIDs())
	}

	var secondPreview model.TLAppCleanupPreview
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview", admin, body, &secondPreview)
	if rec.Code != http.StatusOK || secondPreview.RetainedApp.ID == "" ||
		secondPreview.RetainedApp.Source != "parent" || secondPreview.ParentPromotion != nil {
		t.Fatalf("second preview = %d %+v %s", rec.Code, secondPreview, rec.Body.String())
	}
	for _, warning := range secondPreview.Warnings {
		if strings.Contains(warning, "new global permit policy will be created") ||
			strings.Contains(warning, "original will be deleted") {
			t.Fatalf("second preview retained legacy policy lifecycle warning: %q", warning)
		}
	}

	executeBody := strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"approvalToken":%q}`, secondPreview.ApprovalToken)
	var result model.TLAppCleanupResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute",
		admin, executeBody, &result)
	if rec.Code != http.StatusOK || result.Stage != "policy_review" ||
		result.VerificationStatus != model.TLCleanupVerificationPending {
		t.Fatalf("native merge = %d %+v %s", rec.Code, result, rec.Body.String())
	}
	if !stringInSlice("app_1", portal.mergedAppIDs()) || !stringInSlice("app_2", portal.mergedAppIDs()) {
		t.Fatalf("native merge sources = %v", portal.mergedAppIDs())
	}
	if portal.insertedAppCount() != 0 || len(portal.deletedAppIDs()) != 0 || len(portal.deletedPolicyIDs()) != 0 {
		t.Fatalf("legacy create/delete path ran: inserts=%d deletedApps=%v deletedPolicies=%v",
			portal.insertedAppCount(), portal.deletedAppIDs(), portal.deletedPolicyIDs())
	}
	if !stringInSlice("pol_2", portal.movedPolicyIDs()) {
		t.Fatalf("preserved child policy was not queued to Global: %v", portal.movedPolicyIDs())
	}

	var operation model.TLAppCleanupOperation
	rec = call(t, h, http.MethodPost,
		"/api/v1/threatlocker/apps/cleanup-operations/"+result.OperationID+"/verify",
		admin, "", &operation)
	if rec.Code != http.StatusOK || operation.Status != model.TLCleanupVerified ||
		!operation.Result.Verification.Passed {
		t.Fatalf("native cleanup verification = %d %+v %s", rec.Code, operation, rec.Body.String())
	}
}

func TestThreatLockerCleanupFailsClosedWithoutExactGlobalGroup(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.setComputerGroups([]map[string]any{
		{"computerGroupId": "cg_workstations", "computerGroupName": "Workstations", "organizationId": "org-parent"},
	})

	var preview model.TLAppCleanupPreview
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview", admin,
		`{"appIds":["app_1","app_2"],"retainedAppId":"app_parent","confirmDelete":true}`, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview without Global group = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.Join(preview.Blocked, " "), "exact Global") {
		t.Fatalf("preview blockers = %v, want exact Global group blocker", preview.Blocked)
	}
}

func TestThreatLockerCleanupCandidatesRanksParentReadyFamilyFirst(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	var candidates []struct {
		ID                       string                `json:"id"`
		Name                     string                `json:"name"`
		Score                    int                   `json:"score"`
		Confidence               string                `json:"confidence"`
		ParentReady              bool                  `json:"parentReady"`
		RecommendedRetainedAppID string                `json:"recommendedRetainedAppId"`
		Applications             []model.TLApplication `json:"applications"`
		Reasons                  []string              `json:"reasons"`
	}
	rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps/cleanup-candidates",
		admin, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup candidates = %d %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&candidates); err != nil {
		t.Fatalf("decode cleanup candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("cleanup candidates = %+v, want one Dell application family", candidates)
	}
	got := candidates[0]
	if got.Name != "Dell Display Manager" || got.Score < 80 || got.Confidence != "high" ||
		!got.ParentReady || got.RecommendedRetainedAppID != "app_parent" ||
		len(got.Applications) != 3 || len(got.Reasons) == 0 {
		t.Fatalf("ranked cleanup candidate = %+v", got)
	}
}

func TestThreatLockerCleanupVerificationReReadsPortalState(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.setPolicies([]map[string]any{
		{"policyId": "pol_parent", "policyName": "Dell Display Manager", "name": "Dell Display Manager",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Global", "computerGroupId": "",
			"organizationId": "org-parent",
			"allDevices":     true, "allUserGroups": true, "applicationIdList": []string{"app_parent"}, "isEnabled": true},
		{"policyId": "pol_1", "policyName": "Dell Display Manager", "name": "Dell Display Manager",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "WS-ALPHA", "computerGroupId": "cg_1",
			"organizationId": "org-guid", "applicationIdList": []string{"app_1"}, "isEnabled": true},
		{"policyId": "pol_2", "policyName": "Dell Display Manager Helper", "name": "Dell Display Manager Helper",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "WS-BRAVO", "computerGroupId": "cg_2",
			"organizationId": "org-guid", "applicationIdList": []string{"app_2"}, "isEnabled": true},
	})

	body := `{"appIds":["app_1","app_2"],"retainedAppId":"app_parent","retainedPolicyId":"pol_parent","confirmDelete":true}`
	var preview model.TLAppCleanupPreview
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview",
		admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup preview = %d %s", rec.Code, rec.Body.String())
	}
	executeBody := strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"approvalToken":%q}`, preview.ApprovalToken)
	var result model.TLAppCleanupResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute",
		admin, executeBody, &result)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup execute = %d %s", rec.Code, rec.Body.String())
	}

	var verified struct {
		Status string `json:"status"`
		Result struct {
			VerificationStatus string `json:"verificationStatus"`
			Verification       struct {
				Passed bool `json:"passed"`
				Checks []struct {
					Key    string `json:"key"`
					Passed bool   `json:"passed"`
				} `json:"checks"`
			} `json:"verification"`
		} `json:"result"`
	}
	rec = call(t, h, http.MethodPost,
		"/api/v1/threatlocker/apps/cleanup-operations/"+result.OperationID+"/verify",
		admin, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup verify = %d %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&verified); err != nil {
		t.Fatalf("decode cleanup verification: %v", err)
	}
	if verified.Status != model.TLCleanupVerified ||
		verified.Result.VerificationStatus != model.TLCleanupVerified ||
		!verified.Result.Verification.Passed || len(verified.Result.Verification.Checks) < 4 {
		t.Fatalf("verified cleanup = %+v", verified)
	}
	for _, check := range verified.Result.Verification.Checks {
		if !check.Passed {
			t.Fatalf("verification check failed: %+v", check)
		}
	}
}

func TestThreatLockerAppCleanupPreviewAndExecute(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.setPolicies([]map[string]any{
		{"policyId": "pol_parent", "policyName": "Dell Display Manager", "name": "Dell Display Manager",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Global", "computerGroupId": "",
			"organizationId": "org-parent",
			"allDevices":     true, "allUserGroups": true, "applicationIdList": []string{"app_parent"}, "isEnabled": true},
		{"policyId": "pol_1", "policyName": "Dell Display Manager", "name": "Dell Display Manager",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "WS-ALPHA", "computerGroupId": "cg_1",
			"organizationId": "org-guid", "applicationIdList": []string{"app_1"}, "isEnabled": true},
		{"policyId": "pol_2", "policyName": "Dell Display Manager Helper", "name": "Dell Display Manager Helper",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "WS-BRAVO", "computerGroupId": "cg_2",
			"organizationId": "org-guid", "applicationIdList": []string{"app_2"}, "isEnabled": true},
		// A copy the parent policy pushed into a child org: it must survive the
		// cleanup untouched (the portal refuses to delete such rows directly).
		{"policyId": "pol_pushed", "policyName": `PARENT\Dell Display Manager`, "name": `PARENT\Dell Display Manager`,
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Entire Organization", "computerGroupId": "cg_child",
			"organizationId": "org-child", "applicationIdList": []string{"app_parent"}, "isEnabled": true},
	})

	body := `{"appIds":["app_1","app_2"],"retainedAppId":"app_parent","retainedPolicyId":"pol_parent","confirmDelete":true}`
	var preview model.TLAppCleanupPreview
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview",
		admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.RetainedApp.ID != "app_parent" || preview.RetainedPolicy.ID != "pol_parent" ||
		len(preview.DeleteAppIDs) != 2 || len(preview.DeletePolicyIDs) != 0 ||
		len(preview.PreservedPolicies) != 3 || preview.FileRuleCount != 3 {
		t.Fatalf("preview = %+v", preview)
	}
	preservedPolicyIDs := []string{}
	for _, policy := range preview.PreservedPolicies {
		preservedPolicyIDs = append(preservedPolicyIDs, policy.ID)
	}
	if stringInSlice("pol_pushed", preservedPolicyIDs) {
		t.Fatalf("preview marks the parent-pushed child copy for promotion: %+v", preservedPolicyIDs)
	}
	var warnedPushed bool
	for _, wmsg := range preview.Warnings {
		warnedPushed = warnedPushed || strings.Contains(wmsg, `PARENT\Dell Display Manager`)
	}
	if !warnedPushed {
		t.Fatalf("no warning about the parent-pushed copy: %v", preview.Warnings)
	}

	var result model.TLAppCleanupResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute",
		admin, body, &result)
	if rec.Code != http.StatusOK || result.Status != "Completed" {
		t.Fatalf("execute = %d %+v %s", rec.Code, result, rec.Body.String())
	}
	if result.OperationID == "" || result.VerificationStatus != model.TLCleanupVerificationPending {
		t.Fatalf("cleanup lifecycle result = %+v", result)
	}
	var operations []model.TLAppCleanupOperation
	rec = call(t, h, http.MethodGet, "/api/v1/threatlocker/apps/cleanup-operations",
		admin, "", &operations)
	if rec.Code != http.StatusOK || len(operations) != 1 ||
		operations[0].ID != result.OperationID || operations[0].Status != model.TLCleanupVerificationPending {
		t.Fatalf("cleanup operations = %d %+v %s", rec.Code, operations, rec.Body.String())
	}
	rec = call(t, h, http.MethodPost,
		"/api/v1/threatlocker/apps/cleanup-operations/"+result.OperationID+"/reconcile",
		admin, `{"resolution":"verified"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile cleanup = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(t, h, http.MethodGet, "/api/v1/threatlocker/apps/cleanup-operations",
		admin, "", &operations)
	if rec.Code != http.StatusOK || operations[0].Status != model.TLCleanupVerified {
		t.Fatalf("verified cleanup operation = %d %+v %s", rec.Code, operations, rec.Body.String())
	}
	if !stringInSlice("app_1", portal.mergedAppIDs()) || !stringInSlice("app_2", portal.mergedAppIDs()) {
		t.Fatalf("merged apps = %v", portal.mergedAppIDs())
	}
	if !stringInSlice("pol_1", portal.movedPolicyIDs()) || !stringInSlice("pol_2", portal.movedPolicyIDs()) {
		t.Fatalf("moved policies = %v", portal.movedPolicyIDs())
	}
	if stringInSlice("pol_pushed", portal.movedPolicyIDs()) {
		t.Fatalf("parent-pushed child copy was moved directly: %v", portal.movedPolicyIDs())
	}
	if len(portal.deletedAppIDs()) != 0 || len(portal.deletedPolicyIDs()) != 0 {
		t.Fatalf("legacy delete endpoints ran: apps=%v policies=%v", portal.deletedAppIDs(), portal.deletedPolicyIDs())
	}
}

func TestThreatLockerAppCleanupBlocksEquivalentActiveOperation(t *testing.T) {
	h, st, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)
	body := `{"appIds":["app_2","app_1"],"retainedAppId":"app_parent","confirmDelete":true}`

	var preview map[string]any
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview",
		admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	fingerprint, _ := preview["fingerprint"].(string)
	approvalToken, _ := preview["approvalToken"].(string)
	if fingerprint == "" || approvalToken == "" {
		t.Fatalf("preview lifecycle fields = %+v", preview)
	}
	if _, err := st.CreateTLAppCleanupOperation(t.Context(), model.TLAppCleanupOperation{
		ID: "tlop_existing", TenantID: tenant.ID, Status: model.TLCleanupVerificationPending,
		RequestedBy: "Another Admin", Fingerprint: fingerprint,
	}); err != nil {
		t.Fatalf("seed active cleanup: %v", err)
	}

	var result map[string]any
	executeBody := strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"approvalToken":%q}`, approvalToken)
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute",
		admin, executeBody, &result)
	if rec.Code != http.StatusConflict {
		t.Fatalf("equivalent active cleanup = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if len(portal.deletedAppIDs()) != 0 || len(portal.deletedPolicyIDs()) != 0 {
		t.Fatalf("blocked cleanup mutated portal: apps=%v policies=%v", portal.deletedAppIDs(), portal.deletedPolicyIDs())
	}
}

func TestThreatLockerAppCleanupRecordsUncertainOutcome(t *testing.T) {
	h, st, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.failMerge = true
	body := `{"appIds":["app_1","app_2"],"retainedAppId":"app_parent","name":"Canonical DDM","confirmDelete":true}`

	var preview model.TLAppCleanupPreview
	rec := call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview",
		admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	executeBody := strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"approvalToken":%q}`, preview.ApprovalToken)
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute",
		admin, executeBody, nil)
	if rec.Code < 400 {
		t.Fatalf("failed cleanup = %d %s, want error", rec.Code, rec.Body.String())
	}
	operations, err := st.TLAppCleanupOperations(t.Context(), "")
	if err != nil || len(operations) != 1 {
		t.Fatalf("uncertain cleanup operations = %+v, %v", operations, err)
	}
	if operations[0].Status != model.TLCleanupNeedsReconciliation || operations[0].Error == "" {
		t.Fatalf("uncertain cleanup operation = %+v", operations[0])
	}
}

func TestThreatLockerGlobalAppsListAndCleanup(t *testing.T) {
	h, _, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)
	portal.setPolicies([]map[string]any{
		{"policyId": "pol_parent", "policyName": "Dell Display Manager", "name": "Dell Display Manager",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "Global", "computerGroupId": "",
			"organizationId": "org-parent",
			"allDevices":     true, "allUserGroups": true, "applicationIdList": []string{"app_parent"}, "isEnabled": true},
		{"policyId": "pol_1", "policyName": "Dell Display Manager", "name": "Dell Display Manager",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "WS-ALPHA", "computerGroupId": "cg_1",
			"organizationId": "org-guid", "applicationIdList": []string{"app_1"}, "isEnabled": true},
		{"policyId": "pol_2", "policyName": "Dell Display Manager Helper", "name": "Dell Display Manager Helper",
			"policyAction": "Permit", "policyActionId": 1, "appliesToName": "WS-BRAVO", "computerGroupId": "cg_2",
			"organizationId": "org-guid", "applicationIdList": []string{"app_2"}, "isEnabled": true},
	})

	var apps []model.TLApplication
	rec := call(t, h, http.MethodGet, "/api/v1/threatlocker/apps?search=dell", admin, "", &apps)
	if rec.Code != http.StatusOK {
		t.Fatalf("global apps list = %d %s", rec.Code, rec.Body.String())
	}
	if len(apps) < 3 {
		t.Fatalf("global apps = %+v, want parent and child organization apps", apps)
	}
	var sawParent, sawTenant bool
	for _, app := range apps {
		sawParent = sawParent || app.Source == "parent"
		sawTenant = sawTenant || app.Source == "tenant"
	}
	if !sawParent || !sawTenant {
		t.Fatalf("global app sources = %+v", apps)
	}

	body := `{"appIds":["app_1","app_2"],"retainedAppId":"app_parent","retainedPolicyId":"pol_parent","confirmDelete":true}`
	var preview model.TLAppCleanupPreview
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("global cleanup preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.TenantID != "" || preview.RetainedApp.ID != "app_parent" || len(preview.DeleteAppIDs) != 2 {
		t.Fatalf("global preview = %+v", preview)
	}
	var result model.TLAppCleanupResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute", admin, body, &result)
	if rec.Code != http.StatusOK || result.Status != "Completed" {
		t.Fatalf("global cleanup execute = %d %+v %s", rec.Code, result, rec.Body.String())
	}
	if !stringInSlice("app_1", portal.mergedAppIDs()) || !stringInSlice("app_2", portal.mergedAppIDs()) {
		t.Fatalf("global merged apps = %v", portal.mergedAppIDs())
	}
}

// Regression: when the MSP parent org is configured only in the database
// (GUI settings) and RTM_THREATLOCKER_PARENT_ORG_ID is empty, parent-org apps
// must still be labeled "parent" so cleanup reuses the existing parent app by
// name instead of inserting a duplicate — the portal rejects duplicate
// application names per osType.
func TestThreatLockerCleanupReusesParentAppWithDBParentOrg(t *testing.T) {
	h, _, portal := newTestAPIWithTLGlobalConfig(t)
	admin := adminToken(t, h)
	rec := call(t, h, http.MethodPut, "/api/v1/admin/threatlocker", admin,
		`{"instance":"test","token":"tl-secret","parentOrganizationId":"org-parent"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("configure global threatlocker = %d %s", rec.Code, rec.Body.String())
	}
	connectTLTenant(t, h, admin)

	var apps []model.TLApplication
	rec = call(t, h, http.MethodGet, "/api/v1/threatlocker/apps?search=dell", admin, "", &apps)
	if rec.Code != http.StatusOK {
		t.Fatalf("apps list = %d %s", rec.Code, rec.Body.String())
	}
	var sawParent bool
	for _, app := range apps {
		if app.ID == "app_parent" && app.Source == "parent" {
			sawParent = true
		}
	}
	if !sawParent {
		t.Fatalf("app_parent not labeled parent with DB-configured parent org: %+v", apps)
	}

	// No retainedAppId: the retained name defaults to app_1's name, which
	// matches the existing parent app — cleanup must reuse it.
	body := `{"appIds":["app_1","app_2"],"confirmDelete":true}`
	var preview model.TLAppCleanupPreview
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.RetainedApp.ID != "app_parent" || preview.RetainedApp.Source != "parent" {
		t.Fatalf("preview retained app = %+v, want existing app_parent", preview.RetainedApp)
	}
	var result model.TLAppCleanupResult
	rec = call(t, h, http.MethodPost, "/api/v1/threatlocker/apps/cleanup-execute", admin, body, &result)
	if rec.Code != http.StatusOK || result.Status != "Completed" {
		t.Fatalf("execute = %d %+v %s", rec.Code, result, rec.Body.String())
	}
	if result.RetainedAppID != "app_parent" {
		t.Fatalf("retained app = %q, want app_parent", result.RetainedAppID)
	}
	if n := portal.insertedAppCount(); n != 0 {
		t.Fatalf("cleanup inserted %d duplicate app(s), want 0 (reuse app_parent)", n)
	}
}

func TestThreatLockerValidation(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)

	bad := []string{
		// Maintenance needs a valid type and a bounded duration.
		fmt.Sprintf(`{"action":"enter_maintenance_mode","tenantId":%q,"deviceIds":["dev_1"],"maintenanceType":"party","durationMinutes":60}`, tenant.ID),
		fmt.Sprintf(`{"action":"enter_maintenance_mode","tenantId":%q,"deviceIds":["dev_1"],"maintenanceType":"learning"}`, tenant.ID),
		fmt.Sprintf(`{"action":"enter_maintenance_mode","tenantId":%q,"deviceIds":["dev_1"],"maintenanceType":"learning","durationMinutes":9999}`, tenant.ID),
		// Approvals need a valid scope and a parseable expiry.
		fmt.Sprintf(`{"action":"approve_request","tenantId":%q,"approvalRequestIds":["req_1"],"scope":"universe"}`, tenant.ID),
		fmt.Sprintf(`{"action":"approve_request","tenantId":%q,"approvalRequestIds":["req_1"],"scope":"computer","expiresAt":"tomorrow"}`, tenant.ID),
		// Targets are required.
		fmt.Sprintf(`{"action":"secure_device","tenantId":%q}`, tenant.ID),
	}
	for _, body := range bad {
		if rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("preview %s = %d, want 400", body, rec.Code)
		}
	}
	// Tenant creds validation: a token without an org ID is rejected.
	body := `{"name":"X","domain":"x.com","microsoftTenantId":"g","threatLockerToken":"tok"}`
	if rec := call(t, h, http.MethodPost, "/api/v1/tenants", admin, body, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant with token but no org id = %d, want 400", rec.Code)
	}
}

func TestThreatLockerPreviewComputedFromLiveState(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)

	// Securing already-secured devices is a no-op; the offline device warns.
	body := fmt.Sprintf(`{"action":"secure_device","tenantId":%q,"deviceIds":["dev_1","dev_2","ghost"]}`, tenant.ID)
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	if preview.TargetCount != 0 || len(preview.Skipped) != 3 || preview.TargetNoun != "devices" {
		t.Fatalf("preview = %+v", preview)
	}

	// Entering maintenance on a secured device is a real target with a
	// protection-reduced warning.
	body = fmt.Sprintf(`{"action":"enter_maintenance_mode","tenantId":%q,"deviceIds":["dev_2"],"maintenanceType":"monitor_only","durationMinutes":60}`, tenant.ID)
	rec = call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 1 {
		t.Fatalf("maintenance preview = %d %+v", rec.Code, preview)
	}
	warns := strings.Join(preview.Warnings, " | ")
	if !strings.Contains(warns, "offline") || !strings.Contains(warns, "Protection is reduced") {
		t.Fatalf("maintenance warnings = %q", warns)
	}
}

func TestThreatLockerMaintenancePipelineWithRevert(t *testing.T) {
	h, st, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	// Enter Monitor Only maintenance on dev_1.
	body := `{"action":"enter_maintenance_mode","tenantId":"","deviceIds":["dev_1"],"maintenanceType":"monitor_only","durationMinutes":60}`
	var ref model.JobRef
	rec := call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("execute = %d %s", rec.Code, rec.Body.String())
	}
	if job := waitForJob(t, st, ref.JobID); job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}
	if got := portal.deviceMode("dev_1"); got != "MonitorOnly" {
		t.Fatalf("portal device mode = %q, want MonitorOnly", got)
	}

	// The change record supports revert (→ secure_device).
	changes, _ := st.Changes(t.Context())
	if len(changes) != 1 {
		t.Fatalf("changes = %+v", changes)
	}
	detail, _ := st.Change(t.Context(), changes[0].ID)
	if !detail.RevertEligible {
		t.Fatalf("change not revert-eligible: %+v", detail)
	}

	// Revert secures the device and marks the original Reverted.
	rec = call(t, h, http.MethodPost, "/api/v1/changes/revert", admin, fmt.Sprintf(`{"id":%q}`, changes[0].ID), &ref)
	if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("revert = %d %s", rec.Code, rec.Body.String())
	}
	waitForJob(t, st, ref.JobID)
	if got := portal.deviceMode("dev_1"); got != "Secure" {
		t.Fatalf("portal device mode after revert = %q, want Secure", got)
	}
	orig, _ := st.Change(t.Context(), changes[0].ID)
	if orig.Revert != "Reverted" {
		t.Fatalf("original revert = %q, want Reverted", orig.Revert)
	}
	audit, _ := st.Audit(t.Context())
	found := false
	for _, a := range audit {
		if a.Action == "threatlocker.enter_maintenance_mode" && a.Resource == "ThreatLocker MSP workspace" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ThreatLocker execution audit missing: %+v", audit)
	}
}

// Lockdown, isolation, and tamper toggles aren't in the public portal API, so
// executing them fails the job honestly rather than doing something unintended.
func TestThreatLockerUnsupportedActionsFailHonestly(t *testing.T) {
	h, st, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)

	for _, action := range []string{"lockdown_device", "isolate_device", "disable_tamper_protection"} {
		body := fmt.Sprintf(`{"action":%q,"tenantId":%q,"deviceIds":["dev_1"]}`, action, tenant.ID)
		var ref model.JobRef
		rec := call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
		if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
			t.Fatalf("%s execute = %d %s", action, rec.Code, rec.Body.String())
		}
		if job := waitForJob(t, st, ref.JobID); job.Status != "Failed" {
			t.Fatalf("%s job = %+v, want Failed", action, job)
		}
	}
}

func TestThreatLockerApprovalPipeline(t *testing.T) {
	h, st, portal := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	tenant := connectTLTenant(t, h, admin)

	// Approve preview warns that it creates a policy and can't be reverted.
	body := fmt.Sprintf(`{"action":"approve_request","tenantId":%q,"approvalRequestIds":["req_1"],"scope":"computer"}`, tenant.ID)
	var preview model.WhatIfPreview
	rec := call(t, h, http.MethodPost, "/api/v1/changes/preview", admin, body, &preview)
	if rec.Code != http.StatusOK || preview.TargetCount != 1 {
		t.Fatalf("preview = %d %+v", rec.Code, preview)
	}
	if !strings.Contains(strings.Join(preview.Warnings, " "), "cannot be reverted") {
		t.Fatalf("approve warnings = %v", preview.Warnings)
	}

	var ref model.JobRef
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, &ref)
	if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("execute = %d %s", rec.Code, rec.Body.String())
	}
	job := waitForJob(t, st, ref.JobID)
	if job.Status != "Completed" {
		t.Fatalf("job = %+v", job)
	}
	if portal.requests[0]["statusId"] != 2 {
		t.Fatalf("request status = %v, want approved (2)", portal.requests[0]["statusId"])
	}

	// The change is recorded as not revertible.
	changes, _ := st.Changes(t.Context())
	detail, _ := st.Change(t.Context(), changes[0].ID)
	if detail.RevertEligible {
		t.Fatal("approve_request must not be revert-eligible")
	}

	// A second approval attempt on the same request is a no-op (not pending).
	rec = call(t, h, http.MethodPost, "/api/v1/changes/execute", admin, body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("re-approve = %d, want 400 nothing-to-do", rec.Code)
	}
}

func TestThreatLockerPostureReport(t *testing.T) {
	h, _, _ := newTestAPIWithTL(t)
	admin := adminToken(t, h)
	connectTLTenant(t, h, admin)

	var rep model.GlobalReport
	rec := call(t, h, http.MethodGet, "/api/v1/global-reports/threatlocker", admin, "", &rep)
	if rec.Code != http.StatusOK {
		t.Fatalf("report = %d %s", rec.Code, rec.Body.String())
	}
	if len(rep.Columns) == 0 || rep.Columns[0] != "Workspace" {
		t.Fatalf("columns = %v", rep.Columns)
	}
	if len(rep.Rows) != 1 || rep.Rows[0][0].Text != "MSP workspace" || rep.Rows[0][1].Text != "2" {
		t.Fatalf("rows = %+v", rep.Rows)
	}
}
