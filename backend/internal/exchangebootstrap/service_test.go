package exchangebootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBootstrapCreatesExactOneUseAssignment(t *testing.T) {
	var (
		mu             sync.Mutex
		assignmentBody map[string]any
		offlineAsked   bool
		pkceVerifier   string
	)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(r.Form.Get("scope"), "offline_access") {
				offlineAsked = true
			}
			if r.Form.Get("grant_type") == "authorization_code" {
				if r.Form.Get("client_id") != "11111111-1111-1111-1111-111111111111" || r.Form.Get("client_secret") != "bootstrap-secret" || r.Form.Get("redirect_uri") != "https://rtm.example/api/v1/microsoft/exchange/bootstrap/callback" {
					t.Fatalf("one-time bootstrap credentials were not used: %v", r.Form)
				}
				pkceVerifier = r.Form.Get("code_verifier")
				json.NewEncoder(w).Encode(map[string]string{"access_token": "delegated-secret"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": testJWT(map[string]string{"oid": "sp-object", "tid": "directory-1", "appid": "runtime-client"})})
		case strings.HasSuffix(r.URL.Path, "/roleDefinitions"):
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "role-1", "displayName": roleName, "isBuiltIn": true, "isEnabled": true}}})
		case strings.HasSuffix(r.URL.Path, "/roleAssignments") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		case strings.HasSuffix(r.URL.Path, "/roleAssignments") && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			defer mu.Unlock()
			if err := json.Unmarshal(body, &assignmentBody); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": "assignment-1"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer fake.Close()

	service := New(Config{LoginBase: fake.URL, GraphBase: fake.URL, HTTPClient: fake.Client()}, func(context.Context, string) (RuntimeAuth, error) {
		return RuntimeAuth{DirectoryID: "directory-1", ClientID: "runtime-client", ClientSecret: "runtime-secret"}, nil
	})
	start, err := service.Start(testStartInput())
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if authorizeURL.Path != "/directory-1/oauth2/v2.0/authorize" {
		t.Fatalf("authority path = %s", authorizeURL.Path)
	}
	if strings.Contains(authorizeURL.Query().Get("scope"), "offline_access") {
		t.Fatal("authorization requested offline_access")
	}
	if authorizeURL.Query().Get("code_challenge_method") != "S256" || authorizeURL.Query().Get("code_challenge") == "" {
		t.Fatal("PKCE challenge missing")
	}
	if authorizeURL.Query().Get("response_mode") != "form_post" {
		t.Fatalf("response mode = %q", authorizeURL.Query().Get("response_mode"))
	}
	if authorizeURL.Query().Get("client_id") != "11111111-1111-1111-1111-111111111111" || authorizeURL.Query().Get("redirect_uri") != "https://rtm.example/api/v1/microsoft/exchange/bootstrap/callback" {
		t.Fatalf("authorize query = %v", authorizeURL.Query())
	}
	state := authorizeURL.Query().Get("state")
	service.mu.Lock()
	retained := service.pending[state]
	service.mu.Unlock()

	result, err := service.Complete(t.Context(), state, "auth-code")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.ActorName != "Aaron" {
		t.Fatalf("completion = %+v", result)
	}
	if len(retained.BootstrapClientSecret) != 0 || retained.BootstrapClientID != "" || retained.RedirectURL != "" {
		t.Fatal("one-time bootstrap credentials remained after callback")
	}
	if offlineAsked || pkceVerifier == "" {
		t.Fatalf("offline=%v verifier=%q", offlineAsked, pkceVerifier)
	}
	mu.Lock()
	defer mu.Unlock()
	if assignmentBody["principalId"] != "/ServicePrincipals/sp-object" || assignmentBody["roleDefinitionId"] != "role-1" || assignmentBody["directoryScopeId"] != "/" || assignmentBody["appScopeId"] != nil {
		t.Fatalf("assignment body = %#v", assignmentBody)
	}
	if _, err := service.Complete(t.Context(), state, "auth-code"); !errorsIs(err, ErrInvalidState) {
		t.Fatalf("state was reusable: %v", err)
	}
}

func TestBootstrapKeepsExistingAssignmentAndRejectsWrongRuntimeIdentity(t *testing.T) {
	posts := 0
	wrongIdentity := false
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			r.ParseForm()
			if r.Form.Get("grant_type") == "authorization_code" {
				json.NewEncoder(w).Encode(map[string]string{"access_token": "delegated"})
				return
			}
			clientID := "runtime-client"
			if wrongIdentity {
				clientID = "different-client"
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": testJWT(map[string]string{"oid": "sp-object", "tid": "directory-1", "appid": clientID})})
		case strings.HasSuffix(r.URL.Path, "/roleDefinitions"):
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "role-1", "displayName": roleName, "isBuiltIn": true, "isEnabled": true}}})
		case strings.HasSuffix(r.URL.Path, "/roleAssignments") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"roleDefinitionId": "role-1", "principalId": "/ServicePrincipals/sp-object", "directoryScopeId": "/"}}})
		case strings.HasSuffix(r.URL.Path, "/roleAssignments") && r.Method == http.MethodPost:
			posts++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer fake.Close()
	service := New(Config{LoginBase: fake.URL, GraphBase: fake.URL, HTTPClient: fake.Client()}, func(context.Context, string) (RuntimeAuth, error) {
		return RuntimeAuth{DirectoryID: "directory-1", ClientID: "runtime-client", ClientSecret: "runtime-secret"}, nil
	})

	start, _ := service.Start(testStartInput())
	state, _ := url.Parse(start.AuthorizationURL)
	result, err := service.Complete(t.Context(), state.Query().Get("state"), "code")
	if err != nil || result.Created || posts != 0 {
		t.Fatalf("existing assignment result=%+v posts=%d err=%v", result, posts, err)
	}

	wrongIdentity = true
	start, _ = service.Start(testStartInput())
	state, _ = url.Parse(start.AuthorizationURL)
	if _, err := service.Complete(t.Context(), state.Query().Get("state"), "code"); err == nil || !strings.Contains(err.Error(), "did not match") {
		t.Fatalf("wrong runtime identity accepted: %v", err)
	}
}

func TestBootstrapCredentialsArePurgedOnExpiry(t *testing.T) {
	service := New(Config{StateTTL: 15 * time.Millisecond}, func(context.Context, string) (RuntimeAuth, error) {
		return RuntimeAuth{}, nil
	})
	start, err := service.Start(testStartInput())
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, _ := url.Parse(start.AuthorizationURL)
	state := authorizeURL.Query().Get("state")
	service.mu.Lock()
	retained := service.pending[state]
	service.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		service.mu.Lock()
		_, exists := service.pending[state]
		service.mu.Unlock()
		if !exists {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	service.mu.Lock()
	_, exists := service.pending[state]
	service.mu.Unlock()
	if exists || len(retained.BootstrapClientSecret) != 0 || retained.BootstrapClientID != "" {
		t.Fatal("expired one-time bootstrap credentials were not purged")
	}
}

func testStartInput() StartInput {
	return StartInput{
		TenantID: "tenant-1", TenantName: "Campbellservers", DirectoryID: "directory-1",
		ActorID: "admin-1", ActorName: "Aaron",
		BootstrapClientID:     "11111111-1111-1111-1111-111111111111",
		BootstrapClientSecret: []byte("bootstrap-secret"),
		RedirectURL:           "https://rtm.example/api/v1/microsoft/exchange/bootstrap/callback",
	}
}

func testJWT(claims map[string]string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func errorsIs(err, target error) bool { return err == target }
