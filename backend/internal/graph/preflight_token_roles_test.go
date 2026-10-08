package graph

import (
	"encoding/base64"
	"testing"
)

func TestTokenRoleSetReturnsApplicationRoles(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"https://graph.microsoft.com","roles":["Directory.ReadWrite.All","Sites.ReadWrite.All"]}`))
	roles, err := tokenRoleSet("header." + payload + ".signature")
	if err != nil {
		t.Fatalf("tokenRoleSet: %v", err)
	}
	if _, ok := roles["Directory.ReadWrite.All"]; !ok {
		t.Fatalf("roles = %#v", roles)
	}
	if _, ok := roles["Sites.ReadWrite.All"]; !ok {
		t.Fatalf("roles = %#v", roles)
	}
}

func TestTokenRoleSetRejectsOpaqueToken(t *testing.T) {
	if _, err := tokenRoleSet("opaque-token"); err == nil {
		t.Fatal("tokenRoleSet accepted an opaque token")
	}
}
