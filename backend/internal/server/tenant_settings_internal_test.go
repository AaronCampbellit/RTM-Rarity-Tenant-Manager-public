package server

import (
	"testing"

	"github.com/rarity/rtm/internal/model"
	"github.com/rarity/rtm/internal/store"
)

func TestGraphSettingsChangedIgnoresUnchangedVisibleMetadata(t *testing.T) {
	name, domain, directory := "Contoso", "contoso.com", "dir-1"
	body := tenantSettingsRequest{Name: &name, Domain: &domain, MicrosoftTenantID: &directory}
	tenant := model.Tenant{Name: name, Domain: domain, MicrosoftTenantID: directory}
	creds := store.TenantCreds{Domain: domain, MicrosoftTenantID: directory, ClientID: "app"}
	if graphSettingsChanged(body, tenant, creds) {
		t.Fatal("unchanged visible metadata triggered a Graph connection test")
	}
	directory = "dir-2"
	if !graphSettingsChanged(body, tenant, creds) {
		t.Fatal("changed directory did not trigger a Graph connection test")
	}
}
