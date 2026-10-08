package graph

import "testing"

func TestResolveEffectiveGrant(t *testing.T) {
	tests := []struct {
		name, resource, required string
		assigned                 []string
		status, via              string
	}{
		{"exact", "Microsoft Graph", "User.ReadWrite.All", []string{"User.ReadWrite.All"}, "ok", ""},
		{"directory write parent", "Microsoft Graph", "User.ReadWrite.All", []string{"Directory.ReadWrite.All"}, "ok", "Directory.ReadWrite.All"},
		{"directory read parent", "Microsoft Graph", "GroupMember.Read.All", []string{"Directory.Read.All"}, "ok", "Directory.Read.All"},
		{"group write parent", "Microsoft Graph", "GroupMember.Read.All", []string{"Group.ReadWrite.All"}, "ok", "Group.ReadWrite.All"},
		{"directory role read parent", "Microsoft Graph", "RoleManagement.Read.Directory", []string{"Directory.ReadWrite.All"}, "ok", "Directory.ReadWrite.All"},
		{"missing", "Microsoft Graph", "Sites.ReadWrite.All", []string{"User.Read.All"}, "missing", ""},
		{"no cross resource", "SharePoint Online", "Sites.FullControl.All", []string{"Directory.ReadWrite.All"}, "missing", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assigned := map[string]struct{}{}
			for _, permission := range tt.assigned {
				assigned[permission] = struct{}{}
			}
			status, via := resolveEffectiveGrant(tt.resource, tt.required, assigned)
			if status != tt.status || via != tt.via {
				t.Fatalf("resolveEffectiveGrant() = %q, %q; want %q, %q", status, via, tt.status, tt.via)
			}
		})
	}
}
