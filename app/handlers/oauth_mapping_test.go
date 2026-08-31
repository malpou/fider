package handlers

// Internal test file for resolveMappedRole — uses package handlers (not handlers_test)
// so the unexported function is accessible without exporting it.

import (
	"testing"

	"github.com/getfider/fider/app/models/enum"
)

func expectMappedRole(t *testing.T, userRoles []string, adminRoles, collaboratorRoles string, expectedRole enum.Role, expectedMapped bool) {
	t.Helper()
	role, mapped := resolveMappedRole(userRoles, adminRoles, collaboratorRoles)
	if role != expectedRole || mapped != expectedMapped {
		t.Errorf("resolveMappedRole(%v, %q, %q) = (%v, %v), expected (%v, %v)",
			userRoles, adminRoles, collaboratorRoles, role, mapped, expectedRole, expectedMapped)
	}
}

func TestResolveMappedRole_NoMappingConfigured(t *testing.T) {
	expectMappedRole(t, []string{"admin"}, "", "", enum.RoleVisitor, false)
	expectMappedRole(t, nil, "", "", enum.RoleVisitor, false)
	expectMappedRole(t, []string{"admin"}, " , ", " ", enum.RoleVisitor, false)
}

func TestResolveMappedRole_AdminMatch(t *testing.T) {
	expectMappedRole(t, []string{"admin"}, "admin", "", enum.RoleAdministrator, true)
	expectMappedRole(t, []string{"user", "admin"}, "admin, superuser", "member", enum.RoleAdministrator, true)
}

func TestResolveMappedRole_CollaboratorMatch(t *testing.T) {
	expectMappedRole(t, []string{"member"}, "admin", "member", enum.RoleCollaborator, true)
	expectMappedRole(t, []string{"member"}, "", "member, support", enum.RoleCollaborator, true)
}

func TestResolveMappedRole_AdminWinsOverCollaborator(t *testing.T) {
	// A user matching both lists gets the higher role, regardless of role order.
	expectMappedRole(t, []string{"member", "admin"}, "admin", "member", enum.RoleAdministrator, true)
	expectMappedRole(t, []string{"both"}, "both", "both", enum.RoleAdministrator, true)
}

func TestResolveMappedRole_NoMatchIsVisitor(t *testing.T) {
	expectMappedRole(t, []string{"guest"}, "admin", "member", enum.RoleVisitor, true)
	expectMappedRole(t, nil, "admin", "member", enum.RoleVisitor, true)
}

func TestResolveMappedRole_TrimsWhitespace(t *testing.T) {
	expectMappedRole(t, []string{" admin "}, " admin ,  superuser ", "", enum.RoleAdministrator, true)
	expectMappedRole(t, []string{"member"}, "admin", "  member  ", enum.RoleCollaborator, true)
}

func TestResolveMappedRole_CaseSensitive(t *testing.T) {
	expectMappedRole(t, []string{"Admin"}, "admin", "", enum.RoleVisitor, true)
}
