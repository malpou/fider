package postgres_test

import (
	"testing"

	"github.com/getfider/fider/app/models/query"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
)

// TestOAuthConfig_OIDCFieldsRoundTrip checks that the OIDC columns survive an
// insert, an update and a read back.
func TestOAuthConfig_OIDCFieldsRoundTrip(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	insertCmd := newOAuthConfig("urn:zitadel:iam:org:project:roles", "")
	insertCmd.IssuerURL = "https://idp.test"
	insertCmd.JWKSURL = "https://idp.test/oauth/v2/keys"
	insertCmd.AdminRoles = "fider-admin"
	insertCmd.CollaboratorRoles = "fider-collab"
	err := bus.Dispatch(jonSnowCtx, insertCmd)
	Expect(err).IsNil()

	getConfig := &query.GetCustomOAuthConfigByProvider{Provider: "_TEST_ROLES"}
	err = bus.Dispatch(jonSnowCtx, getConfig)
	Expect(err).IsNil()
	Expect(getConfig.Result.IssuerURL).Equals("https://idp.test")
	Expect(getConfig.Result.JWKSURL).Equals("https://idp.test/oauth/v2/keys")
	Expect(getConfig.Result.AdminRoles).Equals("fider-admin")
	Expect(getConfig.Result.CollaboratorRoles).Equals("fider-collab")
	Expect(getConfig.Result.IsOIDC()).IsTrue()

	updateCmd := newOAuthConfig("urn:zitadel:iam:org:project:roles", "")
	updateCmd.ID = insertCmd.ID
	updateCmd.IssuerURL = "https://other.test"
	updateCmd.JWKSURL = "https://other.test/keys"
	updateCmd.AdminRoles = "fider-admin"
	updateCmd.CollaboratorRoles = "fider-collab"
	err = bus.Dispatch(jonSnowCtx, updateCmd)
	Expect(err).IsNil()

	getConfig = &query.GetCustomOAuthConfigByProvider{Provider: "_TEST_ROLES"}
	err = bus.Dispatch(jonSnowCtx, getConfig)
	Expect(err).IsNil()
	Expect(getConfig.Result.IssuerURL).Equals("https://other.test")
	Expect(getConfig.Result.JWKSURL).Equals("https://other.test/keys")

	listConfigs := &query.ListCustomOAuthConfig{}
	err = bus.Dispatch(jonSnowCtx, listConfigs)
	Expect(err).IsNil()
	Expect(listConfigs.Result).HasLen(1)
	Expect(listConfigs.Result[0].IssuerURL).Equals("https://other.test")
}

// TestOAuthConfig_SecurityStamp_RoleMappingChange checks that changing the role
// mapping (admin_roles/collaborator_roles) while a roles path is configured rotates
// security stamps for all users except the acting one, forcing role re-evaluation.
func TestOAuthConfig_SecurityStamp_RoleMappingChange(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	insertCmd := newOAuthConfig("roles", "")
	insertCmd.AdminRoles = "old-admin-role"
	err := bus.Dispatch(jonSnowCtx, insertCmd)
	Expect(err).IsNil()

	stampsBefore := getSecurityStamps(demoTenant.ID)

	updateCmd := newOAuthConfig("roles", "")
	updateCmd.ID = insertCmd.ID
	updateCmd.AdminRoles = "new-admin-role"
	err = bus.Dispatch(jonSnowCtx, updateCmd)
	Expect(err).IsNil()

	stampsAfter := getSecurityStamps(demoTenant.ID)

	Expect(stampsAfter[aryaStark.ID]).NotEquals(stampsBefore[aryaStark.ID])
	Expect(stampsAfter[sansaStark.ID]).NotEquals(stampsBefore[sansaStark.ID])
	Expect(stampsAfter[jonSnow.ID]).Equals(stampsBefore[jonSnow.ID])
}

// TestOAuthConfig_SecurityStamp_RoleMappingWithoutRolesPath checks that changing the
// role mapping does NOT rotate security stamps when no roles path is configured,
// because mapping cannot take effect without one.
func TestOAuthConfig_SecurityStamp_RoleMappingWithoutRolesPath(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	insertCmd := newOAuthConfig("", "")
	err := bus.Dispatch(jonSnowCtx, insertCmd)
	Expect(err).IsNil()

	stampsBefore := getSecurityStamps(demoTenant.ID)

	updateCmd := newOAuthConfig("", "")
	updateCmd.ID = insertCmd.ID
	updateCmd.AdminRoles = "some-admin-role"
	err = bus.Dispatch(jonSnowCtx, updateCmd)
	Expect(err).IsNil()

	stampsAfter := getSecurityStamps(demoTenant.ID)

	Expect(stampsAfter[jonSnow.ID]).Equals(stampsBefore[jonSnow.ID])
	Expect(stampsAfter[aryaStark.ID]).Equals(stampsBefore[aryaStark.ID])
	Expect(stampsAfter[sansaStark.ID]).Equals(stampsBefore[sansaStark.ID])
}

// TestOAuthConfig_SecurityStamp_RoleMappingCleared checks that clearing the mapping
// entirely does NOT rotate security stamps.
func TestOAuthConfig_SecurityStamp_RoleMappingCleared(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	insertCmd := newOAuthConfig("roles", "")
	insertCmd.AdminRoles = "some-admin-role"
	err := bus.Dispatch(jonSnowCtx, insertCmd)
	Expect(err).IsNil()

	stampsBefore := getSecurityStamps(demoTenant.ID)

	updateCmd := newOAuthConfig("roles", "")
	updateCmd.ID = insertCmd.ID
	err = bus.Dispatch(jonSnowCtx, updateCmd)
	Expect(err).IsNil()

	stampsAfter := getSecurityStamps(demoTenant.ID)

	Expect(stampsAfter[jonSnow.ID]).Equals(stampsBefore[jonSnow.ID])
	Expect(stampsAfter[aryaStark.ID]).Equals(stampsBefore[aryaStark.ID])
	Expect(stampsAfter[sansaStark.ID]).Equals(stampsBefore[sansaStark.ID])
}

// TestCountUsersByRole checks the role-scoped user count used by the last-admin
// demotion guard.
func TestCountUsersByRole(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	countAdmins := &query.CountUsersByRole{Role: jonSnow.Role}
	err := bus.Dispatch(jonSnowCtx, countAdmins)
	Expect(err).IsNil()
	Expect(countAdmins.Result).Equals(1)

	countVisitors := &query.CountUsersByRole{Role: aryaStark.Role}
	err = bus.Dispatch(jonSnowCtx, countVisitors)
	Expect(err).IsNil()
	Expect(countVisitors.Result >= 1).IsTrue()
}
