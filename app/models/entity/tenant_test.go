package entity_test

import (
	"testing"

	"github.com/getfider/fider/app/models/entity"
	. "github.com/getfider/fider/app/pkg/assert"
)

func newLocalizableTenant() *entity.Tenant {
	return &entity.Tenant{
		Locale:              "en",
		WelcomeHeader:       "Welcome!",
		WelcomeMessage:      "Tell us what you think.",
		Invitation:          "Enter your suggestion here...",
		DescriptionTemplate: "Describe your idea",
		MessagesI18n: entity.TenantMessagesI18n{
			"da": {
				WelcomeHeader: "Velkommen!",
				Invitation:    "Skriv dit forslag her...",
			},
		},
	}
}

func TestTenant_Localized_VariantWins(t *testing.T) {
	RegisterT(t)

	tenant := newLocalizableTenant()
	localized := tenant.Localized("da")

	Expect(localized.WelcomeHeader).Equals("Velkommen!")
	Expect(localized.Invitation).Equals("Skriv dit forslag her...")

	// missing variant fields fall back to the base values
	Expect(localized.WelcomeMessage).Equals("Tell us what you think.")
	Expect(localized.DescriptionTemplate).Equals("Describe your idea")

	// the receiver is never mutated
	Expect(tenant.WelcomeHeader).Equals("Welcome!")
}

func TestTenant_Localized_FallbackToBase(t *testing.T) {
	RegisterT(t)

	tenant := newLocalizableTenant()

	// the tenant's own locale always gets the base content, even if a stale variant exists
	tenant.MessagesI18n["en"] = entity.TenantMessages{WelcomeHeader: "Stale override"}
	Expect(tenant.Localized("en")).Equals(tenant)

	// a locale without a variant falls back to the base content
	Expect(tenant.Localized("pt-BR")).Equals(tenant)

	// an invalid locale is ignored
	Expect(tenant.Localized("not-a-locale")).Equals(tenant)

	// a tenant without variants is returned as-is
	tenant.MessagesI18n = nil
	Expect(tenant.Localized("da")).Equals(tenant)
}
