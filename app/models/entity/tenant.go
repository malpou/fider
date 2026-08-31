package entity

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/pkg/errors"
)

// Tenant represents a tenant
type Tenant struct {
	ID                  int               `json:"id"`
	Name                string            `json:"name"`
	Subdomain           string            `json:"subdomain"`
	Invitation          string            `json:"invitation"`
	WelcomeMessage      string            `json:"welcomeMessage"`
	WelcomeHeader       string            `json:"welcomeHeader"`
	DescriptionTemplate string            `json:"descriptionTemplate"`
	CNAME               string            `json:"cname"`
	Status              enum.TenantStatus `json:"status"`
	Locale              string            `json:"locale"`
	IsPrivate           bool              `json:"isPrivate"`
	LogoBlobKey         string            `json:"logoBlobKey"`
	CustomCSS           string            `json:"-"`
	AllowedSchemes      string            `json:"allowedSchemes"`
	IsEmailAuthAllowed  bool              `json:"isEmailAuthAllowed"`
	IsFeedEnabled       bool              `json:"isFeedEnabled"`
	PreventIndexing     bool              `json:"preventIndexing"`
	IsModerationEnabled bool              `json:"isModerationEnabled"`
	IsPro               bool              `json:"isPro"`
	// MessagesI18n holds per-locale variants of the tenant-authored content fields.
	// The plain columns are canonical and act as the fallback (default-language content),
	// so variants are never exposed on the public payload; the admin page gets them via props.
	MessagesI18n TenantMessagesI18n `json:"-"`
	// ScheduledDeletionAt is set when the account owner has requested deletion of the whole
	// site. The tenant stays active during the grace window; a background job performs the
	// hard delete once this time passes. Not exposed to clients.
	ScheduledDeletionAt *time.Time `json:"-"`
}

func (t *Tenant) IsDisabled() bool {
	return t.Status == enum.TenantDisabled
}

// TenantMessages is a per-locale variant of the tenant-authored content fields
type TenantMessages struct {
	WelcomeHeader       string `json:"welcomeHeader,omitempty"`
	WelcomeMessage      string `json:"welcomeMessage,omitempty"`
	Invitation          string `json:"invitation,omitempty"`
	DescriptionTemplate string `json:"descriptionTemplate,omitempty"`
}

// TenantMessagesI18n maps a locale code to its tenant message variants
type TenantMessagesI18n map[string]TenantMessages

func (m TenantMessagesI18n) Value() (driver.Value, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return json.Marshal(m)
}

func (m *TenantMessagesI18n) Scan(src any) error {
	if src == nil {
		return nil
	}
	messages, ok := src.([]byte)
	if !ok {
		return errors.New("Invalid data stored in database")
	}
	return json.Unmarshal(messages, &m)
}

// Localized returns the tenant with the given locale's message variants overlaid
// over the base fields, field by field. The base fields are the content for the
// tenant's default locale, so that locale (and any locale without a variant, or an
// empty variant field) falls back to the base values. The receiver is never mutated.
func (t *Tenant) Localized(locale string) *Tenant {
	if t == nil || locale == t.Locale {
		return t
	}
	messages, ok := t.MessagesI18n[locale]
	if !ok {
		return t
	}
	localized := *t
	if messages.WelcomeHeader != "" {
		localized.WelcomeHeader = messages.WelcomeHeader
	}
	if messages.WelcomeMessage != "" {
		localized.WelcomeMessage = messages.WelcomeMessage
	}
	if messages.Invitation != "" {
		localized.Invitation = messages.Invitation
	}
	if messages.DescriptionTemplate != "" {
		localized.DescriptionTemplate = messages.DescriptionTemplate
	}
	return &localized
}

// TenantContact is a reference to an administrator account
type TenantContact struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	Subdomain string `json:"subdomain"`
}
