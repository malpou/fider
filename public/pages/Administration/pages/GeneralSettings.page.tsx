import React, { useState } from "react"

import { Button, ButtonClickEvent, TextArea, Form, Input, ImageUploader } from "@fider/components"
import { HStack } from "@fider/components/layout"
import { AdminPageContainer } from "../components/AdminBasePage"
import { actions, Failure, Fider } from "@fider/services"
import { ImageUpload, TenantMessages, TenantMessagesI18n, visitorLocales } from "@fider/models"
import { useFider } from "@fider/hooks"
import { Trans } from "@lingui/react/macro"

// The four content fields (and their variants) come from page props with the RAW base
// values: fider.session.tenant has the request locale's variants overlaid and must
// never be edited, or an admin browsing in Danish would save overlays into the base.
interface GeneralSettingsPageProps {
  welcomeHeader: string
  welcomeMessage: string
  invitation: string
  descriptionTemplate: string
  messagesI18n: TenantMessagesI18n | null
}

const GeneralSettingsPage = (props: GeneralSettingsPageProps) => {
  const fider = useFider()
  const [title, setTitle] = useState<string>(fider.session.tenant.name)
  const [welcomeMessage, setWelcomeMessage] = useState<string>(props.welcomeMessage)
  const [welcomeHeader, setWelcomeHeader] = useState<string>(props.welcomeHeader)
  const [descriptionTemplate, setDescriptionTemplate] = useState<string>(props.descriptionTemplate)
  const [invitation, setInvitation] = useState<string>(props.invitation)
  const [messagesI18n, setMessagesI18n] = useState<TenantMessagesI18n>(props.messagesI18n || {})
  const [logo, setLogo] = useState<ImageUpload | undefined>(undefined)
  const [cname, setCNAME] = useState<string>(fider.session.tenant.cname)
  // The tenant locale Select is removed: da/en visitor content is handled by the
  // per-locale variants below plus the visitor switcher, so a tenant-wide locale
  // change would only mislead. The saved value still round-trips on save.
  const [locale] = useState<string>(fider.session.tenant.locale)
  const [error, setError] = useState<Failure | undefined>(undefined)

  // The base fields hold the default-language content; the other locale is edited as
  // overrides. The saved tenant locale decides which tab is the base.
  const baseLocale = visitorLocales.some((l) => l.locale === fider.session.tenant.locale) ? fider.session.tenant.locale : "en"
  const [editingLocale, setEditingLocale] = useState<string>(baseLocale)
  const isBaseLocale = editingLocale === baseLocale
  const variant = messagesI18n[editingLocale] || {}

  const setVariantField = (field: keyof TenantMessages) => (value: string) => {
    setMessagesI18n({ ...messagesI18n, [editingLocale]: { ...variant, [field]: value } })
  }

  const fieldValue = (field: keyof TenantMessages, baseValue: string) => (isBaseLocale ? baseValue : variant[field] || "")

  const handleSave = async (e: ButtonClickEvent) => {
    const result = await actions.updateTenantSettings({
      title,
      cname,
      welcomeMessage,
      welcomeHeader,
      descriptionTemplate,
      invitation,
      logo,
      locale,
      messagesI18n,
    })
    if (result.ok) {
      e.preventEnable()
      location.href = `/`
    } else if (result.error) {
      setError(result.error)
    }
  }

  const dnsInstructions = (): JSX.Element => {
    const isApex = cname.split(".").length <= 2
    const recordType = isApex ? "ALIAS" : "CNAME"
    return (
      <>
        <strong>{cname}</strong> {recordType}{" "}
        <strong>
          {fider.session.tenant.subdomain}
          {fider.settings.domain}
        </strong>
      </>
    )
  }

  return (
    <AdminPageContainer id="p-admin-general" name="general" title="General" subtitle="Manage your site settings">
      <Form error={error}>
        <Input field="title" label="Your Fider board's title" maxLength={60} value={title} disabled={!fider.session.user.isAdministrator} onChange={setTitle}>
          <p className="text-muted">Keep it short and snappy. Your product / service name is usually best.</p>
        </Input>

        <div className="field">
          <HStack spacing={2}>
            {visitorLocales.map((l) => (
              <Button key={l.locale} size="small" variant={editingLocale === l.locale ? "primary" : "secondary"} onClick={() => setEditingLocale(l.locale)}>
                {l.text}
              </Button>
            ))}
          </HStack>
          {!isBaseLocale && (
            <p className="text-muted mt-1">
              <Trans id="admin.general.translation.hint">
                You are editing the translations for this language. Empty fields fall back to the default language content below.
              </Trans>
            </p>
          )}
        </div>

        <Input
          field="welcomeHeader"
          label="Welcome Header"
          maxLength={100}
          value={fieldValue("welcomeHeader", welcomeHeader)}
          disabled={!fider.session.user.isAdministrator}
          placeholder="Help us build the _best feedback platform_"
          onChange={isBaseLocale ? setWelcomeHeader : setVariantField("welcomeHeader")}
        >
          <p className="text-muted">
            Large header text shown on the home page. Leave empty to hide. Wrap text with underscores (e.g., _highlighted_) to show it in blue.
          </p>
        </Input>

        <TextArea
          field="welcomeMessage"
          label="Welcome Message"
          value={fieldValue("welcomeMessage", welcomeMessage)}
          disabled={!fider.session.user.isAdministrator}
          onChange={isBaseLocale ? setWelcomeMessage : setVariantField("welcomeMessage")}
        >
          <p className="text-muted">
            The message is shown on this site&apos;s home page. Use it to help visitors understand what this space is about and the importance of their
            feedback.
          </p>
        </TextArea>

        <TextArea
          field="descriptionTemplate"
          label="Default for New Ideas"
          value={fieldValue("descriptionTemplate", descriptionTemplate)}
          disabled={!fider.session.user.isAdministrator}
          onChange={isBaseLocale ? setDescriptionTemplate : setVariantField("descriptionTemplate")}
        >
          <p className="text-muted">If set, all new ideas submitted by users will use this text as the default description.</p>
        </TextArea>

        <Input
          field="invitation"
          label="Invitation"
          maxLength={60}
          value={fieldValue("invitation", invitation)}
          disabled={!fider.session.user.isAdministrator}
          placeholder="Enter your suggestion here..."
          onChange={isBaseLocale ? setInvitation : setVariantField("invitation")}
        >
          <p className="text-muted">Placeholder text in the suggestion&apos;s box. It should invite your visitors into sharing their feedback.</p>
        </Input>

        <ImageUploader label="Your Logo" field="logo" bkey={fider.session.tenant.logoBlobKey} disabled={!fider.session.user.isAdministrator} onChange={setLogo}>
          <p className="text-muted">JPG, GIF or PNG smaller than 100KB, minimum size 200x200 pixels.</p>
        </ImageUploader>

        {!Fider.isSingleHostMode() && (
          <Input
            field="cname"
            label="Custom Domain"
            maxLength={100}
            placeholder="feedback.yourcompany.com"
            value={cname}
            disabled={!fider.session.user.isAdministrator}
            onChange={setCNAME}
          >
            <div className="text-muted">
              {cname ? (
                [
                  <p key={0}>Enter the following record into your DNS zone records:</p>,
                  <p key={1}>{dnsInstructions()}</p>,
                  <p key={2}>Please note that it may take up to 72 hours for the change to take effect worldwide due to DNS propagation.</p>,
                ]
              ) : (
                <p>
                  Use custom domains to access Fider via your own domain name <code>feedback.yourcompany.com</code>
                </p>
              )}
            </div>
          </Input>
        )}

        <div className="field">
          <Button disabled={!fider.session.user.isAdministrator} variant="primary" onClick={handleSave}>
            Save
          </Button>
        </div>
      </Form>
    </AdminPageContainer>
  )
}

export default GeneralSettingsPage
