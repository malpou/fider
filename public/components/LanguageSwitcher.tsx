import IconGlobe from "@fider/assets/images/lucide-globe.svg"
import React from "react"
import { Dropdown, Icon } from "./common"
import { useFider } from "@fider/hooks"
import { visitorLocales } from "@fider/models"

export const LanguageSwitcher = () => {
  const fider = useFider()

  const changeLanguage = (locale: string) => () => {
    if (locale === fider.currentLocale) {
      return
    }
    document.cookie = `locale=${locale}; path=/; max-age=31536000; SameSite=Lax`
    window.location.reload()
  }

  return (
    <Dropdown position="left" renderHandle={<Icon sprite={IconGlobe} className="h-6 text-gray-500" />}>
      {visitorLocales.map((language) => (
        <Dropdown.ListItem
          key={language.locale}
          onClick={changeLanguage(language.locale)}
          className={language.locale === fider.currentLocale ? "text-semibold" : ""}
        >
          {language.text}
        </Dropdown.ListItem>
      ))}
    </Dropdown>
  )
}
