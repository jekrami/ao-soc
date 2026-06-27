import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import en from './locales/en.json';
import fa from './locales/fa.json';

export const LOCALE_STORAGE_KEY = 'ao-soc-locale';
export const SUPPORTED_LOCALES = ['en', 'fa'] as const;
export type AppLocale = (typeof SUPPORTED_LOCALES)[number];

export function isRtl(locale: string): boolean {
  return locale === 'fa';
}

export function setDocumentLocale(locale: AppLocale): void {
  document.documentElement.lang = locale;
  document.documentElement.dir = isRtl(locale) ? 'rtl' : 'ltr';
}

function readSavedLocale(): AppLocale {
  const saved = localStorage.getItem(LOCALE_STORAGE_KEY);
  if (saved === 'fa' || saved === 'en') return saved;
  return 'en';
}

const initialLocale = readSavedLocale();
setDocumentLocale(initialLocale);

void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    fa: { translation: fa },
  },
  lng: initialLocale,
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
});

export async function setLocale(locale: AppLocale): Promise<void> {
  await i18n.changeLanguage(locale);
  localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  setDocumentLocale(locale);
}

export default i18n;
