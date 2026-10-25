import type { LucideIcon } from 'lucide-react';
import {
  Activity, Archive, Database, FileBarChart, FileWarning, Home, LayoutDashboard,
  Radio, ScrollText, Search, Settings, UserCog, Users,
} from 'lucide-react';

export interface NavPage {
  to: string;
  labelKey: string;
  icon: LucideIcon;
  adminOnly?: boolean;
}

export interface NavSection {
  id: string;
  labelKey: string;
  pages: NavPage[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'operations',
    labelKey: 'nav.operations',
    pages: [
      { to: '/', labelKey: 'nav.commandCenter', icon: Home },
      { to: '/alerts', labelKey: 'nav.liveAlerts', icon: Radio },
      { to: '/incidents', labelKey: 'nav.incidents', icon: FileWarning },
      { to: '/archive', labelKey: 'nav.archive', icon: Archive },
      { to: '/entities', labelKey: 'nav.entityRisk', icon: Users },
      { to: '/health', labelKey: 'nav.systemHealth', icon: Activity },
    ],
  },
  {
    id: 'analytics',
    labelKey: 'nav.analytics',
    pages: [
      { to: '/search', labelKey: 'nav.search', icon: Search },
      { to: '/dashboards', labelKey: 'nav.dashboards', icon: LayoutDashboard },
      { to: '/reports', labelKey: 'nav.reports', icon: FileBarChart },
      { to: '/sources', labelKey: 'nav.dataSources', icon: Database },
    ],
  },
  {
    id: 'administration',
    labelKey: 'nav.administration',
    pages: [
      { to: '/audit', labelKey: 'nav.audit', icon: ScrollText },
      { to: '/users', labelKey: 'nav.users', icon: UserCog, adminOnly: true },
      { to: '/settings', labelKey: 'nav.settings', icon: Settings, adminOnly: true },
    ],
  },
];

export function pagesFor(section: NavSection, role: string | undefined): NavPage[] {
  return section.pages.filter(page => !page.adminOnly || role === 'admin');
}

export function sectionForPath(pathname: string, role: string | undefined): NavSection {
  for (const section of NAV_SECTIONS) {
    for (const page of pagesFor(section, role)) {
      const matched = page.to === '/'
        ? pathname === '/'
        : pathname === page.to || pathname.startsWith(`${page.to}/`);
      if (matched) return section;
    }
  }
  return NAV_SECTIONS[0];
}
