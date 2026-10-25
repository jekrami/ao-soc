import { useEffect, useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { LoginGate } from '@/components/layout/LoginGate';
import { SideNav } from '@/components/layout/SideNav';
import { TopNav } from '@/components/layout/TopNav';
import { DashboardPage } from '@/pages/DashboardPage';
import { IncidentsListPage } from '@/pages/IncidentsListPage';
import { IncidentDetailsPage } from '@/pages/IncidentDetailsPage';
import { EntityRiskPage } from '@/pages/EntityRiskPage';
import { SystemHealthPage } from '@/pages/SystemHealthPage';
import { AlertsPage } from '@/pages/AlertsPage';
import { ArchivePage } from '@/pages/ArchivePage';
import { AuditPage } from '@/pages/AuditPage';
import { UsersPage } from '@/pages/UsersPage';
import { SecuritySettingsPage } from '@/pages/SecuritySettingsPage';
import { SearchPage } from '@/pages/SearchPage';
import { DashboardsPage } from '@/pages/DashboardsPage';
import { DashboardViewPage } from '@/pages/DashboardViewPage';
import { ReportsPage } from '@/pages/ReportsPage';
import { DataSourcesPage } from '@/pages/DataSourcesPage';
import { APP_VERSION } from '@/version';
import { getAuthSession, onAuthChange } from '@/lib/authSession';

const AdminOnly: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [role, setRole] = useState(() => getAuthSession()?.role);
  useEffect(() => onAuthChange(() => setRole(getAuthSession()?.role)), []);
  if (role !== 'admin') return <Navigate to="/" replace />;
  return <>{children}</>;
};

export default function App() {
  const { t } = useTranslation();
  const [navOpen, setNavOpen] = useState(false);

  return (
    <LoginGate>
    <div className="min-h-screen flex bg-bg text-fg">
      <SideNav mobileOpen={navOpen} onClose={() => setNavOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
      <TopNav onOpenNav={() => setNavOpen(true)} />
      <main className="flex-1 px-4 lg:px-6 py-4 lg:py-5 max-w-[1800px] w-full mx-auto">
        <Routes>
          <Route path="/"                        element={<DashboardPage />} />
          <Route path="/search"                  element={<SearchPage />} />
          <Route path="/dashboards"              element={<DashboardsPage />} />
          <Route path="/dashboards/:id"          element={<DashboardViewPage />} />
          <Route path="/dashboards/:id/edit"     element={<DashboardViewPage edit />} />
          <Route path="/reports"                 element={<ReportsPage />} />
          <Route path="/alerts"                  element={<AlertsPage />} />
          <Route path="/sources"                 element={<DataSourcesPage />} />
          <Route path="/incidents"               element={<IncidentsListPage />} />
          <Route path="/incidents/:id"           element={<IncidentDetailsPage />} />
          <Route path="/archive"                 element={<ArchivePage />} />
          <Route path="/entities"                element={<EntityRiskPage />} />
          <Route path="/health"                  element={<SystemHealthPage />} />
          <Route path="/audit"                   element={<AuditPage />} />
          <Route path="/users"                   element={<AdminOnly><UsersPage /></AdminOnly>} />
          <Route path="/settings"                element={<AdminOnly><SecuritySettingsPage /></AdminOnly>} />
          <Route path="*"                        element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="border-t border-border py-3 px-4 lg:px-6 text-[11px] text-muted flex items-center justify-between">
        <span>{t('footer.title')} · v{APP_VERSION}</span>
        <span className="font-mono">{t('footer.pipeline')}</span>
      </footer>
      </div>
    </div>
    </LoginGate>
  );
}
