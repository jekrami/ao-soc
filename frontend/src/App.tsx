import { Routes, Route, Navigate } from 'react-router-dom';
import { TopNav } from '@/components/layout/TopNav';
import { DashboardPage } from '@/pages/DashboardPage';
import { IncidentsListPage } from '@/pages/IncidentsListPage';
import { IncidentDetailsPage } from '@/pages/IncidentDetailsPage';
import { EntityRiskPage } from '@/pages/EntityRiskPage';
import { SystemHealthPage } from '@/pages/SystemHealthPage';
import { APP_VERSION } from '@/version';

export default function App() {
  return (
    <div className="min-h-screen flex flex-col bg-bg text-fg">
      <TopNav />
      <main className="flex-1 px-4 lg:px-6 py-4 lg:py-5 max-w-[1800px] w-full mx-auto">
        <Routes>
          <Route path="/"                        element={<DashboardPage />} />
          <Route path="/incidents"               element={<IncidentsListPage />} />
          <Route path="/incidents/:id"           element={<IncidentDetailsPage />} />
          <Route path="/entities"                element={<EntityRiskPage />} />
          <Route path="/health"                  element={<SystemHealthPage />} />
          <Route path="*"                        element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="border-t border-border py-3 px-4 lg:px-6 text-[11px] text-muted flex items-center justify-between">
        <span>AO-SOC Command Center · v{APP_VERSION}</span>
        <span className="font-mono">Splunk → AI Broker → Local LLM (Qwen) → SOAR</span>
      </footer>
    </div>
  );
}
