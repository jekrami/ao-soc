import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAoSoc } from '@/store/useAoSoc';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { SeverityChip, StatusPill, RiskBadge } from '@/components/ui/chip';
import { Link } from 'react-router-dom';
import { ArrowRight, AlertOctagon } from 'lucide-react';

export const IncidentsListPage: React.FC = () => {
  const { t } = useTranslation();
  const { incidents, loadIncidents, summary } = useAoSoc();

  useEffect(() => { void loadIncidents(true); }, [loadIncidents]);

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-base font-semibold text-fg">{t('incidents.title')}</h1>
        <p className="text-[11px] text-muted">{t('incidents.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-info" />
            <CardTitle>{t('incidents.queue')}</CardTitle>
          </div>
          <CardSubtitle>
            {t('incidents.totalSummary', { count: incidents.length })}
            {summary?.demo_incidents ? ` · ${summary.demo_incidents} ${t('common.demoCount')}` : ''}
          </CardSubtitle>
        </CardHeader>
        <CardBody className="p-0">
          <div className="hidden md:grid grid-cols-12 px-4 py-2 text-[11px] uppercase tracking-wider text-muted border-b border-border">
            <div className="col-span-2">{t('common.severity')}</div>
            <div className="col-span-2">{t('common.status')}</div>
            <div className="col-span-5">{t('common.title')}</div>
            <div className="col-span-1 text-end">{t('common.risk')}</div>
            <div className="col-span-1 text-end">{t('common.conf')}</div>
            <div className="col-span-1 text-end">{t('common.open')}</div>
          </div>
          <ul>
            {incidents.map(inc => (
              <li key={inc.id} className="border-b border-border last:border-b-0">
                <Link
                  to={`/incidents/${inc.id}`}
                  className="flex flex-col gap-2 px-4 py-3 hover:bg-surface2/50 transition-colors md:grid md:grid-cols-12 md:items-center md:gap-3"
                >
                  {/* Mobile: stacked card */}
                  <div className="flex flex-wrap items-center gap-2 md:hidden">
                    <SeverityChip severity={inc.severity} />
                    {inc.source === 'broker' && (
                      <span className="rounded px-1 py-0.5 text-[9px] font-semibold bg-info/15 text-info border border-info/30">{t('common.live')}</span>
                    )}
                    {inc.source === 'mock' && (
                      <span className="rounded px-1 py-0.5 text-[9px] font-semibold bg-muted/15 text-muted border border-border">{t('common.demo')}</span>
                    )}
                    <StatusPill status={inc.status} />
                    <span className="ms-auto"><RiskBadge score={inc.risk_score} /></span>
                  </div>
                  <div className="text-sm text-fg md:hidden">
                    <span className="font-mono text-[11px] text-muted block mb-0.5">{inc.id}</span>
                    <span className="line-clamp-2">{inc.title}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted md:hidden">
                    <span>{t('common.conf')} <span className="font-mono text-fg">{inc.confidence}%</span></span>
                    <ArrowRight className="h-3.5 w-3.5 text-muted rtl:rotate-180" />
                  </div>

                  {/* Desktop: table columns */}
                  <div className="hidden md:flex col-span-2 items-center gap-1.5">
                    <SeverityChip severity={inc.severity} />
                    {inc.source === 'broker' && (
                      <span className="rounded px-1 py-0.5 text-[9px] font-semibold bg-info/15 text-info border border-info/30">{t('common.live')}</span>
                    )}
                    {inc.source === 'mock' && (
                      <span className="rounded px-1 py-0.5 text-[9px] font-semibold bg-muted/15 text-muted border border-border">{t('common.demo')}</span>
                    )}
                  </div>
                  <div className="hidden md:block col-span-2"><StatusPill status={inc.status} /></div>
                  <div className="hidden md:block col-span-5 text-sm text-fg truncate">
                    <span className="font-mono text-[11px] text-muted me-2">{inc.id}</span>
                    {inc.title}
                  </div>
                  <div className="hidden md:block col-span-1 text-end"><RiskBadge score={inc.risk_score} /></div>
                  <div className="hidden md:block col-span-1 text-end font-mono text-sm text-muted">{inc.confidence}%</div>
                  <div className="hidden md:block col-span-1 text-end">
                    <ArrowRight className="h-3.5 w-3.5 text-muted inline rtl:rotate-180" />
                  </div>
                </Link>
              </li>
            ))}
            {incidents.length === 0 && (
              <li className="text-center text-muted text-sm py-12">{t('incidents.empty')}</li>
            )}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};
