import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Archive, Bot, CheckCircle2, ChevronDown, User, XCircle } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { SeverityChip, StatusPill } from '@/components/ui/chip';
import { useAoSoc } from '@/store/useAoSoc';
import { cn } from '@/lib/utils';
import type { ArchivedIncident } from '@/types';

const clearedAt = (inc: ArchivedIncident) =>
  inc.tier2_decision?.completed_at || inc.mitigated_at || inc.updated_at || null;

const fmtWhen = (value: string | null, locale: string) => {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(locale, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
};

export const ArchivePage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { archive, loadArchive, loading } = useAoSoc();
  const [expanded, setExpanded] = useState<string | null>(null);
  const locale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  useEffect(() => { void loadArchive(); }, [loadArchive]);

  const autoCount = useMemo(
    () => archive.filter(i => i.tier2_decision?.approved_by && i.tier2_decision.approved_by !== 'analyst').length,
    [archive]
  );

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-base font-semibold text-fg">{t('archive.title')}</h1>
        <p className="text-[11px] text-muted">{t('archive.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Archive className="h-4 w-4 text-info" />
            <CardTitle>{t('archive.cleared')}</CardTitle>
          </div>
          <CardSubtitle>
            {t('archive.totalSummary', { count: archive.length })}
            {autoCount > 0 ? ` · ${t('archive.autoSummary', { count: autoCount })}` : ''}
          </CardSubtitle>
        </CardHeader>
        <CardBody className="p-0">
          {archive.length === 0 && (
            <div className="text-center text-muted text-sm py-12">
              {loading.archive ? t('archive.loading') : t('archive.empty')}
            </div>
          )}

          <ul>
            {archive.map(inc => {
              const decision = inc.tier2_decision;
              const byAutopilot = Boolean(decision?.approved_by && decision.approved_by !== 'analyst');
              const isOpen = expanded === inc.id;
              const actions = decision?.required_actions ?? [];

              return (
                <li key={inc.id} className="border-b border-border last:border-b-0">
                  <button
                    onClick={() => setExpanded(isOpen ? null : inc.id)}
                    className="w-full text-start px-4 py-3 hover:bg-surface2/40 transition-colors"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityChip severity={inc.severity} />
                      <StatusPill status={inc.status} />
                      {decision && (
                        <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold tracking-wide border border-border bg-surface2/60 text-muted">
                          {decision.decision}
                        </span>
                      )}
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] border',
                          byAutopilot
                            ? 'text-info border-info/40 bg-info/10'
                            : 'text-muted border-border bg-surface2/60'
                        )}
                      >
                        {byAutopilot ? <Bot className="h-3 w-3" /> : <User className="h-3 w-3" />}
                        {byAutopilot ? t('archive.byAutopilot') : t('archive.byAnalyst')}
                      </span>
                      <span className="ms-auto flex items-center gap-3 text-[11px] text-muted">
                        <span className="font-mono">{fmtWhen(clearedAt(inc), locale)}</span>
                        <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', isOpen && 'rotate-180')} />
                      </span>
                    </div>
                    <div className="mt-1.5 text-sm text-fg">
                      <span className="font-mono text-[11px] text-muted me-2">{inc.id}</span>
                      {inc.title}
                    </div>
                  </button>

                  {isOpen && (
                    <div className="px-4 pb-4 space-y-3 bg-surface2/20">
                      {decision?.rationale && (
                        <div className="rounded-md border border-border bg-surface2/40 p-3 text-sm">
                          <div className="text-[11px] uppercase tracking-wide text-muted mb-1">
                            {t('tier2.rationale')}
                          </div>
                          <p className="text-fg/90 leading-relaxed">{decision.rationale}</p>
                        </div>
                      )}

                      <div>
                        <div className="text-[11px] uppercase tracking-wide text-muted mb-2">
                          {t('archive.deliveredActions')} ({actions.length})
                        </div>
                        {actions.length === 0 && (
                          <div className="text-[11px] text-muted">{t('archive.noActions')}</div>
                        )}
                        <div className="space-y-1.5">
                          {actions.map(action => {
                            const ok = action.status === 'DONE';
                            return (
                              <div
                                key={action.id}
                                className="flex items-start gap-2 rounded-md border border-border bg-surface2/40 p-2.5"
                              >
                                {ok
                                  ? <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0 text-low" />
                                  : <XCircle className="h-4 w-4 mt-0.5 shrink-0 text-critical" />}
                                <div className="min-w-0 flex-1">
                                  <div className="text-sm text-fg">
                                    {action.action}
                                    <span className="text-muted"> → </span>
                                    <span className="font-mono text-[12px]">{action.target}</span>
                                  </div>
                                  {action.result?.error && (
                                    <div className="text-[11px] text-critical">{action.result.error}</div>
                                  )}
                                </div>
                                <div className="text-end text-[10px] text-muted shrink-0">
                                  <div>{action.status}</div>
                                  {action.result?.execution_id && (
                                    <div className="font-mono">{action.result.execution_id}</div>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-muted">
                        {decision?.approved_by && (
                          <span>{t('archive.approvedBy')}: <span className="text-fg font-mono">{decision.approved_by}</span></span>
                        )}
                        {decision && (
                          <span>{t('common.confidence')}: <span className="text-fg font-mono">{decision.confidence}%</span></span>
                        )}
                        {decision && (
                          <span>
                            {t('archive.decidedBy')}:{' '}
                            <span className="text-fg">
                              {t(`tier2.source.${decision.decision_source === 'llm' ? 'llm' : 'rules'}`)}
                            </span>
                          </span>
                        )}
                        <Link to={`/incidents/${inc.id}`} className="ms-auto text-info hover:underline">
                          {t('archive.openIncident')}
                        </Link>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};
