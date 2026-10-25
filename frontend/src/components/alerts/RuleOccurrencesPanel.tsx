import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import { SeverityChip } from '@/components/ui/chip';
import { listAlertOccurrences, listAlertRules } from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';

export const RuleOccurrencesPanel: React.FC = () => {
  const { t } = useTranslation();
  const { data: occ = [] } = useQuery({
    queryKey: queryKeys.alertOccurrences,
    queryFn: () => listAlertOccurrences(100),
  });
  const { data: rules = [] } = useQuery({
    queryKey: queryKeys.alertRules,
    queryFn: listAlertRules,
  });
  const byId = Object.fromEntries(rules.map(r => [r.id, r]));

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('workspace.alertsPage.ruleOccurrence')}</CardTitle>
        <CardSubtitle>{occ.length}</CardSubtitle>
      </CardHeader>
      <CardBody className="p-0">
        <ul>
          {occ.map(o => {
            const rule = byId[o.rule_id];
            return (
              <li key={o.id} className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-border last:border-0">
                <span className="chip chip-info" title={t('workspace.alertsPage.ruleOccurrence')}>
                  {t('workspace.alertsPage.ruleOccurrence')}
                </span>
                <SeverityChip severity={o.severity} />
                <div className="min-w-0 flex-1 text-xs">
                  <div className="text-fg font-medium">{rule?.title || o.rule_id}</div>
                  <div className="text-muted font-mono">
                    {o.fired_at} · count {o.result_count}
                    {o.sample_ids?.[0] && (
                      <>
                        {' · '}
                        <Link className="text-info hover:underline" to={`/incidents/${encodeURIComponent(o.sample_ids[0])}`}>
                          {o.sample_ids[0]}
                        </Link>
                      </>
                    )}
                  </div>
                </div>
                {rule && (
                  <Link
                    className="text-[11px] text-info hover:underline"
                    to={`/search?saved=${encodeURIComponent(rule.saved_search_id)}`}
                  >
                    search
                  </Link>
                )}
              </li>
            );
          })}
          {occ.length === 0 && (
            <li className="px-4 py-6 text-center text-xs text-muted">{t('workspace.alertsPage.emptyOcc')}</li>
          )}
        </ul>
      </CardBody>
    </Card>
  );
};
