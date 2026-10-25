import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, Play } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import { SeverityChip } from '@/components/ui/chip';
import {
  createAlertRule, deleteAlertRule, evaluateAlertRule, listAlertRules,
  listSavedSearches, updateAlertRule,
} from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';

export const AlertDefinitionsPanel: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const canWrite = canActOnDecisions(getAuthSession()?.role);

  const { data: rules = [], isLoading } = useQuery({
    queryKey: queryKeys.alertRules,
    queryFn: listAlertRules,
  });
  const { data: searches = [] } = useQuery({
    queryKey: queryKeys.savedSearches,
    queryFn: listSavedSearches,
    enabled: canWrite,
  });

  const createMut = useMutation({
    mutationFn: async () => {
      const ss = searches[0];
      if (!ss) throw new Error('Create a saved search first');
      return createAlertRule({
        saved_search_id: ss.id,
        title: `${ss.title} rule`,
        threshold_count: 1,
        severity: 'MEDIUM',
      });
    },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.alertRules }),
  });

  const evalMut = useMutation({
    mutationFn: (id: string) => evaluateAlertRule(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.alertRules });
      void queryClient.invalidateQueries({ queryKey: queryKeys.alertOccurrences });
    },
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => updateAlertRule(id, { enabled }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.alertRules }),
  });

  const delMut = useMutation({
    mutationFn: (id: string) => deleteAlertRule(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.alertRules }),
  });

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{t('workspace.alertsPage.definitions')}</CardTitle>
          <CardSubtitle>{t('workspace.alertsPage.definitionsSubtitle')}</CardSubtitle>
        </div>
        {canWrite && (
          <Button size="sm" aria-label={t('workspace.alertsPage.newRule')} onClick={() => createMut.mutate()} disabled={!searches.length}>
            <Plus className="h-3.5 w-3.5" />
            {t('workspace.alertsPage.newRule')}
          </Button>
        )}
      </CardHeader>
      <CardBody className="p-0">
        <ul>
          {rules.map(rule => (
            <li key={rule.id} className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-border last:border-0">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-fg">{rule.title}</span>
                  <SeverityChip severity={rule.severity} />
                </div>
                <div className="text-[11px] text-muted">
                  {t('workspace.alertsPage.threshold')}: ≥ {rule.threshold_count}
                  {' · '}
                  <Link className="text-info hover:underline" to={`/search?saved=${encodeURIComponent(rule.saved_search_id)}`}>
                    {rule.saved_search_id}
                  </Link>
                  {rule.last_evaluated_at && ` · ${rule.last_evaluated_at.slice(0, 19)}`}
                </div>
              </div>
              <label className="inline-flex items-center gap-1.5 text-[11px] text-muted">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  disabled={!canWrite}
                  aria-label={t('workspace.alertsPage.enabled')}
                  onChange={e => toggleMut.mutate({ id: rule.id, enabled: e.target.checked })}
                />
                {t('workspace.alertsPage.enabled')}
              </label>
              {canWrite && (
                <>
                  <Button size="sm" variant="outline" aria-label={t('workspace.alertsPage.evaluate')} onClick={() => evalMut.mutate(rule.id)}>
                    <Play className="h-3.5 w-3.5" />
                    {t('workspace.alertsPage.evaluate')}
                  </Button>
                  <button
                    type="button"
                    className="text-[11px] text-critical"
                    aria-label={t('workspace.dashboards.delete')}
                    onClick={() => delMut.mutate(rule.id)}
                  >
                    {t('workspace.dashboards.delete')}
                  </button>
                </>
              )}
            </li>
          ))}
          {!isLoading && rules.length === 0 && (
            <li className="px-4 py-8 text-center text-xs text-muted">{t('workspace.alertsPage.emptyRules')}</li>
          )}
        </ul>
      </CardBody>
    </Card>
  );
};
