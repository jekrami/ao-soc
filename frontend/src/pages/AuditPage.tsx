import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { ScrollText } from 'lucide-react';
import { AuditTable } from '@/components/auth/AuditTable';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import { queryKeys } from '@/lib/queryKeys';
import { fetchAudit } from '@/services/authService';
import type { AuditEntry } from '@/types/auth';

export const AuditPage: React.FC = () => {
  const { t } = useTranslation();
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [resetToken, setResetToken] = useState(0);

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: [...queryKeys.authAudit(cursor), resetToken],
    queryFn: () => fetchAudit({ cursor, limit: 50 }),
  });

  useEffect(() => {
    if (!data) return;
    setItems(prev => {
      if (!cursor) return data.items;
      const seen = new Set(prev.map(row => String(row.id)));
      const added = data.items.filter(row => !seen.has(String(row.id)));
      return added.length === 0 ? prev : [...prev, ...added];
    });
  }, [data, cursor]);

  const nextCursor = data?.next_cursor ?? null;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-base font-semibold text-fg">{t('authAudit.title')}</h1>
          <p className="text-[11px] text-muted">{t('authAudit.subtitle')}</p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          aria-label={t('common.refresh')}
          onClick={() => {
            setCursor(undefined);
            setItems([]);
            setResetToken(n => n + 1);
          }}
          disabled={isFetching}
        >
          {t('common.refresh')}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ScrollText className="h-4 w-4 text-info" aria-hidden />
            <CardTitle>{t('authAudit.tableTitle')}</CardTitle>
          </div>
          <CardSubtitle>{t('authAudit.totalSummary', { count: items.length })}</CardSubtitle>
        </CardHeader>
        <CardBody className="p-0">
          {error ? (
            <div role="alert" className="text-center text-critical text-sm py-12">
              {t('authAudit.loadFailed')}
            </div>
          ) : (
            <AuditTable items={items} loading={isLoading} />
          )}
          {nextCursor && (
            <div className="flex justify-center p-3 border-t border-border">
              <Button
                type="button"
                variant="subtle"
                size="sm"
                aria-label={t('authAudit.loadMore')}
                disabled={isFetching}
                onClick={() => setCursor(nextCursor)}
              >
                {t('authAudit.loadMore')}
              </Button>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
};
