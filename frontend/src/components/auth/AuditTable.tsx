import { useTranslation } from 'react-i18next';
import type { AuditEntry } from '@/types/auth';

interface Props {
  items: AuditEntry[];
  loading?: boolean;
  emptyLabel?: string;
}

export const AuditTable: React.FC<Props> = ({ items, loading = false, emptyLabel }) => {
  const { t, i18n } = useTranslation();
  const locale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  const fmtTime = (value: string) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString(locale, {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  if (loading && items.length === 0) {
    return <div className="text-center text-muted text-sm py-12">{t('common.loading')}</div>;
  }

  if (items.length === 0) {
    return (
      <div className="text-center text-muted text-sm py-12">
        {emptyLabel ?? t('authAudit.empty')}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-start text-xs" aria-label={t('authAudit.tableLabel')}>
        <thead>
          <tr className="border-b border-border text-muted uppercase tracking-wider">
            <th scope="col" className="px-3 py-2 font-medium">{t('authAudit.columns.time')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('authAudit.columns.action')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('authAudit.columns.actor')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('authAudit.columns.target')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('authAudit.columns.result')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('authAudit.columns.reason')}</th>
          </tr>
        </thead>
        <tbody>
          {items.map(row => (
            <tr key={String(row.id)} className="border-b border-border/60 last:border-0">
              <td className="px-3 py-2 font-mono whitespace-nowrap">{fmtTime(row.time)}</td>
              <td className="px-3 py-2 font-medium">{row.action}</td>
              <td className="px-3 py-2">{row.actor}</td>
              <td className="px-3 py-2">{row.target_user ?? '—'}</td>
              <td className="px-3 py-2">{row.result}</td>
              <td className="px-3 py-2 text-muted">{row.reason ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
