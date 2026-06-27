import { useTranslation } from 'react-i18next';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useAoSoc } from '@/store/useAoSoc';
import { Progress } from '@/components/ui/progress';
import { cn, riskColor } from '@/lib/utils';
import { User, Server, Globe } from 'lucide-react';
import type { Entity, EntityType } from '@/types';

const iconFor: Record<EntityType, React.ComponentType<{ className?: string }>> = {
  user: User,
  host: Server,
  ip:   Globe
};

const EntityList: React.FC<{ items: Entity[]; type: EntityType }> = ({ items, type }) => {
  const { t } = useTranslation();
  const Icon = iconFor[type];
  return (
    <ul className="space-y-2">
      {items.map(e => {
        const tone =
          e.risk_score >= 90 ? 'critical' :
          e.risk_score >= 70 ? 'high'     :
          e.risk_score >= 40 ? 'medium'   : 'low';
        return (
          <li key={e.id} className="rounded-md border border-border bg-surface2/40 p-3">
            <div className="flex items-center gap-2">
              <Icon className={cn('h-3.5 w-3.5', riskColor(e.risk_score))} />
              <span className="font-mono text-sm text-fg truncate flex-1">{e.name}</span>
              <span className={cn('font-mono text-sm font-semibold', riskColor(e.risk_score))}>
                {e.risk_score}
              </span>
            </div>
            <div className="mt-1 text-[11px] text-muted line-clamp-2">{e.reason}</div>
            <div className="mt-2 flex items-center gap-3 text-[10px] text-muted">
              <span>{t('common.conf')} <span className="font-mono text-fg/80">{e.confidence}%</span></span>
              <span>{t('common.seen')} <span className="font-mono text-fg/80">{e.last_seen}</span></span>
            </div>
            <div className="mt-2">
              <Progress value={e.risk_score} tone={tone as 'critical' | 'high' | 'medium' | 'low'} />
            </div>
          </li>
        );
      })}
    </ul>
  );
};

export const RiskAnalytics: React.FC = () => {
  const { t } = useTranslation();
  const { highRiskUsers, highRiskHosts, highRiskIps } = useAoSoc();

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
      <Card>
        <CardHeader>
          <div>
            <CardTitle>{t('dashboard.highRiskUsers')}</CardTitle>
            <CardSubtitle>{highRiskUsers.length} {t('common.flagged')}</CardSubtitle>
          </div>
          <User className="h-4 w-4 text-high" />
        </CardHeader>
        <CardBody>
          <EntityList items={highRiskUsers} type="user" />
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>{t('dashboard.highRiskHosts')}</CardTitle>
            <CardSubtitle>{highRiskHosts.length} {t('common.flagged')}</CardSubtitle>
          </div>
          <Server className="h-4 w-4 text-high" />
        </CardHeader>
        <CardBody>
          <EntityList items={highRiskHosts} type="host" />
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>{t('dashboard.highRiskIps')}</CardTitle>
            <CardSubtitle>{highRiskIps.length} {t('common.flagged')}</CardSubtitle>
          </div>
          <Globe className="h-4 w-4 text-high" />
        </CardHeader>
        <CardBody>
          <EntityList items={highRiskIps} type="ip" />
        </CardBody>
      </Card>
    </div>
  );
};
