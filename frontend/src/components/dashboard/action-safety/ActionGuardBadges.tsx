import { useTranslation } from 'react-i18next';
import { Cog, Crown, KeyRound } from 'lucide-react';
import type { Tier2ActionStatus } from '@/types';

const GUARD_TONE = 'text-critical border-critical/40 bg-critical/10';
const chip = 'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold tracking-wide border';

/** A target autopilot will never act on: a critical asset, or a privileged / service account. */
export const ActionGuardBadges: React.FC<{ action: Tier2ActionStatus }> = ({ action }) => {
  const { t } = useTranslation();
  const badges: { key: string; label: string; Icon: typeof Crown; reason?: string | null }[] = [];

  if (action.asset_criticality === 'CRITICAL') {
    badges.push({ key: 'asset', label: t('tier2.guard.CRITICAL'), Icon: Crown, reason: action.criticality_reason });
  }
  if (action.identity_role === 'PRIVILEGED') {
    badges.push({ key: 'identity', label: t('tier2.guard.PRIVILEGED'), Icon: KeyRound, reason: action.identity_reason });
  } else if (action.identity_role === 'SERVICE') {
    badges.push({ key: 'identity', label: t('tier2.guard.SERVICE'), Icon: Cog, reason: action.identity_reason });
  }
  if (!badges.length) return null;

  return (
    <>
      {badges.map(({ key, label, Icon, reason }) => (
        <span
          key={key}
          className={`${chip} ${GUARD_TONE}`}
          title={[reason, t('tier2.guard.hint')].filter(Boolean).join(' — ')}
        >
          <Icon className="h-3 w-3" />
          {label}
        </span>
      ))}
    </>
  );
};

export { chip };
