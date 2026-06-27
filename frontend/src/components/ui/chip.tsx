import { useTranslation } from 'react-i18next';
import { severityClass, riskColor } from '@/lib/utils';
import type { Severity } from '@/types';

export const SeverityChip: React.FC<{ severity: Severity | string }> = ({ severity }) => {
  const { t } = useTranslation();
  const key = `enums.severity.${severity}`;
  const label = t(key, { defaultValue: severity });
  return <span className={severityClass(severity)}>{label}</span>;
};

export const RiskBadge: React.FC<{ score: number }> = ({ score }) => (
  <span className={`font-mono text-sm font-semibold ${riskColor(score)}`}>{score}</span>
);

export const StatusPill: React.FC<{ status: string }> = ({ status }) => {
  const { t } = useTranslation();
  const cls =
    status === 'ACTIVE'        ? 'chip-critical' :
    status === 'INVESTIGATING' ? 'chip-high'     :
    status === 'OPEN'          ? 'chip-medium'   :
    status === 'MONITORING'    ? 'chip-info'     :
    status === 'CONTAINED'     ? 'chip-low'      :
    status === 'CLOSED'        ? 'chip-muted'    : 'chip-muted';
  const label = t(`enums.status.${status}`, { defaultValue: status });
  return <span className={cls}>{label}</span>;
};

export function useRiskLabel(label: string): string {
  const { t } = useTranslation();
  return t(`enums.risk.${label}`, { defaultValue: label });
}
