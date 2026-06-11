import { severityClass, riskColor } from '@/lib/utils';
import type { Severity } from '@/types';

export const SeverityChip: React.FC<{ severity: Severity | string }> = ({ severity }) => {
  return <span className={severityClass(severity)}>{severity}</span>;
};

export const RiskBadge: React.FC<{ score: number }> = ({ score }) => (
  <span className={`font-mono text-sm font-semibold ${riskColor(score)}`}>{score}</span>
);

export const StatusPill: React.FC<{ status: string }> = ({ status }) => {
  const cls =
    status === 'ACTIVE'        ? 'chip-critical' :
    status === 'INVESTIGATING' ? 'chip-high'     :
    status === 'OPEN'          ? 'chip-medium'   :
    status === 'MONITORING'    ? 'chip-info'     :
    status === 'CONTAINED'     ? 'chip-low'      :
    status === 'CLOSED'        ? 'chip-muted'    : 'chip-muted';
  return <span className={cls}>{status}</span>;
};
