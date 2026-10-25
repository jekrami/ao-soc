import type { SystemHealth } from '@/types';

export type SystemLane = 'splunk' | 'broker' | 'llm' | 'soar';
export type LaneStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN';

export function deriveSystemStatus(
  h: SystemHealth | null,
): Record<SystemLane, LaneStatus> {
  if (!h) return { splunk: 'UNKNOWN', broker: 'UNKNOWN', llm: 'UNKNOWN', soar: 'UNKNOWN' };
  const derive = (s: string, queueDepth: number): LaneStatus => {
    if (s === 'OFFLINE') return 'OFFLINE';
    if (s === 'DEGRADED' || queueDepth > 50) return 'DEGRADED';
    return 'ONLINE';
  };
  return {
    splunk: derive(h.splunk.status, h.splunk.queue_depth),
    broker: derive(h.broker.status, h.broker.queue_depth),
    llm: h.llm.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED',
    soar: h.soar.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED',
  };
}
