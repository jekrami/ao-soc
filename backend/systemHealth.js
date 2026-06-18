import { jitterHealth } from './mockData.js';
import { brokerAvailable, brokerFetch } from './brokerClient.js';

export async function buildSystemHealth() {
  const health = jitterHealth();

  if (!(await brokerAvailable())) {
    health.broker.status = 'OFFLINE';
    health.broker.queue_depth = 0;
    return health;
  }

  try {
    const [brokerHealth, alerts] = await Promise.all([
      brokerFetch('/health'),
      brokerFetch('/api/alerts').catch(() => null),
    ]);

    health.broker.status = 'ONLINE';
    if (brokerHealth.model) {
      health.llm.model = brokerHealth.model;
    }
    health.llm.status = 'ONLINE';

    if (alerts?.metrics) {
      const pending = alerts.metrics.by_mitigation_status?.PENDING ?? 0;
      health.broker.queue_depth = pending;
      health.broker.correlations_per_min = alerts.count ?? health.broker.correlations_per_min;
      if (pending > 10) {
        health.broker.status = 'DEGRADED';
      }
    }
  } catch {
    health.broker.status = 'DEGRADED';
  }

  return health;
}
