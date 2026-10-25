import { api } from '@/lib/api';
import type { Entity, MitrePayload, Summary, SystemHealth } from '@/types';

export async function fetchSummary(): Promise<Summary> {
  return api<Summary>('/api/summary');
}

export async function fetchMitre(): Promise<MitrePayload> {
  return api<MitrePayload>('/api/mitre');
}

export async function fetchSystemHealth(): Promise<SystemHealth> {
  return api<SystemHealth>('/api/system/health');
}

export async function fetchEntities(): Promise<{
  users: Entity[];
  hosts: Entity[];
  ips: Entity[];
}> {
  const [users, hosts, ips] = await Promise.all([
    api<{ items: Entity[] }>('/api/entities/users'),
    api<{ items: Entity[] }>('/api/entities/hosts'),
    api<{ items: Entity[] }>('/api/entities/ips'),
  ]);
  return { users: users.items, hosts: hosts.items, ips: ips.items };
}
