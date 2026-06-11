import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { SeverityChip, StatusPill } from '@/components/ui/chip';
import { RecommendedActions } from '@/components/dashboard/RecommendedActions';
import { AiExplanation } from '@/components/dashboard/AiExplanation';
import { useAoSoc } from '@/store/useAoSoc';
import { api } from '@/lib/api';
import type { Incident } from '@/types';
import { ArrowLeft, Server, User, Clock } from 'lucide-react';

export const IncidentDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { incidents, selectIncident } = useAoSoc();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    if (!id) return;
    setLoading(true);
    api<Incident>(`/api/incidents/${id}`)
      .then(data => { if (alive) { setIncident(data); void selectIncident(data.id); } })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [id, selectIncident]);

  if (loading || !incident) {
    return (
      <div className="space-y-3">
        <div className="h-10 w-40 bg-surface rounded animate-pulse" />
        <div className="h-64 bg-surface rounded animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link to="/" className="text-muted hover:text-fg text-sm inline-flex items-center gap-1">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Command Center
        </Link>
        <span className="text-muted">·</span>
        <span className="font-mono text-xs text-muted">{incident.id}</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <SeverityChip severity={incident.severity} />
        <StatusPill status={incident.status} />
        <h1 className="text-xl font-semibold text-fg ml-1">{incident.title}</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="lg:col-span-2 space-y-3">
          <Card>
            <CardHeader>
              <CardTitle>Attack Storyboard</CardTitle>
              <CardSubtitle>{incident.timeline.length} stages · {incident.first_seen} → {incident.last_seen}</CardSubtitle>
            </CardHeader>
            <CardBody>
              <ol className="relative ml-2">
                <span className="absolute left-3 top-2 bottom-2 w-px bg-border" />
                {incident.timeline.map((s, i) => (
                  <li key={i} className="relative pl-9 pr-1 py-2.5">
                    <span className="absolute left-0 top-2.5 inline-flex h-6 w-6 items-center justify-center rounded-full bg-info/15 border border-info/40 text-info text-[10px] font-mono">
                      {i + 1}
                    </span>
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs text-muted inline-flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {s.time}
                      </span>
                      <span className="text-sm font-medium text-fg">{s.label}</span>
                      <span className="kbd">{s.mitre}</span>
                    </div>
                    <div className="text-sm text-muted mt-0.5">{s.detail}</div>
                  </li>
                ))}
              </ol>
            </CardBody>
          </Card>

          <AiExplanation />
        </div>

        <div className="space-y-3">
          <Card>
            <CardHeader>
              <CardTitle>Affected Assets</CardTitle>
              <CardSubtitle>{incident.affected_assets.length} entities</CardSubtitle>
            </CardHeader>
            <CardBody>
              <ul className="space-y-2">
                {incident.affected_assets.map(a => (
                  <li key={a} className="flex items-center gap-2 rounded-md border border-border bg-surface2/40 px-3 py-2">
                    <Server className="h-3.5 w-3.5 text-muted" />
                    <span className="font-mono text-sm text-fg">{a}</span>
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>MITRE Techniques</CardTitle>
              <CardSubtitle>{incident.mitre_techniques.length} matched</CardSubtitle>
            </CardHeader>
            <CardBody>
              <ul className="space-y-1.5">
                {incident.mitre_techniques.map(t => (
                  <li key={t.id} className="flex items-center gap-2 text-sm">
                    <span className="kbd">{t.id}</span>
                    <span className="text-fg">{t.name}</span>
                    <span className="text-muted text-[11px] ml-auto">{t.tactic}</span>
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>

          <RecommendedActions />
        </div>
      </div>
    </div>
  );
};
