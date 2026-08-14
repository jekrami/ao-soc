import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Network, ChevronDown, ChevronRight, ExternalLink, Layers, Link2, Users,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useAoSoc } from '@/store/useAoSoc';
import type { Severity, SituationDetection } from '@/types';

/**
 * The detections a decision stands on (plan §2.1).
 *
 * Phase B built cross-tool correlation and left it as an API; this is the
 * analyst's view of it. It answers the question a Tier-2 verdict on a merged
 * situation immediately raises — *what am I actually approving containment
 * for?* — by showing every member detection with the tool that raised it, the
 * entities they were correlated on, and each term of the risk score.
 *
 * The risk factors are listed rather than summarised on purpose. The score is
 * deterministic and explainable, unlike the model's own confidence, and an
 * analyst asked to trust a number is owed the arithmetic behind it.
 */

const severityTone: Record<Severity, string> = {
  CRITICAL: 'text-critical border-critical/40 bg-critical/10',
  HIGH: 'text-high border-high/40 bg-high/10',
  MEDIUM: 'text-medium border-medium/40 bg-medium/10',
  LOW: 'text-low border-low/40 bg-low/10',
};

const ENTITY_ICON: Record<string, typeof Users> = {
  user: Users,
  host: Network,
  ip: Link2,
};

function shortTime(value: string | null): string {
  if (!value) return '--:--';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value.slice(11, 16) : date.toISOString().slice(11, 16);
}

const DetectionRow: React.FC<{ detection: SituationDetection }> = ({ detection }) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const Chevron = open ? ChevronDown : ChevronRight;
  const entities = Object.entries(detection.entities || {});

  return (
    <li className="rounded-md border border-border bg-surface2/40">
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        className="flex w-full items-start gap-2 p-2.5 text-start"
        aria-expanded={open}
      >
        <Chevron className="mt-0.5 h-4 w-4 shrink-0 text-muted" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            {/* The source tool is the point: two of these from one vendor is a
                queue, two from different vendors is corroboration. */}
            <span className="rounded border border-info/40 bg-info/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-info">
              {detection.source_tool}
            </span>
            <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${severityTone[detection.severity] ?? severityTone.MEDIUM}`}>
              {t(`enums.severity.${detection.severity}`, detection.severity)}
            </span>
            <span className="text-xs text-muted">{shortTime(detection.detected_at)}</span>
          </div>
          <div className="mt-1 truncate text-sm text-fg">{detection.rule_name}</div>
        </div>
      </button>

      {open && (
        <div className="space-y-2 border-t border-border px-2.5 pb-2.5 pt-2 text-xs">
          {detection.message && (
            <p className="whitespace-pre-wrap break-words text-muted">{detection.message}</p>
          )}
          {entities.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {entities.map(([kind, value]) => (
                <span key={kind} className="rounded bg-surface px-1.5 py-0.5 font-mono text-[11px] text-fg">
                  <span className="text-muted">{kind}</span> {value}
                </span>
              ))}
            </div>
          )}
          {detection.vendor_techniques?.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {detection.vendor_techniques.map(id => (
                <span key={id} className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted">
                  {id}
                </span>
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted">
            <span>{t('situation.rule')}: <span className="font-mono text-fg">{detection.rule_id || '—'}</span></span>
            <span>{t('situation.adapter')}: <span className="font-mono">{detection.adapter} v{detection.adapter_version}</span></span>
            {detection.vendor_severity && (
              <span>{t('situation.vendorSeverity')}: <span className="font-mono">{detection.vendor_severity}</span></span>
            )}
          </div>
          {/* An evidence pointer with no URL is still a pointer — it names the
              tool and rule an analyst types into their own console. */}
          {detection.evidence?.url ? (
            <a
              href={detection.evidence.url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 text-[11px] text-info hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              {t('situation.openUpstream', { tool: detection.source_tool })}
            </a>
          ) : (
            <div className="text-[11px] text-muted">
              {t('situation.noUpstreamLink', { tool: detection.source_tool })}
            </div>
          )}
        </div>
      )}
    </li>
  );
};

export const SituationPanel: React.FC = () => {
  const { t } = useTranslation();
  const { selectedIncident, selectedSituation } = useAoSoc();

  if (selectedIncident?.source !== 'broker') return null;

  if (!selectedSituation) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-info" />
            <CardTitle>{t('situation.title')}</CardTitle>
          </div>
          <CardSubtitle>{t('situation.subtitle')}</CardSubtitle>
        </CardHeader>
        <CardBody>
          <div className="text-sm text-muted">{t('situation.none')}</div>
        </CardBody>
      </Card>
    );
  }

  const s = selectedSituation;
  const entityGroups = Object.entries(s.entities || {});

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-info" />
          <div className="min-w-0">
            <CardTitle>{t('situation.title')}</CardTitle>
            <CardSubtitle>
              {t('situation.builtFrom', { count: s.detection_count, tools: s.sources.length })}
            </CardSubtitle>
          </div>
        </div>
      </CardHeader>

      <CardBody className="space-y-4">
        {/* Corroboration first — it is the whole claim of the layer. */}
        <div className="flex flex-wrap items-center gap-2">
          {s.sources.map(tool => (
            <span key={tool} className="rounded border border-info/40 bg-info/10 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-info">
              {tool}
            </span>
          ))}
          {s.multi_source && (
            <span className="text-xs text-low">{t('situation.corroborated')}</span>
          )}
        </div>

        {s.merged_into && (
          <div className="rounded-md border border-medium/40 bg-medium/10 p-2 text-xs text-medium">
            {t('situation.mergedInto', { id: s.merged_into })}
          </div>
        )}

        {/* The score, and the arithmetic behind it. */}
        <div>
          <div className="mb-1.5 flex items-baseline justify-between">
            <span className="text-xs uppercase tracking-wide text-muted">{t('situation.riskScore')}</span>
            <span className="font-mono text-lg text-fg">{s.risk_score}<span className="text-xs text-muted">/100</span></span>
          </div>
          <ul className="space-y-1">
            {s.risk_factors.map(f => (
              <li key={f.factor} className="flex items-start gap-2 text-xs">
                <span className={`w-10 shrink-0 text-end font-mono ${f.points < 0 ? 'text-medium' : 'text-low'}`}>
                  {f.points > 0 ? '+' : ''}{f.points}
                </span>
                {/* The broker sends both a rendered English sentence and the
                    numbers behind it. Translating from the numbers keeps the
                    Persian UI actually Persian (§9); the sentence is the
                    fallback for a factor this build has no string for yet. */}
                <span className="text-muted">
                  {t(`situation.factors.${f.factor}`, { ...(f.params ?? {}), defaultValue: f.detail })}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* The entity graph — what the detections were actually joined on. */}
        {entityGroups.length > 0 && (
          <div>
            <div className="mb-1.5 text-xs uppercase tracking-wide text-muted">
              {t('situation.correlatedOn')}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {entityGroups.map(([kind, values]) => {
                const Icon = ENTITY_ICON[kind] ?? Link2;
                return values.map(value => (
                  <span
                    key={`${kind}:${value}`}
                    className="inline-flex items-center gap-1 rounded border border-border bg-surface2/60 px-1.5 py-0.5 font-mono text-[11px] text-fg"
                    title={kind}
                  >
                    <Icon className="h-3 w-3 text-muted" />
                    {value}
                  </span>
                ));
              })}
            </div>
          </div>
        )}

        <div>
          <div className="mb-1.5 text-xs uppercase tracking-wide text-muted">
            {t('situation.detections')}
          </div>
          <ul className="space-y-1.5">
            {s.detections.map(d => (
              <DetectionRow key={d.detection_id} detection={d} />
            ))}
          </ul>
        </div>
      </CardBody>
    </Card>
  );
};
