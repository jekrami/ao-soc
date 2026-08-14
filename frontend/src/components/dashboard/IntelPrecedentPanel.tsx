import { useTranslation } from 'react-i18next';
import {
  AlertTriangle, BadgeCheck, HelpCircle, History, ShieldQuestion, WifiOff,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useAoSoc } from '@/store/useAoSoc';
import type { IntelObservation } from '@/types';

/**
 * What was verified, and what this SOC has decided before (Phase D).
 *
 * Two things a Tier-2 analyst has that a model did not: a feed to check an
 * indicator against, and a memory of the last four times this shape of
 * intrusion came round. This panel shows both, and — more importantly — shows
 * where they are *absent*.
 *
 * The absence is the design constraint. A panel that renders only hits teaches
 * an analyst that a quiet panel means a clean situation, when it may mean no
 * feed is configured or the feed was unreachable. So every state is drawn:
 * confirmed, checked-and-not-found, never-checked, and feed-unavailable.
 */

const VERDICT_TONE: Record<string, string> = {
  MALICIOUS: 'border-critical/40 bg-critical/10 text-critical',
  SUSPICIOUS: 'border-high/40 bg-high/10 text-high',
  BENIGN: 'border-low/40 bg-low/10 text-low',
};

const IndicatorRow: React.FC<{ item: IntelObservation }> = ({ item }) => (
  <li className="flex flex-wrap items-center gap-2 text-xs">
    <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${VERDICT_TONE[item.verdict] ?? VERDICT_TONE.BENIGN}`}>
      {item.verdict}
    </span>
    <span className="font-mono text-fg">{item.value}</span>
    <span className="text-muted">{item.feed}</span>
    {item.tags.slice(0, 3).map(tag => (
      <span key={tag} className="rounded bg-surface2/60 px-1.5 py-0.5 text-[11px] text-muted">{tag}</span>
    ))}
  </li>
);

export const IntelPrecedentPanel: React.FC = () => {
  const { t } = useTranslation();
  const { selectedIncident, selectedTier2Decision } = useAoSoc();

  if (selectedIncident?.source !== 'broker') return null;

  const intel = selectedIncident.threat_intel ?? null;
  const precedent = selectedIncident.precedent ?? null;
  const basis = selectedTier2Decision?.autopilot_basis ?? null;
  const techniques = selectedIncident.mitre_techniques ?? [];
  const unverified = techniques.filter(
    tech => tech.catalog_status && tech.catalog_status !== 'verified',
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <BadgeCheck className="h-4 w-4 text-info" />
          <div className="min-w-0">
            <CardTitle>{t('intel.title')}</CardTitle>
            <CardSubtitle>{t('intel.subtitle')}</CardSubtitle>
          </div>
        </div>
      </CardHeader>

      <CardBody className="space-y-4">
        {/* --- Threat intelligence ------------------------------------- */}
        {!intel || intel.status === 'disabled' ? (
          <div className="flex items-start gap-2 rounded-md border border-border bg-surface2/40 p-2 text-xs text-muted">
            <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{t('intel.noProvider')}</span>
          </div>
        ) : (
          <div className="space-y-2">
            {intel.status === 'degraded' && (
              <div className="flex items-start gap-2 rounded-md border border-high/40 bg-high/10 p-2 text-xs text-high">
                <WifiOff className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{t('intel.degraded', { provider: intel.provider })}</span>
              </div>
            )}

            {(intel.malicious.length > 0 || intel.suspicious.length > 0 || intel.benign.length > 0) ? (
              <ul className="space-y-1.5">
                {[...intel.malicious, ...intel.suspicious, ...intel.benign].map(item => (
                  <IndicatorRow key={`${item.kind}:${item.value}`} item={item} />
                ))}
              </ul>
            ) : (
              <div className="text-xs text-muted">{t('intel.noHits', { provider: intel.provider })}</div>
            )}

            {/* Checked-and-empty is not clean, and never-checked is not clean
                either. Both are stated in words rather than left as a gap. */}
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted">
              {intel.not_found.length > 0 && (
                <span>{t('intel.notFound', { count: intel.not_found.length })}</span>
              )}
              {intel.skipped.length > 0 && (
                <span>{t('intel.skipped', { count: intel.skipped.length })}</span>
              )}
            </div>
          </div>
        )}

        {/* --- ATT&CK verification -------------------------------------- */}
        {unverified.length > 0 && (
          <div className="flex items-start gap-2 rounded-md border border-medium/40 bg-medium/10 p-2 text-xs text-medium">
            <HelpCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              {t('intel.unverifiedTechniques', {
                ids: unverified.map(tech => tech.id).join(', '),
                count: unverified.length,
              })}
            </span>
          </div>
        )}

        {/* --- Precedent ------------------------------------------------- */}
        <div>
          <div className="mb-1.5 flex items-center gap-2 text-xs uppercase tracking-wide text-muted">
            <History className="h-3.5 w-3.5" />
            {t('intel.precedent')}
          </div>

          {basis ? (
            <div className={`rounded-md border p-2 text-xs ${basis.ok ? 'border-low/40 bg-low/10 text-low' : 'border-border bg-surface2/40 text-muted'}`}>
              <div className="font-semibold">{t('intel.autoExecuted')}</div>
              <div className="mt-1">{basis.reason}</div>
              <ul className="mt-1.5 space-y-0.5 font-mono text-[11px]">
                {basis.cases.map(item => (
                  <li key={item.alert_id}>
                    {item.alert_id} · {item.verdict} · {item.similarity}% · {item.resolution}
                  </li>
                ))}
              </ul>
            </div>
          ) : precedent && precedent.offered > 0 ? (
            <div className="text-xs text-muted">
              {t('intel.offered', { count: precedent.offered, cited: precedent.cited.length })}
            </div>
          ) : (
            <div className="text-xs text-muted">{t('intel.noPrecedent')}</div>
          )}

          {/* A model that invents a case id is a fact about the model, and the
              store keeps it rather than quietly discarding it. */}
          {precedent && precedent.fabricated.length > 0 && (
            <div className="mt-1.5 flex items-start gap-2 rounded-md border border-high/40 bg-high/10 p-2 text-[11px] text-high">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{t('intel.fabricated', { ids: precedent.fabricated.join(', ') })}</span>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
};
