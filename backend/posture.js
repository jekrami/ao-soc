import { mitreTactics } from './mockData.js';

const SEVERITY_WEIGHT = { CRITICAL: 5, HIGH: 3, MEDIUM: 2, LOW: 1 };

export function buildMitreHeatmap(incidentList) {
  const counts = Object.fromEntries(mitreTactics.map(t => [t, 0]));
  const techniquesByTactic = Object.fromEntries(mitreTactics.map(t => [t, new Set()]));

  for (const inc of incidentList) {
    for (const tech of inc.mitre_techniques || []) {
      const tactic = tech.tactic;
      if (!(tactic in counts)) continue;
      counts[tactic] += SEVERITY_WEIGHT[inc.severity] || 1;
      techniquesByTactic[tactic].add(tech.id);
    }
  }

  const max = Math.max(...Object.values(counts), 1);
  return mitreTactics.map(tactic => ({
    tactic,
    intensity: counts[tactic] / max,
    techniques: [...techniquesByTactic[tactic]],
  }));
}

export function buildMitrePayload(incidentList) {
  return {
    tactics: mitreTactics,
    heatmap: buildMitreHeatmap(incidentList),
  };
}
