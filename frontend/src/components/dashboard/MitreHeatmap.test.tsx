import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '@/test/i18nForTests';
import { MitreHeatmap } from './MitreHeatmap';

vi.mock('@/hooks/useHealth', () => ({
  useMitre: () => ({
    data: {
      tactics: ['Initial Access', 'Execution'],
      heatmap: [
        { tactic: 'Initial Access', intensity: 0.8, techniques: ['T1190'] },
        { tactic: 'Execution', intensity: 0.4, techniques: ['T1059'] },
      ],
    },
    isLoading: false,
  }),
}));

describe('MitreHeatmap', () => {
  it('binds cells to query data techniques, not hardcoded demo overwrite', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <MitreHeatmap />
      </I18nextProvider>,
    );
    expect(screen.getByText('Initial Access')).toBeInTheDocument();
    expect(screen.getByText('Execution')).toBeInTheDocument();
    // Intensity-driven cells should expose technique ids from the payload.
    expect(screen.getByText(/T1190/)).toBeInTheDocument();
  });
});
