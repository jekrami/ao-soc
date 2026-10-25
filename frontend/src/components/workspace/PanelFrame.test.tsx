import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PanelFrame } from './PanelFrame';
import '@/test/i18nForTests';

describe('PanelFrame', () => {
  it('shows empty state distinctly from zero', () => {
    const { rerender } = render(
      <PanelFrame title="KPI" state="empty" />,
    );
    expect(screen.getByRole('status')).toHaveTextContent(/no rows yet/i);

    rerender(<PanelFrame title="KPI" state="zero" />);
    expect(screen.getByRole('status')).toHaveTextContent(/zero results/i);
  });

  it('shows error with alert role', () => {
    render(<PanelFrame title="KPI" state="error" errorMessage="boom" />);
    expect(screen.getByRole('alert')).toHaveTextContent('boom');
  });
});
