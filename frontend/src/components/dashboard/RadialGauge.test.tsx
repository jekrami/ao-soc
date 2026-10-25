import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RadialGauge } from './RadialGauge';

describe('RadialGauge', () => {
  it('keeps a posture word inside the ring', () => {
    render(
      <RadialGauge value={97} display="ELEVATED" label="Posture" size={108} sweep={220} />,
    );
    const word = screen.getByText('ELEVATED');
    const size = Number.parseFloat(word.style.fontSize);
    const maxWidth = Number.parseFloat(word.style.maxWidth);
    expect(size).toBeLessThanOrEqual(13);
    expect(size * 'ELEVATED'.length * 0.7).toBeLessThanOrEqual(maxWidth);
  });

  it('keeps a score at the large size', () => {
    render(<RadialGauge value={97} label="Overall Risk" size={128} />);
    expect(screen.getByText('97').style.fontSize).toBe('24px');
  });
});
