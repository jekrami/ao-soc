import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '@/test/i18nForTests';
import { LiveBadge } from './LiveBadge';

describe('LiveBadge', () => {
  it('renders LIVE for broker-sourced incidents', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <LiveBadge source="broker" />
      </I18nextProvider>,
    );
    expect(screen.getByLabelText('LIVE')).toBeInTheDocument();
    expect(screen.getByText('LIVE')).toBeInTheDocument();
  });

  it('renders DEMO for demo-sourced incidents', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <LiveBadge source="demo" />
      </I18nextProvider>,
    );
    expect(screen.getByLabelText('DEMO')).toBeInTheDocument();
  });

  it('renders nothing when source is absent', () => {
    const { container } = render(
      <I18nextProvider i18n={i18n}>
        <LiveBadge />
      </I18nextProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
