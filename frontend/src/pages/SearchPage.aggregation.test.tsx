import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import i18n from '@/test/i18nForTests';

/** Stats view must be labelled as aggregation, not raw events. */
describe('search result labelling', () => {
  it('exposes the aggregation note string for stats results', () => {
    render(
      <I18nextProvider i18n={i18n}>
        <p role="note">{i18n.t('workspace.search.aggregationNote')}</p>
      </I18nextProvider>,
    );
    const note = screen.getByRole('note');
    expect(note.textContent?.toLowerCase()).toContain('aggregat');
    expect(note.textContent?.toLowerCase()).not.toMatch(/^raw events/);
  });
});
