/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Surfaces use CSS variables so light/dark can swap without class churn
        bg:        'var(--color-bg)',
        surface:   'var(--color-surface)',
        surface2:  'var(--color-surface2)',
        border:    'var(--color-border)',
        // Information
        info:      '#3B82F6',
        // Risk
        low:       '#22C55E',
        medium:    '#EAB308',
        high:      '#F97316',
        critical:  '#EF4444',
        // Text
        fg:        'var(--color-fg)',
        muted:     'var(--color-muted)',
        subtle:    'var(--color-subtle)',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      boxShadow: {
        card: '0 1px 0 0 rgba(255,255,255,0.04) inset, 0 1px 2px rgba(0,0,0,0.4)'
      }
    }
  },
  plugins: []
};
