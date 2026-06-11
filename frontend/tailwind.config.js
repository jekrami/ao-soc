/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Brand / surfaces
        bg:        '#0B1220',
        surface:   '#111827',
        surface2:  '#0F172A',
        border:    '#1F2937',
        // Information
        info:      '#3B82F6',
        // Risk
        low:       '#22C55E',
        medium:    '#EAB308',
        high:      '#F97316',
        critical:  '#EF4444',
        // Text
        fg:        '#F9FAFB',
        muted:     '#9CA3AF',
        subtle:    '#6B7280'
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
