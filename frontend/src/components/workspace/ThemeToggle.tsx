import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Moon, Sun } from 'lucide-react';
import { applyTheme, getStoredTheme, type ThemeMode } from '@/lib/theme';
import { cn } from '@/lib/utils';

export const ThemeToggle: React.FC = () => {
  const { t } = useTranslation();
  const [mode, setMode] = useState<ThemeMode>(() => getStoredTheme());

  useEffect(() => {
    applyTheme(mode);
  }, [mode]);

  const next: ThemeMode = mode === 'dark' ? 'light' : 'dark';

  return (
    <button
      type="button"
      aria-label={t(mode === 'dark' ? 'workspace.theme.switchToLight' : 'workspace.theme.switchToDark')}
      onClick={() => setMode(next)}
      className={cn(
        'inline-flex h-7 w-7 items-center justify-center rounded-md border border-border',
        'bg-surface text-muted hover:text-fg transition-colors',
      )}
    >
      {mode === 'dark' ? <Sun className="h-3.5 w-3.5" aria-hidden /> : <Moon className="h-3.5 w-3.5" aria-hidden />}
    </button>
  );
};
