import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface BreadcrumbItem {
  label: string;
  to?: string;
}

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  breadcrumbs?: BreadcrumbItem[];
  actions?: React.ReactNode;
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  subtitle,
  breadcrumbs,
  actions,
  className,
}) => (
  <div className={cn('flex flex-wrap items-end justify-between gap-3 mb-3', className)}>
    <div className="min-w-0">
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-1 text-[11px] text-muted mb-1">
          {breadcrumbs.map((item, idx) => (
            <span key={`${item.label}-${idx}`} className="inline-flex items-center gap-1">
              {idx > 0 && <ChevronRight className="h-3 w-3 opacity-50 rtl:rotate-180" aria-hidden />}
              {item.to ? (
                <Link to={item.to} className="hover:text-fg transition-colors">
                  {item.label}
                </Link>
              ) : (
                <span className="text-fg" aria-current="page">{item.label}</span>
              )}
            </span>
          ))}
        </nav>
      )}
      <h1 className="text-base font-semibold text-fg">{title}</h1>
      {subtitle && <p className="text-[11px] text-muted mt-0.5">{subtitle}</p>}
    </div>
    {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
  </div>
);
