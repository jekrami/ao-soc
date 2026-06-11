import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityClass(sev: string) {
  switch (sev) {
    case 'CRITICAL': return 'chip-critical';
    case 'HIGH':     return 'chip-high';
    case 'MEDIUM':   return 'chip-medium';
    case 'LOW':      return 'chip-low';
    default:         return 'chip-muted';
  }
}

export function riskColor(score: number) {
  if (score >= 90) return 'text-critical';
  if (score >= 70) return 'text-high';
  if (score >= 40) return 'text-medium';
  return 'text-low';
}

export function fmtNumber(n: number) {
  return new Intl.NumberFormat('en-US').format(n);
}

export function pad2(n: number) { return n.toString().padStart(2, '0'); }

export function fmtClock(d: Date) {
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

export function fmtDate(d: Date) {
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: '2-digit' });
}
