// Tiny fetch wrapper. Throws on non-2xx.
//
// Every call carries the operator's API key (M14, risk R1). The key lives in
// sessionStorage, not localStorage: it dies with the tab, so a shared SOC
// workstation does not keep an analyst signed in for the next shift.

const KEY_STORAGE = 'aosoc.apiKey';

type Listener = () => void;
const listeners = new Set<Listener>();

export function getApiKey(): string {
  try {
    return sessionStorage.getItem(KEY_STORAGE) || '';
  } catch {
    return '';
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) sessionStorage.setItem(KEY_STORAGE, key);
    else sessionStorage.removeItem(KEY_STORAGE);
  } catch {
    /* private mode — the key simply does not persist */
  }
  listeners.forEach(fn => fn());
}

/** Notified when the key is set, cleared, or rejected by the API. */
export function onApiKeyChange(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const key = getApiKey();
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(key ? { 'X-API-Key': key } : {}),
      ...init?.headers,
    },
  });
  if (res.status === 401) {
    // A stale or wrong key must not leave the dashboard silently empty —
    // drop it so the gate reappears and the operator can enter a valid one.
    setApiKey('');
    throw new UnauthorizedError(`API 401 ${path}: authentication required`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API ${res.status} ${path}: ${text}`);
  }
  return res.json() as Promise<T>;
}
