const BROKER_URL = (process.env.BROKER_URL || 'http://127.0.0.1:8500').replace(/\/$/, '');

// The UI API is a confidential client: one service key for the broker, and the
// operator it is acting for named in X-Actor. The broker only honours X-Actor
// from a principal holding actor:assert, so the dashboard cannot forge an
// approver (orchestrator/auth.py, resolve_actor).
const BROKER_API_KEY = (process.env.BROKER_API_KEY || '').trim();

if (!BROKER_API_KEY) {
  console.warn(
    '[broker] BROKER_API_KEY is not set — every broker call will be rejected with 401.\n' +
    '         Start the broker with BROKER_API_KEYS="ui-api:service:<secret>" and export\n' +
    '         the same secret here as BROKER_API_KEY.'
  );
}

export async function brokerFetch(path, init = {}) {
  const url = `${BROKER_URL}${path}`;
  const { actor, headers, ...rest } = init;
  const res = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(BROKER_API_KEY ? { 'X-API-Key': BROKER_API_KEY } : {}),
      ...(actor ? { 'X-Actor': actor } : {}),
      ...headers,
    },
    ...rest,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`Broker ${res.status} ${path}: ${text}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function brokerAvailable() {
  try {
    await brokerFetch('/health');
    return true;
  } catch {
    return false;
  }
}

export { BROKER_URL };
