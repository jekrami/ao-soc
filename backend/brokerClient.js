const BROKER_URL = (process.env.BROKER_URL || 'http://127.0.0.1:8500').replace(/\/$/, '');

export async function brokerFetch(path, init = {}) {
  const url = `${BROKER_URL}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...init.headers },
    ...init,
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
