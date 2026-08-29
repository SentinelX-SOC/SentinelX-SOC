const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

export function resolveWebSocketUrl(url?: string): string {
  const configured = url ?? import.meta.env.VITE_WS_URL ?? API_BASE_URL;
  const normalized = configured.endsWith('/') ? configured.slice(0, -1) : configured;
  const wsBase = normalized.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
  return `${wsBase}/ws`;
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const controller = new AbortController();
  const timeoutMs = Number(import.meta.env.VITE_API_TIMEOUT_MS ?? 15000);
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.headers ?? {}),
      },
      credentials: 'include',
      signal: controller.signal,
    });

    if (!response.ok) {
      let message = 'Request failed';
      try {
        const payload = await response.json();
        if (typeof payload?.detail === 'string') message = payload.detail;
        else if (payload?.detail && Array.isArray(payload.detail)) {
          message = payload.detail.map((entry: { msg?: string }) => entry.msg ?? String(entry)).join(', ');
        }
      } catch {
        message = response.statusText || message;
      }
      throw new Error(message);
    }

    const text = await response.text();
    return text ? (JSON.parse(text) as T) : (undefined as T);
  } finally {
    window.clearTimeout(timer);
  }
}

export { API_BASE_URL };
