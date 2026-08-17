import keycloak from './keycloak';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:9090';

export interface ApiResult<T> {
  status: number;
  ok: boolean;
  data: T | null;
  error?: string;
}

// Thin fetch wrapper: attaches the current access token, refreshes it if
// close to expiry, and always returns the HTTP status alongside the body —
// callers need the status to distinguish "200 allowed" from "403 denied by
// policy X" for the access-control demo pages, not just a boolean.
export async function apiCall<T>(path: string, options: RequestInit = {}): Promise<ApiResult<T>> {
  try {
    await keycloak.updateToken(30);
  } catch {
    keycloak.login();
    return { status: 0, ok: false, data: null, error: 'session expired, redirecting to login' };
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${keycloak.token}`,
      'Content-Type': 'application/json',
    },
  });

  let body: T | null = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  return { status: res.status, ok: res.ok, data: body };
}
