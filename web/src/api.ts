// File: api.ts
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Send console API requests with session and organization context.

// Error that keeps the HTTP status next to the server's message so callers can branch on it.
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

// Console API call. The session cookie is sent same-origin, X-Terminus-Request is the header the server
// requires on cookie-authenticated writes (cross-site request protection), and X-Org-ID scopes the call to the
// selected organization. A 401 outside /auth/ broadcasts 'session-expired' so the shell returns to sign-in.
export async function api<T>(path: string, orgId?: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Terminus-Request': '1', ...(orgId ? { 'X-Org-ID': orgId } : {}), ...init.headers },
  });
  // Error bodies are optional JSON; fall back to the status code when no readable detail is present.
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail = typeof body.detail === 'string' ? body.detail : Array.isArray(body.detail)
      ? body.detail.map((item: { msg: string }) => item.msg).join('; ') : `Request failed (${response.status})`;
    if (response.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new Event('session-expired'));
    throw new ApiError(response.status, detail);
  }
  // No-content responses (for example deletes) have no JSON body to parse.
  if (response.status === 204) return undefined as T;
  return response.json();
}

// Builds fetch options for a write; omits the body entirely when no value is given.
export const body = (method: string, value?: unknown): RequestInit => ({ method, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
// Saves text as a browser download; the object URL is revoked after a delay so the download can start.
export function download(name: string, text: string, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
