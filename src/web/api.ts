import type { DashboardData } from '../shared/types';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function parseError(response: Response): Promise<string> {
  try {
    const data = await response.json() as { error?: string };
    return data.error || 'Ошибка запроса';
  } catch {
    return 'Ошибка запроса';
  }
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: options?.body
      ? { 'Content-Type': 'application/json', ...options.headers }
      : options?.headers,
  });
  if (!response.ok) throw new ApiError(await parseError(response), response.status);
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  session: () => request<{ authenticated: boolean }>('/api/session'),
  login: (password: string) => request<{ ok: true }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ password }),
  }),
  logout: () => request<{ ok: true }>('/api/auth/logout', { method: 'POST' }),
  dashboard: () => request<DashboardData>('/api/dashboard'),
  createPeer: (name: string) => request<{ id: string }>('/api/peers', {
    method: 'POST',
    body: JSON.stringify({ name }),
  }),
  togglePeer: (id: string) => request<{ enabled: boolean }>(`/api/peers/${id}/toggle`, { method: 'POST' }),
  deletePeer: (id: string) => request<void>(`/api/peers/${id}`, { method: 'DELETE' }),
  restore: (backup: unknown) => request<{ ok: true }>('/api/backup/restore', {
    method: 'POST',
    body: JSON.stringify(backup),
  }),
};

export async function download(path: string, fallbackName: string): Promise<void> {
  const response = await fetch(path);
  if (!response.ok) throw new ApiError(await parseError(response), response.status);
  const disposition = response.headers.get('content-disposition');
  const match = disposition?.match(/filename="([^"]+)"/);
  const blob = await response.blob();
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = match?.[1] || fallbackName;
  anchor.click();
  URL.revokeObjectURL(href);
}
