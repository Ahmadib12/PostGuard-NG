export type Overview = {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  authenticated_clients: number;
  blocked_requests: number;
  replay_attacks: number;
  suspicious_requests: number;
};

export type EventItem = {
  id: string;
  timestamp: string;
  event_type: string;
  client_id: string | null;
  request_id: string | null;
  http_status: number | null;
  outcome: string;
  severity: string;
  metadata: Record<string, string | number | boolean>;
};

export type Page<T> = { items: T[]; page: number; page_size: number; total: number };
export type ClientItem = {
  client_id: string;
  enabled: boolean;
  total_requests: number;
  successful_requests: number;
  blocked_requests: number;
  authenticated_requests: number;
  authenticated_recently: boolean;
  last_activity: string | null;
};
export type Health = {
  status: string;
  application: string;
  redis: string;
  database: string;
  upstream: string;
  upstream_is_mock: boolean;
};
export type Point = { timestamp: string; total: number; successful: number; failed: number };
export type AuditItem = {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, credentials: "same-origin" });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail?.message ?? body?.detail ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  session: () => request<{ authenticated: boolean; username: string }>("/api/admin/session"),
  login: (username: string, password: string) =>
    request<{ username: string; csrf_token: string }>("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }),
  logout: (csrf: string) =>
    request<{ status: string }>("/api/admin/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),
  overview: (hours: number) => request<Overview>(`/api/admin/overview?hours=${hours}`),
  analytics: (hours: number) => request<{ points: Point[] }>(`/api/admin/analytics?hours=${hours}`),
  clients: () => request<{ items: ClientItem[] }>("/api/admin/clients"),
  health: () => request<Health>("/api/admin/health"),
  events: (params: URLSearchParams = new URLSearchParams()) =>
    request<Page<EventItem>>(`/api/admin/events?${params}`),
  replays: () => request<Page<EventItem>>("/api/admin/security/replays"),
  suspicious: () => request<Page<EventItem>>("/api/admin/security/suspicious"),
  audit: () => request<Page<AuditItem>>("/api/admin/audit-logs"),
};
