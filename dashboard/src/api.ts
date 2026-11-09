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
  deployment_mode: "customer_hosted" | "managed";
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
export type AdminItem = {
  admin_id: string;
  username: string;
  active: boolean;
  role: string;
  must_change_password: boolean;
};
export type OrganizationItem = {
  organization_id: string;
  name: string;
  status: "active" | "suspended";
};
export type IncidentItem = {
  id: string;
  event_type: string;
  severity: string;
  risk_score: number;
  event_count: number;
  first_seen: string;
  last_seen: string;
};
export type IntelligenceResult = {
  summary: string;
  recommendations: string[];
  automated_actions: false;
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
  session: () => request<{
    authenticated: boolean;
    username: string;
    organization_id: string;
    role: string;
    permissions: string[];
    must_change_password: boolean;
  }>("/api/admin/session"),
  login: (username: string, password: string, organizationId?: string) =>
    request<{
      username: string;
      organization_id: string;
      role: string;
      permissions: string[];
      must_change_password: boolean;
      csrf_token: string;
    }>("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, organization_id: organizationId || undefined }),
    }),
  logout: (csrf: string) =>
    request<{ status: string }>("/api/admin/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),
  changePassword: (currentPassword: string, newPassword: string, csrf: string) =>
    request<{ status: string }>("/api/admin/password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
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
  users: () => request<{ items: AdminItem[] }>("/api/admin/users"),
  createUser: (username: string, role: string, csrf: string) =>
    request<{ admin_id: string; username: string; role: string; temporary_password: string }>("/api/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ username, role }),
    }),
  updateUser: (adminId: string, changes: { role?: string; active?: boolean }, csrf: string) =>
    request<{ status: string }>(`/api/admin/users/${encodeURIComponent(adminId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(changes),
    }),
  resetUserPassword: (adminId: string, csrf: string) =>
    request<{ temporary_password: string; must_change_password: boolean }>(
      `/api/admin/users/${encodeURIComponent(adminId)}/reset-password`,
      { method: "POST", headers: { "X-CSRF-Token": csrf } },
    ),
  revokeUserSessions: (adminId: string, csrf: string) =>
    request<{ revoked_sessions: number }>(
      `/api/admin/users/${encodeURIComponent(adminId)}/revoke-sessions`,
      { method: "POST", headers: { "X-CSRF-Token": csrf } },
    ),
  organizations: () => request<{ items: OrganizationItem[] }>("/api/admin/organizations"),
  createOrganization: (organizationId: string, name: string, csrf: string) =>
    request<{ organization_id: string; status: string }>("/api/admin/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ organization_id: organizationId, name }),
    }),
  setOrganizationStatus: (organizationId: string, status: "active" | "suspended", csrf: string) =>
    request<{ organization_id: string; status: string }>(
      `/api/admin/organizations/${encodeURIComponent(organizationId)}/${status === "active" ? "restore" : "suspend"}`,
      { method: "POST", headers: { "X-CSRF-Token": csrf } },
    ),
  incidents: () =>
    request<{ items: IncidentItem[]; provider_enabled: boolean }>("/api/admin/intelligence/incidents"),
  investigate: (csrf: string) =>
    request<IntelligenceResult>("/api/admin/intelligence/investigate", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),
};
