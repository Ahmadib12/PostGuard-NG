import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell, Check, ChevronDown,
  CircleHelp, Database, Eye, EyeOff, Gauge, Globe2, LayoutDashboard,
  LockKeyhole, LogOut, Menu, RefreshCw, RotateCcw, ScrollText, Search, Server,
  Shield, ShieldAlert, UsersRound, X,
} from "lucide-react";
import {
  CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  api,
  type AdminItem,
  type AuditItem,
  type ClientItem,
  type EventItem,
  type Health,
  type IncidentItem,
  type IntelligenceResult,
  type OrganizationItem,
  type Overview,
  type Point,
} from "./api";

type View = "overview" | "clients" | "analytics" | "blocked" | "replays" | "suspicious" | "health" | "audit" | "intelligence" | "users" | "organizations" | "password";
type TimeRange = { label: string; hours: number };
const ranges: TimeRange[] = [
  { label: "Last hour", hours: 1 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 168 },
  { label: "30 days", hours: 720 },
];
const navigation: { id: View; label: string; icon: typeof LayoutDashboard; group: string; permission: string }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, group: "Monitor", permission: "dashboard.read" },
  { id: "clients", label: "Authenticated clients", icon: UsersRound, group: "Monitor", permission: "dashboard.read" },
  { id: "analytics", label: "Request analytics", icon: Activity, group: "Monitor", permission: "dashboard.read" },
  { id: "blocked", label: "Blocked requests", icon: ShieldAlert, group: "Security", permission: "events.read" },
  { id: "replays", label: "Replay monitoring", icon: RotateCcw, group: "Security", permission: "events.read" },
  { id: "suspicious", label: "Suspicious activity", icon: AlertTriangle, group: "Security", permission: "events.read" },
  { id: "intelligence", label: "Threat intelligence", icon: Activity, group: "Security", permission: "incidents.read" },
  { id: "health", label: "System health", icon: Server, group: "System", permission: "health.read" },
  { id: "audit", label: "Audit logs", icon: ScrollText, group: "System", permission: "audit.read" },
  { id: "users", label: "Administrators", icon: UsersRound, group: "Administration", permission: "users.read" },
  { id: "organizations", label: "Organizations", icon: Globe2, group: "Administration", permission: "organizations.manage" },
  { id: "password", label: "Change password", icon: LockKeyhole, group: "Account", permission: "profile.password.change" },
];
const titles: Record<View, { title: string; subtitle: string }> = {
  overview: { title: "Security overview", subtitle: "Live telemetry from your PostGuard gateway." },
  clients: { title: "Authenticated clients", subtitle: "Configured identities and their observed request activity." },
  analytics: { title: "Request analytics", subtitle: "Request volume and outcomes over time." },
  blocked: { title: "Blocked requests", subtitle: "Requests rejected by authentication, policy, replay, or rate controls." },
  replays: { title: "Replay monitoring", subtitle: "Nonce reuse and replay attempts captured by the gateway." },
  suspicious: { title: "Suspicious activity", subtitle: "Authentication, policy, and advisory anomaly events." },
  health: { title: "System health", subtitle: "Current application dependencies and provider mode." },
  audit: { title: "Audit logs", subtitle: "Administrator authentication and security actions." },
  intelligence: { title: "Threat intelligence", subtitle: "Deduplicated risk signals with optional AI-assisted defensive recommendations." },
  users: { title: "Administrators", subtitle: "Manage organization-scoped administrator accounts and access." },
  organizations: { title: "Organizations", subtitle: "Provision organizations and control service access." },
  password: { title: "Change password", subtitle: "Update your administrator password and revoke existing sessions." },
};

function readCookie(name: string) {
  return document.cookie.split("; ").find((cookie) => cookie.startsWith(`${name}=`))?.split("=").slice(1).join("=") ?? "";
}

function formatNumber(value = 0) {
  return new Intl.NumberFormat().format(value);
}

function formatDate(value: string | null) {
  if (!value) return "No activity";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function severityClass(value: string) {
  return `severity severity-${value.toLowerCase()}`;
}

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [username, setUsername] = useState("");
  const [organizationId, setOrganizationId] = useState("");
  const [role, setRole] = useState("");
  const [permissions, setPermissions] = useState<string[]>([]);
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [csrf, setCsrf] = useState("");
  const [checking, setChecking] = useState(true);
  const [active, setActive] = useState<View>("overview");
  const [range, setRange] = useState(24);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [points, setPoints] = useState<Point[]>([]);
  const [clients, setClients] = useState<ClientItem[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [audit, setAudit] = useState<AuditItem[]>([]);
  const [eventType, setEventType] = useState("");
  const [clientFilter, setClientFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [sinceDate, setSinceDate] = useState("");
  const [untilDate, setUntilDate] = useState("");
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [admins, setAdmins] = useState<AdminItem[]>([]);
  const [organizations, setOrganizations] = useState<OrganizationItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [providerEnabled, setProviderEnabled] = useState(false);
  const [investigation, setInvestigation] = useState<IntelligenceResult | null>(null);

  const load = useCallback(async (showSpinner = false) => {
    if (!authenticated) return;
    if (showSpinner) setRefreshing(true);
    try {
      setError("");
      if (active === "overview") {
        const [stats, chart, clientData, healthData, eventData] = await Promise.all([
          api.overview(range), api.analytics(range), api.clients(), api.health(),
          api.events(new URLSearchParams({ page_size: "8" })),
        ]);
        setOverview(stats);
        setPoints(chart.points);
        setClients(clientData.items);
        setHealth(healthData);
        setEvents(eventData.items);
      } else if (active === "clients") {
        setClients((await api.clients()).items);
      } else if (active === "analytics") {
        const [stats, chart] = await Promise.all([api.overview(range), api.analytics(range)]);
        setOverview(stats);
        setPoints(chart.points);
      } else if (active === "replays") {
        setEvents((await api.replays()).items);
      } else if (active === "suspicious") {
        setEvents((await api.suspicious()).items);
      } else if (active === "blocked") {
        const params = new URLSearchParams({ page_size: "50" });
        if (clientFilter) params.set("client_id", clientFilter);
        if (severityFilter) params.set("severity", severityFilter);
        if (eventType) params.set("event_type", eventType);
        if (sinceDate) params.set("since", new Date(`${sinceDate}T00:00:00`).toISOString());
        if (untilDate) params.set("until", new Date(`${untilDate}T23:59:59.999`).toISOString());
        setEvents((await api.events(params)).items.filter((event) => [401, 403, 409, 429, 503].includes(event.http_status ?? 0)));
      } else if (active === "health") {
        setHealth(await api.health());
      } else if (active === "audit") {
        setAudit((await api.audit()).items);
      } else if (active === "users") {
        setAdmins((await api.users()).items);
      } else if (active === "organizations") {
        setOrganizations((await api.organizations()).items);
      } else if (active === "intelligence") {
        const result = await api.incidents();
        setIncidents(result.items);
        setProviderEnabled(result.provider_enabled);
      }
      setLastUpdated(new Date());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load dashboard data.");
    } finally {
      setRefreshing(false);
    }
  }, [active, authenticated, range, clientFilter, severityFilter, eventType, sinceDate, untilDate]);

  useEffect(() => {
    api.session().then((session) => {
      setUsername(session.username);
      setOrganizationId(session.organization_id);
      setRole(session.role);
      setPermissions(session.permissions);
      setMustChangePassword(session.must_change_password);
      setAuthenticated(true);
      setCsrf(readCookie("postguard_admin_csrf"));
    }).catch(() => setAuthenticated(false)).finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    void load();
    const timer = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(timer);
  }, [authenticated, load]);

  async function handleLogin(user: string, password: string, requestedOrganizationId?: string) {
    const result = await api.login(user, password, requestedOrganizationId);
    setUsername(result.username);
    setOrganizationId(result.organization_id);
    setRole(result.role);
    setPermissions(result.permissions);
    setMustChangePassword(result.must_change_password);
    setCsrf(result.csrf_token);
    setAuthenticated(true);
    setActive("overview");
  }

  async function handleLogout() {
    try {
      await api.logout(csrf || readCookie("postguard_admin_csrf"));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Logout failed.");
    } finally {
      setAuthenticated(false);
      setUsername("");
      setOrganizationId("");
      setRole("");
      setPermissions([]);
      setMustChangePassword(false);
      setCsrf("");
    }
  }

  const selected = titles[active];
  const allowedNavigation = useMemo(
    () => navigation.filter((item) => permissions.includes(item.permission)),
    [permissions],
  );
  const navGroups = useMemo(() => [...new Set(allowedNavigation.map((item) => item.group))], [allowedNavigation]);

  if (checking) return <div className="loading-screen"><div className="loader" />Checking administrator session</div>;
  if (!authenticated) return <Login onLogin={handleLogin} />;
  if (mustChangePassword) {
    return <PasswordChange onSubmit={async (currentPassword, newPassword) => {
      await api.changePassword(currentPassword, newPassword, csrf || readCookie("postguard_admin_csrf"));
      await handleLogin(username, newPassword, organizationId);
    }} forced />;
  }

  return (
    <div className="app-shell">
      {mobileOpen && <button className="mobile-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} strokeWidth={2.5} /></div>
          <div><strong>PostGuard</strong><span>SECURITY OPERATIONS</span></div>
          <button className="icon-button mobile-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="workspace-picker">
          <div className="workspace-avatar">PG</div>
          <div><strong>Organization</strong><span>{organizationId}</span></div>
        </div>
        <nav className="nav-list" aria-label="Dashboard navigation">
          {navGroups.map((group) => (
            <section className="nav-group" key={group}>
              <p>{group}</p>
              {allowedNavigation.filter((item) => item.group === group).map(({ id, label, icon: Icon }) => (
                <button key={id} className={`nav-item ${active === id ? "nav-active" : ""}`} onClick={() => { setActive(id); setMobileOpen(false); }}>
                  <Icon size={17} strokeWidth={1.9} /><span>{label}</span>
                  {id === "replays" && (overview?.replay_attacks ?? 0) > 0 && <span className="nav-count">{overview?.replay_attacks}</span>}
                </button>
              ))}
            </section>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="gateway-status"><span className={`status-dot ${health?.status === "healthy" ? "dot-green" : "dot-amber"}`} />
            <div><strong>Gateway {health?.status === "healthy" ? "operational" : "monitoring"}</strong><span>Telemetry updates every 30s</span></div>
          </div>
          <div className="sidebar-user">
            <div className="user-avatar">{username.slice(0, 1).toUpperCase() || "A"}</div>
            <div><strong>{username}</strong><span>{role.replaceAll("_", " ")}</span></div>
            <button className="icon-button" onClick={() => void handleLogout()} aria-label="Sign out"><LogOut size={16} /></button>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="breadcrumb"><span>PostGuard</span><span className="crumb-slash">/</span><strong>{selected.title}</strong></div>
          <div className="topbar-actions">
            <span className="live-pill"><span /> LIVE</span>
            <button className={`icon-button refresh-button ${refreshing ? "spinning" : ""}`} onClick={() => void load(true)} aria-label="Refresh dashboard" title="Refresh now"><RefreshCw size={17} /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button>
            <div className="top-user"><div className="user-avatar">{username.slice(0, 1).toUpperCase() || "A"}</div><ChevronDown size={14} /></div>
          </div>
        </header>

        <div className="content">
          <div className="page-heading">
            <div><div className="eyebrow"><span className="eyebrow-square" /> SECURITY CENTER</div><h1>{selected.title}</h1><p>{selected.subtitle}</p></div>
            <div className="heading-tools">
              {active === "overview" || active === "analytics" ? <RangePicker value={range} onChange={setRange} /> : null}
              <div className="updated-note"><span className="status-dot dot-green" /> Updated {lastUpdated ? lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}</div>
            </div>
          </div>
          {error && <div className="error-banner"><AlertTriangle size={17} /><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss error"><X size={16} /></button></div>}

          {active === "overview" && <OverviewPage overview={overview} points={points} clients={clients} events={events} health={health} onNavigate={setActive} />}
          {active === "clients" && <ClientsPage clients={clients} />}
          {active === "analytics" && <AnalyticsPage overview={overview} points={points} />}
          {active === "blocked" && <EventsPage events={events} showFilters clientFilter={clientFilter} severityFilter={severityFilter} eventType={eventType} sinceDate={sinceDate} untilDate={untilDate} setClientFilter={setClientFilter} setSeverityFilter={setSeverityFilter} setEventType={setEventType} setSinceDate={setSinceDate} setUntilDate={setUntilDate} onFilter={() => void load(true)} />}
          {active === "replays" && <EventsPage events={events} title="Replay attempts" description="Each record represents a nonce replay rejected before an upstream request." />}
          {active === "suspicious" && <EventsPage events={events} title="Suspicious events" description="Monitor failed authentication and policy signals without storing request secrets." />}
          {active === "health" && <HealthPage health={health} />}
          {active === "audit" && <AuditPage audit={audit} />}
          {active === "intelligence" && <IntelligencePage incidents={incidents} providerEnabled={providerEnabled} result={investigation} onInvestigate={async () => {
            try {
              const result = await api.investigate(csrf || readCookie("postguard_admin_csrf"));
              setInvestigation(result);
            } catch (reason) {
              setError(reason instanceof Error ? reason.message : "AI investigation failed.");
            }
          }} canInvestigate={permissions.includes("analyst.investigate")} />}
          {active === "users" && <UsersPage admins={admins} canManage={permissions.includes("users.manage")} canAssignOwner={role === "platform_super_admin"} csrf={csrf} onRefresh={() => void load(true)} />}
          {active === "organizations" && <OrganizationsPage organizations={organizations} csrf={csrf} onRefresh={() => void load(true)} />}
          {active === "password" && <PasswordChange onSubmit={async (currentPassword, newPassword) => {
            await api.changePassword(currentPassword, newPassword, csrf || readCookie("postguard_admin_csrf"));
            setAuthenticated(false);
            setUsername("");
            setPermissions([]);
            setRole("");
            setCsrf("");
          }} />}
          <footer className="page-footer"><span>PostGuard NG <b>·</b> Security Operations</span><span>Telemetry is persisted locally and is not mock activity.</span></footer>
        </div>
      </main>
    </div>
  );
}

function RangePicker({ value, onChange }: { value: number; onChange: (value: number) => void }) {
  return <div className="range-picker" role="group" aria-label="Activity time range">
    {ranges.map((item) => <button key={item.hours} className={value === item.hours ? "range-active" : ""} onClick={() => onChange(item.hours)}>{item.label}</button>)}
  </div>;
}

function MetricCard({ label, value, note, icon: Icon, tone = "blue", change }: {
  label: string; value: number | string; note: string; icon: typeof Activity; tone?: string; change?: "up" | "down";
}) {
  return <div className="metric-card">
    <div className="metric-top"><span>{label}</span><div className={`metric-icon tone-${tone}`}><Icon size={18} /></div></div>
    <div className="metric-value">{typeof value === "number" ? formatNumber(value) : value}</div>
    <div className="metric-note">{change && (change === "up" ? <ArrowUpRight size={14} /> : <ArrowDownRight size={14} />)}<span>{note}</span></div>
  </div>;
}

function OverviewPage({ overview, points, clients, events, health, onNavigate }: {
  overview: Overview | null; points: Point[]; clients: ClientItem[]; events: EventItem[]; health: Health | null; onNavigate: (view: View) => void;
}) {
  const metrics = [
    { label: "Total requests", value: overview?.total_requests ?? 0, note: "Recorded in selected period", icon: Activity, tone: "blue" },
    { label: "Successful", value: overview?.successful_requests ?? 0, note: "Completed requests", icon: Check, tone: "green" },
    { label: "Failed", value: overview?.failed_requests ?? 0, note: "Rejected or upstream errors", icon: CircleHelp, tone: "amber" },
    { label: "Authenticated clients", value: overview?.authenticated_clients ?? 0, note: `${clients.length} configured identities`, icon: UsersRound, tone: "violet" },
    { label: "Blocked requests", value: overview?.blocked_requests ?? 0, note: "Security controls enforced", icon: ShieldAlert, tone: "red" },
    { label: "Replay attacks", value: overview?.replay_attacks ?? 0, note: "Duplicate nonce attempts", icon: RotateCcw, tone: "orange" },
    { label: "Suspicious activity", value: overview?.suspicious_requests ?? 0, note: "Authentication & policy alerts", icon: AlertTriangle, tone: "amber" },
  ];
  return <>
    <section className="metric-grid">{metrics.map((metric) => <MetricCard key={metric.label} {...metric} />)}</section>
    <section className="dashboard-grid">
      <div className="panel chart-panel">
        <div className="panel-heading"><div><h2>Request activity</h2><p>Gateway traffic and response outcomes</p></div><div className="chart-legend"><span><i className="legend-total" /> Requests</span><span><i className="legend-success" /> Successful</span></div></div>
        <ActivityChart points={points} />
      </div>
      <div className="panel health-panel">
        <div className="panel-heading"><div><h2>System status</h2><p>Live dependency checks</p></div><span className={`health-badge ${health?.status === "healthy" ? "healthy" : "degraded"}`}><i />{health?.status ?? "Checking"}</span></div>
        <HealthRow icon={Gauge} label="Application" state={health?.application ?? "unknown"} />
        <HealthRow icon={Database} label="Database" state={health?.database ?? "unknown"} />
        <HealthRow icon={Shield} label="Redis protection" state={health?.redis ?? "unknown"} />
        <HealthRow icon={Globe2} label="Upstream provider" state={health?.upstream ?? "unknown"} note={health?.upstream_is_mock ? "Mock mode" : undefined} />
        <button className="text-link" onClick={() => onNavigate("health")}>View system health <ArrowUpRight size={14} /></button>
      </div>
    </section>
    <section className="panel event-panel">
      <div className="panel-heading"><div><h2>Recent security events</h2><p>Latest persisted events from the request pipeline</p></div><button className="text-link" onClick={() => onNavigate("suspicious")}>View monitoring <ArrowUpRight size={14} /></button></div>
      <EventsTable events={events.slice(0, 6)} />
    </section>
  </>;
}

function ActivityChart({ points }: { points: Point[] }) {
  const data = points.map((point) => ({
    ...point,
    label: new Date(point.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" }),
  }));
  return <div className="chart-area">
    {data.length === 0 ? <div className="empty-chart"><Activity size={24} /><span>Request activity will appear here as gateway events are recorded.</span></div> :
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="#e9eef5" strokeDasharray="3 5" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: "#8290a5", fontSize: 11 }} axisLine={false} tickLine={false} minTickGap={30} />
          <YAxis allowDecimals={false} tick={{ fill: "#8290a5", fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={{ border: "1px solid #e8edf4", borderRadius: 9, boxShadow: "0 8px 26px #14233b12" }} />
          <Line type="monotone" dataKey="total" name="Requests" stroke="#386af5" strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
          <Line type="monotone" dataKey="successful" name="Successful" stroke="#19a679" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
        </LineChart>
      </ResponsiveContainer>}
  </div>;
}

function HealthRow({ icon: Icon, label, state, note }: { icon: typeof Activity; label: string; state: string; note?: string }) {
  const okay = state === "ok" || state === "healthy" || state === "mock_mode";
  return <div className="health-row"><div className="health-row-icon"><Icon size={16} /></div><div className="health-row-label"><strong>{label}</strong>{note && <span>{note}</span>}</div><span className={`service-state ${okay ? "state-ok" : "state-warn"}`}><i />{state.replaceAll("_", " ")}</span></div>;
}

function ClientsPage({ clients }: { clients: ClientItem[] }) {
  return <section className="panel data-panel">
    <div className="panel-heading"><div><h2>Client registry</h2><p>Configured clients are shown separately from observed authentications.</p></div><span className="soft-pill">{clients.length} configured</span></div>
    <div className="table-wrap"><table><thead><tr><th>CLIENT</th><th>STATUS</th><th>REQUESTS</th><th>SUCCESSFUL</th><th>BLOCKED</th><th>LAST ACTIVITY</th><th>AUTH ACTIVITY</th></tr></thead>
      <tbody>{clients.map((client) => <tr key={client.client_id}><td><div className="client-name"><span className="client-avatar">{client.client_id.slice(0, 2).toUpperCase()}</span><strong>{client.client_id}</strong></div></td><td><span className="status-label"><i className={client.enabled ? "dot-green" : "dot-muted"} />{client.enabled ? "Enabled" : "Disabled"}</span></td><td>{formatNumber(client.total_requests)}</td><td>{formatNumber(client.successful_requests)}</td><td>{formatNumber(client.blocked_requests)}</td><td>{formatDate(client.last_activity)}</td><td><span className={`auth-state ${client.authenticated_recently ? "auth-active" : ""}`}><i />{client.authenticated_recently ? "Authenticated recently" : "No recent authentication"}</span></td></tr>)}</tbody>
    </table>{clients.length === 0 && <EmptyState title="No configured clients" detail="Client policies are configured in the gateway settings." />}</div>
  </section>;
}

function AnalyticsPage({ overview, points }: { overview: Overview | null; points: Point[] }) {
  return <>
    <div className="metric-grid analytics-metrics">
      <MetricCard label="Total requests" value={overview?.total_requests ?? 0} note="Selected time range" icon={Activity} />
      <MetricCard label="Success rate" value={`${overview?.total_requests ? Math.round((overview.successful_requests / overview.total_requests) * 100) : 0}%`} note="Percentage of completed requests" icon={Check} tone="green" />
      <MetricCard label="Failed requests" value={overview?.failed_requests ?? 0} note="Rejected or failed upstream" icon={AlertTriangle} tone="amber" />
    </div>
    <section className="panel chart-panel analytics-chart"><div className="panel-heading"><div><h2>Traffic over time</h2><p>Actual gateway requests grouped into time buckets</p></div></div><ActivityChart points={points} /></section>
  </>;
}

function EventsPage({ events, title = "Blocked requests", description = "Security events and their safe request metadata.", showFilters = false, clientFilter = "", severityFilter = "", eventType = "", sinceDate = "", untilDate = "", setClientFilter, setSeverityFilter, setEventType, setSinceDate, setUntilDate, onFilter }: {
  events: EventItem[]; title?: string; description?: string; showFilters?: boolean; clientFilter?: string; severityFilter?: string; eventType?: string;
  sinceDate?: string; untilDate?: string; setClientFilter?: (value: string) => void; setSeverityFilter?: (value: string) => void; setEventType?: (value: string) => void;
  setSinceDate?: (value: string) => void; setUntilDate?: (value: string) => void; onFilter?: () => void;
}) {
  return <section className="panel data-panel">
    <div className="panel-heading"><div><h2>{title}</h2><p>{description}</p></div><span className="soft-pill">{events.length} events</span></div>
    {showFilters && <div className="filters">
      <label className="filter-search"><Search size={15} /><input value={clientFilter} onChange={(event) => setClientFilter?.(event.target.value)} placeholder="Filter client ID" /></label>
      <select value={eventType} onChange={(event) => setEventType?.(event.target.value)}><option value="">All event types</option>{["INVALID_SIGNATURE", "REPLAY_DETECTED", "RATE_LIMIT_EXCEEDED", "UNKNOWN_CLIENT", "INVALID_NONCE", "CLIENT_POLICY_VIOLATION"].map((item) => <option key={item}>{item}</option>)}</select>
      <select value={severityFilter} onChange={(event) => setSeverityFilter?.(event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((item) => <option key={item} value={item}>{item}</option>)}</select>
      <label className="date-filter">From<input aria-label="Filter events from date" type="date" value={sinceDate} onChange={(event) => setSinceDate?.(event.target.value)} /></label>
      <label className="date-filter">To<input aria-label="Filter events to date" type="date" value={untilDate} onChange={(event) => setUntilDate?.(event.target.value)} /></label>
      <button className="button-secondary" onClick={onFilter}>Apply filters</button>
    </div>}
    <div className="table-wrap"><EventsTable events={events} /></div>
  </section>;
}

function EventsTable({ events }: { events: EventItem[] }) {
  return <table><thead><tr><th>EVENT</th><th>SEVERITY</th><th>CLIENT</th><th>TIME</th><th>HTTP</th><th>REQUEST ID</th><th>SAFE CONTEXT</th></tr></thead>
    <tbody>{events.map((event) => <tr key={event.id}><td><div className="event-name"><span className={`event-mark ${event.severity}`}><ShieldAlert size={14} /></span><strong>{event.event_type.replaceAll("_", " ")}</strong></div></td><td><span className={severityClass(event.severity)}>{event.severity}</span></td><td>{event.client_id ?? "Unknown"}</td><td>{formatDate(event.timestamp)}</td><td><span className="http-code">{event.http_status ?? "—"}</span></td><td><code>{event.request_id?.slice(0, 12) ?? "—"}</code></td><td><span className="safe-context">{Object.entries(event.metadata).map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`).join(" · ") || "—"}</span></td></tr>)}</tbody>
    {events.length === 0 && <tbody><tr><td colSpan={7}><EmptyState title="No events recorded" detail="Events will appear here when the gateway records matching activity." /></td></tr></tbody>}
  </table>;
}

function HealthPage({ health }: { health: Health | null }) {
  const components = [
    { title: "Deployment model", mode: health?.deployment_mode ?? "unknown", icon: Server, desc: health?.deployment_mode === "managed" ? "Managed label selected; hosting, client lifecycle, and a managed control plane remain operator responsibilities" : "Customer-hosted deployment; this instance is operated by its owner" },
    { title: "Application", status: health?.application ?? "unknown", icon: Gauge, desc: "FastAPI gateway request processing" },
    { title: "Telemetry database", status: health?.database ?? "unknown", icon: Database, desc: "Persistent dashboard events and audit history" },
    { title: "Redis security controls", status: health?.redis ?? "unknown", icon: Shield, desc: "Atomic rate limiting and nonce replay protection" },
    { title: "Upstream provider", status: health?.upstream ?? "unknown", icon: Globe2, desc: health?.upstream_is_mock ? "Mock mode — responses are not live NIPOST data" : "Live upstream reachability is checked on demand" },
  ];
  return <>
    <div className={`health-hero ${health?.status === "healthy" ? "" : "health-hero-degraded"}`}><div className="health-hero-icon"><Shield size={24} /></div><div><span>OVERALL SYSTEM STATUS</span><h2>{health?.status === "healthy" ? "All monitored systems operational" : "One or more systems need attention"}</h2><p>Health checks reflect the latest API probe; upstream live connectivity is not continuously tested.</p></div><span className="health-badge">{health?.status ?? "checking"}</span></div>
    <div className="component-grid">{components.map(({ title, status, mode, icon: Icon, desc }) => <div className="panel component-card" key={title}><div className="component-card-top"><div className="metric-icon tone-blue"><Icon size={18} /></div>{mode ? <span className="audit-action">{mode.replaceAll("_", " ")}</span> : <span className={`service-state ${(status === "ok" || status === "mock_mode") ? "state-ok" : "state-warn"}`}><i />{(status ?? "unknown").replaceAll("_", " ")}</span>}</div><h3>{title}</h3><p>{desc}</p></div>)}</div>
    <div className="notice-card"><AlertTriangle size={18} /><div><strong>Provider mode disclosure</strong><p>Mock mode is explicitly labeled and never represented as verified NIPOST data. A live provider status is not checked by the health endpoint.</p></div></div>
  </>;
}

function AuditPage({ audit }: { audit: AuditItem[] }) {
  return <section className="panel data-panel"><div className="panel-heading"><div><h2>Administrator audit trail</h2><p>Authentication and administrative actions with secrets excluded.</p></div></div>
    <div className="table-wrap"><table><thead><tr><th>ACTION</th><th>ADMINISTRATOR</th><th>TIME</th><th>DETAILS</th></tr></thead>
      <tbody>{audit.map((item) => <tr key={item.id}><td><span className="audit-action">{item.action.replaceAll("_", " ")}</span></td><td>{item.actor}</td><td>{formatDate(item.timestamp)}</td><td><code>{JSON.stringify(item.details)}</code></td></tr>)}</tbody>
      {audit.length === 0 && <tbody><tr><td colSpan={4}><EmptyState title="No audit entries" detail="Administrator actions are logged as they occur." /></td></tr></tbody>}
    </table></div>
  </section>;
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><div><Search size={18} /></div><strong>{title}</strong><span>{detail}</span></div>;
}

function IntelligencePage({ incidents, providerEnabled, result, canInvestigate, onInvestigate }: {
  incidents: IncidentItem[];
  providerEnabled: boolean;
  result: IntelligenceResult | null;
  canInvestigate: boolean;
  onInvestigate: () => Promise<void>;
}) {
  const [investigating, setInvestigating] = useState(false);
  async function investigate() {
    setInvestigating(true);
    try {
      await onInvestigate();
    } finally {
      setInvestigating(false);
    }
  }
  return <>
    <section className="panel data-panel">
      <div className="panel-heading">
        <div><h2>Deduplicated incident signals</h2><p>Events are grouped by type and UTC day; scores are deterministic triage aids, not proof of compromise.</p></div>
        <span className="soft-pill">{incidents.length} active groups</span>
      </div>
      <div className="table-wrap">
        <table><thead><tr><th>EVENT TYPE</th><th>SEVERITY</th><th>RISK SCORE</th><th>OCCURRENCES</th><th>FIRST SEEN</th><th>LAST SEEN</th></tr></thead>
          <tbody>{incidents.map((incident) => <tr key={incident.id}>
            <td><strong>{incident.event_type.replaceAll("_", " ")}</strong></td>
            <td><span className={severityClass(incident.severity)}>{incident.severity}</span></td>
            <td>{incident.risk_score}/100</td>
            <td>{formatNumber(incident.event_count)}</td>
            <td>{formatDate(incident.first_seen)}</td>
            <td>{formatDate(incident.last_seen)}</td>
          </tr>)}</tbody>
        </table>
        {incidents.length === 0 && <EmptyState title="No recent incidents" detail="Security events will be grouped here as the gateway records them." />}
      </div>
    </section>
    <section className="panel data-panel" style={{ marginTop: 16 }}>
      <div className="panel-heading">
        <div><h2>AI-assisted investigation</h2><p>Optional OpenAI-compatible provider. Only aggregate event types, severities, scores, and counts are sent; identifiers and request metadata are excluded.</p></div>
        <span className={`health-badge ${providerEnabled ? "healthy" : "degraded"}`}><i />{providerEnabled ? "Enabled" : "Disabled"}</span>
      </div>
      {providerEnabled ? <button className="button-secondary" disabled={!canInvestigate || investigating} onClick={() => void investigate()}>
        {investigating ? "Investigating…" : "Generate defensive recommendations"}
      </button> : <p className="intelligence-note">AI analysis is off. Enable and configure it on the server to use this feature.</p>}
      {!canInvestigate && providerEnabled && <p className="intelligence-note">Your role can view incidents but cannot request AI investigations.</p>}
      {result && <div className="incident-result">
        <h3>Analyst summary</h3><p>{result.summary}</p>
        <h3>Recommendations</h3>
        {result.recommendations.length ? <ul>{result.recommendations.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul> : <p>No recommendations returned.</p>}
        <p className="intelligence-note">Recommendations only. No automated actions were taken.</p>
      </div>}
    </section>
  </>;
}

function UsersPage({ admins, canManage, canAssignOwner, csrf, onRefresh }: {
  admins: AdminItem[];
  canManage: boolean;
  canAssignOwner: boolean;
  csrf: string;
  onRefresh: () => void;
}) {
  const [username, setUsername] = useState("");
  const [newRole, setNewRole] = useState("read_only_operator");
  const [temporaryPassword, setTemporaryPassword] = useState("");
  const [error, setError] = useState("");
  const csrfToken = csrf || readCookie("postguard_admin_csrf");
  async function createUser(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const created = await api.createUser(username, newRole, csrfToken);
      setTemporaryPassword(created.temporary_password);
      setUsername("");
      onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create administrator.");
    }
  }
  async function updateUser(admin: AdminItem, changes: { role?: string; active?: boolean }) {
    setError("");
    try {
      await api.updateUser(admin.admin_id, changes, csrfToken);
      onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update administrator.");
    }
  }
  async function resetPassword(admin: AdminItem) {
    setError("");
    try {
      const result = await api.resetUserPassword(admin.admin_id, csrfToken);
      setTemporaryPassword(`${admin.username}: ${result.temporary_password}`);
      onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not reset password.");
    }
  }
  async function revokeSessions(admin: AdminItem) {
    setError("");
    try {
      const result = await api.revokeUserSessions(admin.admin_id, csrfToken);
      setTemporaryPassword(`${result.revoked_sessions} active session(s) revoked for ${admin.username}.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not revoke administrator sessions.");
    }
  }
  return <section className="panel data-panel">
    <div className="panel-heading"><div><h2>Organization administrators</h2><p>Temporary credentials are shown only once and must be changed at first sign-in.</p></div><span className="soft-pill">{admins.length} accounts</span></div>
    {error && <div className="error-banner"><AlertTriangle size={15} /><span>{error}</span></div>}
    {temporaryPassword && <div className="credential-notice"><strong>One-time password or access notice:</strong><code>{temporaryPassword}</code><button className="icon-button" onClick={() => setTemporaryPassword("")} aria-label="Dismiss administrator notice"><X size={15} /></button></div>}
    {canManage && <form className="filters" onSubmit={createUser}>
      <input required maxLength={128} value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Administrator username" aria-label="Administrator username" />
      <select value={newRole} onChange={(event) => setNewRole(event.target.value)} aria-label="New administrator role">
        {canAssignOwner && <option value="organization_owner">Organization owner</option>}
        <option value="organization_admin">Organization admin</option>
        <option value="security_auditor">Security auditor</option>
        <option value="read_only_operator">Read-only operator</option>
      </select>
      <button className="button-secondary">Create administrator</button>
    </form>}
    <div className="table-wrap"><table><thead><tr><th>USERNAME</th><th>ROLE</th><th>STATUS</th><th>PASSWORD</th>{canManage && <th>ACCESS</th>}</tr></thead>
      <tbody>{admins.map((admin) => <tr key={admin.admin_id}>
        <td><strong>{admin.username}</strong></td>
        <td>{canManage ? <select aria-label={`Role for ${admin.username}`} value={admin.role} onChange={(event) => void updateUser(admin, { role: event.target.value })}>
          <option value="organization_owner" disabled={!canAssignOwner}>Organization owner</option>
          <option value="organization_admin">Organization admin</option>
          <option value="security_auditor">Security auditor</option>
          <option value="read_only_operator">Read-only operator</option>
        </select> : admin.role.replaceAll("_", " ")}</td>
        <td>{admin.active ? "Active" : "Disabled"}</td>
        <td>{admin.must_change_password ? "Change required" : "Current"}</td>
        {canManage && <td className="row-actions">
          <button className="button-secondary" onClick={() => void updateUser(admin, { active: !admin.active })}>{admin.active ? "Disable" : "Enable"}</button>
          <button className="button-secondary" onClick={() => void resetPassword(admin)}>Reset password</button>
          <button className="button-secondary" onClick={() => void revokeSessions(admin)}>Revoke sessions</button>
        </td>}
      </tr>)}</tbody>
    </table>{admins.length === 0 && <EmptyState title="No administrators" detail="Create an organization administrator to delegate access." />}</div>
  </section>;
}

function OrganizationsPage({ organizations, csrf, onRefresh }: {
  organizations: OrganizationItem[];
  csrf: string;
  onRefresh: () => void;
}) {
  const [organizationId, setOrganizationId] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const csrfToken = csrf || readCookie("postguard_admin_csrf");
  async function createOrganization(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api.createOrganization(organizationId, name, csrfToken);
      setOrganizationId("");
      setName("");
      onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create organization.");
    }
  }
  async function setStatus(item: OrganizationItem) {
    setError("");
    try {
      await api.setOrganizationStatus(item.organization_id, item.status === "active" ? "suspended" : "active", csrfToken);
      onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update organization.");
    }
  }
  return <section className="panel data-panel">
    <div className="panel-heading"><div><h2>Organizations</h2><p>Suspended organizations cannot authenticate gateway requests or use tenant administration.</p></div><span className="soft-pill">{organizations.length} organizations</span></div>
    {error && <div className="error-banner"><AlertTriangle size={15} /><span>{error}</span></div>}
    <form className="filters" onSubmit={createOrganization}>
      <input required maxLength={32} pattern="[A-Za-z0-9_-]+" value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} placeholder="Organization ID" aria-label="Organization ID" />
      <input required maxLength={128} value={name} onChange={(event) => setName(event.target.value)} placeholder="Organization name" aria-label="Organization name" />
      <button className="button-secondary">Create organization</button>
    </form>
    <div className="table-wrap"><table><thead><tr><th>ORGANIZATION</th><th>STATUS</th><th>ACCESS CONTROL</th></tr></thead>
      <tbody>{organizations.map((item) => <tr key={item.organization_id}>
        <td><strong>{item.name}</strong><div className="intelligence-note">{item.organization_id}</div></td>
        <td><span className={`status-label ${item.status === "active" ? "auth-active" : ""}`}>{item.status}</span></td>
        <td><button className="button-secondary" onClick={() => void setStatus(item)}>{item.status === "active" ? "Suspend" : "Restore"}</button></td>
      </tr>)}</tbody>
    </table></div>
  </section>;
}

function PasswordChange({ onSubmit, forced = false }: {
  onSubmit: (currentPassword: string, newPassword: string) => Promise<void>;
  forced?: boolean;
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (newPassword !== confirmation) {
      setError("New password confirmation does not match.");
      return;
    }
    setSubmitting(true);
    try {
      await onSubmit(currentPassword, newPassword);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not change password.");
    } finally {
      setSubmitting(false);
    }
  }
  return <main className="login-page"><section className="login-card">
    <div className="login-lock"><LockKeyhole size={20} /></div>
    <div className="login-eyebrow">ACCOUNT SECURITY</div>
    <h1>{forced ? "Set a new password" : "Change password"}</h1>
    <p>{forced ? "Your temporary administrator password must be changed before continuing." : "Changing your password revokes all active sessions."}</p>
    {error && <div className="login-error"><AlertTriangle size={15} />{error}</div>}
    <form onSubmit={submit}>
      <label>Current password<input autoComplete="current-password" type="password" required value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></label>
      <label>New password<input autoComplete="new-password" type="password" minLength={16} maxLength={1024} required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></label>
      <label>Confirm new password<input autoComplete="new-password" type="password" minLength={16} maxLength={1024} required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
      <button className="login-submit" disabled={submitting}>{submitting ? "Updating password…" : "Update password"}</button>
    </form>
  </section></main>;
}

function Login({ onLogin }: { onLogin: (username: string, password: string, organizationId?: string) => Promise<void> }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [organizationId, setOrganizationId] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await onLogin(username, password, organizationId || undefined);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in failed.");
    } finally {
      setSubmitting(false);
    }
  }
  return <main className="login-page">
    <div className="login-brand"><div className="brand-mark"><Shield size={22} strokeWidth={2.5} /></div><strong>PostGuard</strong><span>SECURITY OPERATIONS</span></div>
    <section className="login-card">
      <div className="login-lock"><LockKeyhole size={20} /></div>
      <div className="login-eyebrow">ADMINISTRATOR ACCESS</div>
      <h1>Welcome back</h1><p>Sign in to your security operations dashboard.</p>
      {error && <div className="login-error"><AlertTriangle size={15} />{error}</div>}
      <form onSubmit={submit}>
        <label>Administrator username<input autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Enter your username" /></label>
        <label>Organization ID (if prompted)<input value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} placeholder="Leave blank for default" /></label>
        <label>Password<div className="password-field"><input autoComplete="current-password" required type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" /><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label>
        <button className="login-submit" disabled={submitting}>{submitting ? <><div className="button-loader" /> Verifying access</> : <>Sign in securely <ArrowUpRight size={17} /></>}</button>
      </form>
      <div className="login-secure"><Shield size={14} /><span>Protected by secure administrator authentication</span></div>
    </section>
    <div className="login-bottom">PostGuard NG <b>·</b> Security administration</div>
  </main>;
}

export default App;
