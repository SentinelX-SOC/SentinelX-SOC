import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Check,
  CircleAlert,
  ChevronRight,
  Cpu,
  Crosshair,
  Database,
  Gauge,
  Globe,
  HeartPulse,
  Home,
  LoaderCircle,
  Menu,
  Network,
  Plus,
  Play,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  SquareTerminal,
  TimerReset,
  Wifi,
  X,
} from 'lucide-react';
import './App.css';
import { getCurrentUser, login, logout, type AuthenticatedUser } from './api/auth';
import { resolveWebSocketUrl } from './api/client';
import { ingestEvent } from './api/events';
import { getHealth } from './api/health';
import { getGraph, getGraphNeighbors } from './api/graph';
import { deployHoneytoken, listHoneytokenEvents, listHoneytokens, triggerHoneytoken } from './api/honeytokens';
import { decideReview, listReviews } from './api/reviews';
import { getSimulationStatus, pauseSimulation, resumeSimulation, startSimulation, stopSimulation } from './api/simulation';
import { SocWebSocket } from './api/websocket';
import type { AlertRead, EventPipelineResult, GraphRead, HealthRead, HoneytokenEventRead, HoneytokenRead, HumanReviewRead, SimulationStatusRead, TelemetryEventCreate, TelemetryEventRead } from './types/api';

type Screen = 'overview' | 'telemetry' | 'graph' | 'honeytokens' | 'simulation' | 'health' | 'reviews';

type ConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'disconnected';
type LiveEvent = TelemetryEventRead & { risk_score?: number; anomaly_score?: number; confidence?: number; detection_source?: string };
type RealtimeRemediation = { action: string; device_id?: string; alert_id?: string; received_at: string };

const navItems = [
  { id: 'overview', label: 'Overview', icon: Home, group: 'Command' },
  { id: 'graph', label: 'Attack Graph', icon: Network, group: 'Investigate' },
  { id: 'telemetry', label: 'Telemetry', icon: Activity, group: 'Investigate' },
  { id: 'reviews', label: 'Human Review', icon: Check, group: 'Operations' },
  { id: 'honeytokens', label: 'Honeytokens', icon: ShieldAlert, group: 'Operations' },
  { id: 'simulation', label: 'Simulation', icon: SquareTerminal, group: 'Operations' },
  { id: 'health', label: 'System Health', icon: HeartPulse, group: 'Operations' },
] as const;

const emptyEventForm: TelemetryEventCreate = {
  timestamp: new Date().toISOString(),
  source: '',
  destination: '',
  user: '',
  event_type: 'login',
  status: 'success',
};

function App() {
  const [authUser, setAuthUser] = useState<AuthenticatedUser | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [authError, setAuthError] = useState<string | null>(null);
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [activeScreen, setActiveScreen] = useState<Screen>('overview');
  const [health, setHealth] = useState<HealthRead | null>(null);
  const [graph, setGraph] = useState<GraphRead | null>(null);
  const [honeytokens, setHoneytokens] = useState<HoneytokenRead[]>([]);
  const [simulation, setSimulation] = useState<SimulationStatusRead | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [socketState, setSocketState] = useState<ConnectionState>('connecting');
  const [lastAlert, setLastAlert] = useState<AlertRead | null>(null);
  const [remediationActivity, setRemediationActivity] = useState<RealtimeRemediation[]>([]);
  const [search, setSearch] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [eventForm, setEventForm] = useState<TelemetryEventCreate>(emptyEventForm);
  const [eventSubmission, setEventSubmission] = useState<{ loading: boolean; error: string | null; result: EventPipelineResult | null }>({ loading: false, error: null, result: null });
  const [reviews, setReviews] = useState<HumanReviewRead[]>([]);
  const [reviewsLoading, setReviewsLoading] = useState(false);
  const [reviewsError, setReviewsError] = useState<string | null>(null);
  const socketRef = useRef<SocWebSocket | null>(null);

  useEffect(() => {
    void getCurrentUser()
      .then(setAuthUser)
      .catch(() => setAuthUser(null))
      .finally(() => setAuthChecking(false));
  }, []);

  useEffect(() => {
    if (!authUser) {
      return undefined;
    }
    const load = async () => {
      setReviewsLoading(true);
      setReviewsError(null);
      try {
        const [healthRes, graphRes, honeyRes, simRes, reviewRes] = await Promise.allSettled([
          getHealth(),
          getGraph(),
          listHoneytokens(),
          getSimulationStatus(),
          listReviews(),
        ]);
        const failures: string[] = [];
        if (healthRes.status === 'fulfilled') setHealth(healthRes.value); else failures.push('health');
        if (graphRes.status === 'fulfilled') setGraph(graphRes.value); else failures.push('graph');
        if (honeyRes.status === 'fulfilled') setHoneytokens(honeyRes.value); else failures.push('honeytokens');
        if (simRes.status === 'fulfilled') setSimulation(simRes.value); else failures.push('simulation');
        if (reviewRes.status === 'fulfilled') setReviews(reviewRes.value); else setReviewsError(reviewRes.reason instanceof Error ? reviewRes.reason.message : 'Reviews could not be loaded');
        setLoadError(failures.length ? `Unavailable backend resources: ${failures.join(', ')}` : null);
      } finally {
        setReviewsLoading(false);
        setLoading(false);
      }
    };
    void load();
  }, [authUser]);

  useEffect(() => {
    if (!authUser) {
      return undefined;
    }
    if (socketRef.current) {
      return undefined;
    }

    const ws = new SocWebSocket(resolveWebSocketUrl());
    socketRef.current = ws;
    ws.connect((event) => {
      if (event.event === 'connected') {
        setSocketState('connected');
        return;
      }
      if (event.event === 'disconnected') {
        setSocketState('disconnected');
        return;
      }
      if (event.event === 'error') {
        setSocketState('reconnecting');
        return;
      }
      if (event.type === 'telemetry' && event.payload && typeof event.payload === 'object' && 'event_type' in event.payload) {
        const next = { ...(event.payload as TelemetryEventRead), risk_score: event.risk_score };
        setLiveEvents((prev) => [next, ...prev].slice(0, 12));
      }
      if (event.type === 'alert' && event.payload && typeof event.payload === 'object' && 'entity' in event.payload) {
        setLastAlert(event.payload as AlertRead);
      }
      if (event.type === 'graph' && event.payload && typeof event.payload === 'object' && 'nodes' in event.payload && 'edges' in event.payload) {
        setGraph(event.payload as GraphRead);
      }
      if (event.type === 'remediation_executed') {
        setRemediationActivity((prev) => [{ action: event.action ?? 'remediation', device_id: event.device_id, alert_id: event.alert_id, received_at: new Date().toISOString() }, ...prev].slice(0, 12));
      }
      if (event.type === 'honeytoken_triggered') {
        void listHoneytokens().then(setHoneytokens).catch(() => undefined);
      }
    });
    return () => {
      ws.disconnect();
      socketRef.current = null;
    };
  }, [authUser]);

  const topRisk = useMemo(() => {
    const scored = liveEvents.map((item) => item.risk_score).filter((value): value is number => typeof value === 'number');
    return scored.length ? Math.round(Math.max(...scored)) : lastAlert?.risk_score ?? null;
  }, [lastAlert, liveEvents]);

  const filteredTelem = useMemo(() => {
    if (!search.trim()) return liveEvents;
    const q = search.toLowerCase();
    return liveEvents.filter((item) => `${item.user} ${item.source} ${item.destination} ${item.event_type}`.toLowerCase().includes(q));
  }, [liveEvents, search]);

  const handleSubmitEvent = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setEventSubmission({ loading: true, error: null, result: null });
    try {
      const result = await ingestEvent(eventForm);
      setEventSubmission({ loading: false, error: null, result });
      setLiveEvents((prev) => [{ ...result.event, risk_score: result.risk_score, anomaly_score: result.ml?.anomaly_score ?? undefined, confidence: result.ml?.confidence ?? undefined, detection_source: result.detection_source }, ...prev].slice(0, 20));
      if (result.alert) {
        setLastAlert(result.alert);
      }
      setEventForm((prev) => ({ ...prev, timestamp: new Date().toISOString() }));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Telemetry submission failed';
      setEventSubmission({ loading: false, error: message, result: null });
    }
  };

  const content = (() => {
    switch (activeScreen) {
      case 'telemetry':
        return <TelemetryPanel events={filteredTelem} eventForm={eventForm} setEventForm={setEventForm} onSubmit={handleSubmitEvent} submission={eventSubmission} />;
      case 'graph':
        return <GraphPanel graph={graph} />;
      case 'honeytokens':
        return <HoneytokenPanel tokens={honeytokens} onDeploy={async (payload) => { const next = await deployHoneytoken(payload); setHoneytokens((prev) => [next, ...prev]); }} onTrigger={async (tokenId) => { const next = await triggerHoneytoken(tokenId); setHoneytokens((prev) => prev.map((token) => token.id === next.honeytoken.id ? next.honeytoken : token)); }} />;
      case 'simulation':
        return <SimulationPanel simulation={simulation} setSimulation={setSimulation} />;
      case 'health':
        return <HealthPanel health={health} socketState={socketState} />;
      case 'reviews':
        return <ReviewPanel reviews={reviews} loading={reviewsLoading} error={reviewsError} onRefresh={async () => { setReviewsLoading(true); setReviewsError(null); try { setReviews(await listReviews()); } catch (error) { setReviewsError(error instanceof Error ? error.message : 'Reviews could not be loaded'); } finally { setReviewsLoading(false); } }} onDecision={async (reviewId, action, comment) => { const next = await decideReview(reviewId, action, comment); setReviews((prev) => prev.map((entry) => entry.id === next.id ? next : entry)); setReviews(await listReviews()); }} userRole={authUser?.role} />;
      default:
        return <OverviewPanel health={health} graph={graph} honeytokens={honeytokens} liveEvents={liveEvents} lastAlert={lastAlert} topRisk={topRisk} simulation={simulation} remediationActivity={remediationActivity} />;
    }
  })();

  if (authChecking) {
    return <AuthLoading />;
  }

  if (!authUser) {
    return <LoginScreen error={authError} email={loginEmail} password={loginPassword} onEmailChange={setLoginEmail} onPasswordChange={setLoginPassword} onLogin={async (email, password) => { setAuthError(null); try { setAuthUser(await login(email, password)); } catch { setAuthError('Invalid email or password'); } }} />;
  }

  return (
    <div className={`soc-shell ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="brand-mark">OS</div>
          <div className="brand-copy">
            {!sidebarCollapsed && <><div className="brand-name">Obsidian Sentinel</div><div className="brand-subtitle">SOC Command</div></>}
          </div>
          <button className="icon-btn sidebar-toggle" onClick={() => setSidebarCollapsed((value) => !value)} aria-label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'} title={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}>
            {sidebarCollapsed ? <Menu size={16} /> : <X size={16} />}
          </button>
        </div>
        <nav className="nav">
          {navItems.map(({ id, label, icon: Icon, group }, index) => (
            <div key={id} className="nav-entry">
              {!sidebarCollapsed && (index === 0 || navItems[index - 1].group !== group) ? <div className="nav-group-label">{group}</div> : null}
              <button className={`nav-item ${activeScreen === id ? 'active' : ''}`} onClick={() => setActiveScreen(id)} title={sidebarCollapsed ? label : undefined}>
                <Icon size={16} />
                {!sidebarCollapsed && <span>{label}</span>}
              </button>
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className={`status-dot ${socketState === 'connected' && health ? 'status-healthy' : socketState === 'connecting' || socketState === 'reconnecting' ? 'status-warn' : 'status-alert'}`} />
          {!sidebarCollapsed && <span>{socketState === 'connected' && health ? 'SOC online' : socketState}</span>}
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="search-box">
            <Search size={14} />
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search entity / host / user" aria-label="Search" />
          </div>
          <div className="topbar-right">
            <div className={`status-pill ${health ? 'success' : 'neutral'}`}>
              <div className={`status-dot ${health ? 'status-healthy' : 'status-alert'}`} />
              <span>{health ? 'backend online' : 'backend unavailable'}</span>
            </div>
            <div className="status-pill">
              <div className={`status-dot ${socketState === 'connected' ? 'status-healthy' : socketState === 'connecting' ? 'status-warn' : 'status-alert'}`} />
              <span>{socketState}</span>
            </div>
            <div className="identity-pill">
              <div className="identity-dot" />
              <div><strong>{authUser.email || authUser.username}</strong><span>{authUser.role}</span></div>
              <button className="text-btn" onClick={async () => { await logout().catch(() => undefined); setAuthUser(null); setLoginEmail(''); setLoginPassword(''); }} aria-label="Sign out">Sign out</button>
            </div>
            <div className="status-pill neutral">
              <Database size={14} />
              <span>{health?.ml_service_status ?? 'unknown'}</span>
            </div>
          </div>
        </header>

        <div className="page-wrap">
          {loadError ? <div className="notice error"><CircleAlert size={15} />{loadError}<button className="icon-btn" onClick={() => window.location.reload()} aria-label="Retry loading backend data"><RefreshCw size={14} /></button></div> : null}
          {loading ? <LoadingState /> : content}
        </div>
      </main>
    </div>
  );
}

function OverviewPanel({ health, graph, honeytokens, liveEvents, lastAlert, topRisk, simulation, remediationActivity }: { health: HealthRead | null; graph: GraphRead | null; honeytokens: HoneytokenRead[]; liveEvents: LiveEvent[]; lastAlert: AlertRead | null; topRisk: number | null; simulation: SimulationStatusRead | null; remediationActivity: RealtimeRemediation[]; }) {
  const severityCounts = liveEvents.reduce<Record<string, number>>((counts, event) => {
    const severity = getEventSeverity(event);
    counts[severity] = (counts[severity] ?? 0) + 1;
    return counts;
  }, {});
  const activityBars = liveEvents.slice(0, 10).reverse();

  return (
    <>
      <section className="hero-grid">
        <div className="hero-card large">
          <div className="card-header row-between">
            <div>
              <p className="eyebrow">Threat posture</p>
              <h2>{topRisk === null ? 'Risk posture unavailable' : `${topRisk}% risk posture`}</h2>
            </div>
            <div className={`chip ${simulation?.state === 'running' ? 'success' : simulation?.state === 'paused' ? 'warn' : 'neutral'}`}>{simulation?.state ?? 'unknown'}</div>
          </div>
          <div className="risk-line">
            <div className={`risk-ring ${topRisk === null ? 'neutral' : riskClass(topRisk)}`}>
              <span>{topRisk === null ? '—' : topRisk}</span>
            </div>
            <div className="risk-meta">
              <div><small>Telemetry</small><strong>{liveEvents.length}</strong></div>
              <div><small>Graph nodes</small><strong>{graph?.nodes.length ?? 0}</strong></div>
              <div><small>Honeytokens</small><strong>{honeytokens.length}</strong></div>
              <div><small>Actions</small><strong>{remediationActivity.length}</strong></div>
            </div>
          </div>
        </div>

        <div className="hero-card compact">
          <div className="card-header row-between">
            <p className="eyebrow">Backend</p>
            <StatusPill ok={Boolean(health)} />
          </div>
          <div className="metric-row">
            <div>
              <div className="metric-label">Connected</div>
              <div className="metric-value">{health ? 'online' : 'offline'}</div>
            </div>
            <div>
              <div className="metric-label">Connections</div>
              <div className="metric-value">{health?.websocket_connections ?? 0}</div>
            </div>
          </div>
        </div>

        <div className="hero-card compact">
          <div className="card-header row-between">
            <p className="eyebrow">ML</p>
            <StatusPill ok={Boolean(health?.ml_service_ready)} />
          </div>
          <div className="metric-row">
            <div>
              <div className="metric-label">URL</div>
              <div className="metric-value mono">{health?.ml_service_url ?? 'unknown'}</div>
            </div>
            <div>
              <div className="metric-label">Ready</div>
              <div className="metric-value">{health?.ml_inference_ready ? 'yes' : 'no'}</div>
            </div>
          </div>
        </div>
      </section>

      <section className="dashboard-grid">
        <Panel title="Live event stream">
          <div className="event-list">
            {liveEvents.length ? liveEvents.map((event) => (
              <div key={event.id} className="event-row">
                <div className={`severity-pill ${getEventSeverity(event)}`}>
                  {event.event_type}
                </div>
                <div className="event-main">
                  <strong>{event.user}</strong>
                  <span>{event.source} → {event.destination}</span>
                </div>
                <div className="event-time mono">{typeof event.risk_score === 'number' ? `${Math.round(event.risk_score)} risk` : 'unscored'}<br />{new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
              </div>
            )) : <div className="empty-box">Waiting for telemetry from the backend</div>}
          </div>
        </Panel>

        <Panel title="Activity signal">
          <div className="signal-card"><div className="signal-bars" aria-label="Recent telemetry activity">{activityBars.length ? activityBars.map((event) => <span key={event.id} className={`signal-bar ${getEventSeverity(event)}`} style={{ height: `${Math.max(12, Math.min(100, event.risk_score ?? 18))}%` }} title={`${event.event_type}: ${event.risk_score ?? 'unscored'} risk`} />) : <div className="empty-box">No activity signal yet</div>}</div><div className="signal-legend"><span><i className="legend-dot good" /> low</span><span><i className="legend-dot warn" /> medium</span><span><i className="legend-dot critical" /> high</span></div></div>
          <div className="severity-summary">{['critical', 'warn', 'good'].map((severity) => <div key={severity}><span className={`legend-dot ${severity}`} /> <strong>{severityCounts[severity] ?? 0}</strong><small>{severity}</small></div>)}</div>
        </Panel>

        <Panel title="Recent alert">
          {lastAlert ? (
            <div className="alert-panel">
              <div className="alert-header">
                <ShieldAlert size={18} />
                <span>{lastAlert.entity}</span>
              </div>
              <div className="score-block">{Math.round(lastAlert.risk_score)}</div>
              <div className="alert-footer">{lastAlert.status}</div>
            </div>
          ) : (
            <div className="empty-box">Waiting for backend WebSocket alerts</div>
          )}
        </Panel>

        <Panel title="Attack graph preview">
          <GraphPreview graph={graph} />
        </Panel>

        <Panel title="Honeytoken activity">
          <div className="stack-list">
            {honeytokens.length ? honeytokens.map((token) => (
              <div key={token.id} className="stack-row">
                <span>{token.name}</span>
                <div className={`chip ${token.status === 'triggered' ? 'alert' : 'success'}`}>{token.status}</div>
              </div>
            )) : <div className="empty-box">No honeytokens</div>}
          </div>
        </Panel>
      </section>
    </>
  );
}

function TelemetryPanel({ events, eventForm, setEventForm, onSubmit, submission }: { events: LiveEvent[]; eventForm: TelemetryEventCreate; setEventForm: React.Dispatch<React.SetStateAction<TelemetryEventCreate>>; onSubmit: (event: React.FormEvent<HTMLFormElement>) => Promise<void>; submission: { loading: boolean; error: string | null; result: EventPipelineResult | null }; }) {
  const [selectedEvent, setSelectedEvent] = useState<LiveEvent | null>(null);
  const costEstimate = submission.result?.estimated_cost;

  return (
    <Panel title="Telemetry explorer">
      <div className="panel-context"><span className="chip success">LIVE</span><span className="muted">Showing events observed in this browser session. Historical event retrieval is not exposed by the backend.</span></div>
      <form className="telemetry-form" onSubmit={onSubmit}>
        <div className="field-grid">
          <label>
            <span>Timestamp</span>
            <input type="datetime-local" value={eventForm.timestamp.slice(0, 16)} onChange={(e) => setEventForm((prev) => ({ ...prev, timestamp: new Date(e.target.value).toISOString() }))} />
          </label>
          <label>
            <span>Source</span>
            <input value={eventForm.source} onChange={(e) => setEventForm((prev) => ({ ...prev, source: e.target.value }))} required />
          </label>
          <label>
            <span>Destination</span>
            <input value={eventForm.destination} onChange={(e) => setEventForm((prev) => ({ ...prev, destination: e.target.value }))} required />
          </label>
          <label>
            <span>User</span>
            <input value={eventForm.user} onChange={(e) => setEventForm((prev) => ({ ...prev, user: e.target.value }))} required />
          </label>
          <label>
            <span>Event Type</span>
            <select value={eventForm.event_type} onChange={(e) => setEventForm((prev) => ({ ...prev, event_type: e.target.value as TelemetryEventCreate['event_type'] }))}>
              <option value="login">login</option>
              <option value="logout">logout</option>
              <option value="auth_failure">auth_failure</option>
              <option value="file_access">file_access</option>
              <option value="process_start">process_start</option>
              <option value="network_connection">network_connection</option>
              <option value="dns_query">dns_query</option>
              <option value="privilege_escalation">privilege_escalation</option>
              <option value="lateral_movement">lateral_movement</option>
              <option value="data_exfiltration">data_exfiltration</option>
              <option value="malware_detected">malware_detected</option>
              <option value="honeytoken_triggered">honeytoken_triggered</option>
            </select>
          </label>
          <label>
            <span>Status</span>
            <select value={eventForm.status} onChange={(e) => setEventForm((prev) => ({ ...prev, status: e.target.value as TelemetryEventCreate['status'] }))}>
              <option value="success">success</option>
              <option value="failure">failure</option>
              <option value="allowed">allowed</option>
              <option value="blocked">blocked</option>
              <option value="suspicious">suspicious</option>
            </select>
          </label>
        </div>
        <div className="form-actions">
          <button type="submit" className="action-btn" disabled={submission.loading}>{submission.loading ? 'Submitting...' : 'Ingest event'}</button>
        </div>
        {submission.error ? <div className="empty-box alert">{submission.error}</div> : null}
        {submission.result ? (
          <div className="result-box-wrap">
            <div className="result-box"><strong>Pipeline result:</strong> risk {submission.result.risk_score} / policy {submission.result.policy.action ?? 'n/a'}</div>
            {costEstimate ? (
              <div className="cost-estimate-box">
                <div className="row-between">
                  <span className="eyebrow">Estimated cost</span>
                  <span className="chip neutral">{costEstimate.estimate_label}</span>
                </div>
                <div className="cost-grid">
                  <div className="cost-row"><span>Events processed</span><strong>{costEstimate.event_count}</strong></div>
                  <div className="cost-row"><span>Incident count</span><strong>{costEstimate.incident_count}</strong></div>
                  <div className="cost-row"><span>Estimated cost per event</span><strong>{formatCurrency(costEstimate.cost_per_event)}</strong></div>
                  <div className="cost-row"><span>Estimated cost per incident</span><strong>{costEstimate.cost_per_incident == null ? '—' : formatCurrency(costEstimate.cost_per_incident)}</strong></div>
                  <div className="cost-row total"><span>Estimated total run cost</span><strong>{formatCurrency(costEstimate.total_cost)}</strong></div>
                </div>
              </div>
            ) : null}
          </div>
        ) : null}
      </form>
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>User</th>
              <th>Destination</th>
              <th>Type</th>
              <th>Status</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {events.length ? events.map((event) => (
              <tr key={event.id} className={selectedEvent?.id === event.id ? 'selected-row' : ''} onClick={() => setSelectedEvent(event)} tabIndex={0} onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === 'Enter') setSelectedEvent(event); }}>
                <td className="mono">{new Date(event.timestamp).toLocaleString()}</td>
                <td>{event.source}</td>
                <td>{event.user}</td>
                <td>{event.destination}</td>
                <td><span className={`severity-pill ${getEventSeverity(event)}`}>{event.event_type}</span></td>
                <td>{event.status}</td>
                <td className="mono">{typeof event.risk_score === 'number' ? Math.round(event.risk_score) : '—'}</td>
              </tr>
            )) : <tr><td colSpan={7} className="empty-cell">No telemetry available from the backend yet</td></tr>}
          </tbody>
        </table>
      </div>
      {selectedEvent ? <div className="detail-drawer telemetry-detail"><div className="row-between"><div><span className="eyebrow">Event detail</span><h3>{selectedEvent.event_type}</h3></div><button className="icon-btn" onClick={() => setSelectedEvent(null)} aria-label="Close event details"><X size={15} /></button></div><div className="detail-grid"><span>Risk <strong>{selectedEvent.risk_score === undefined ? 'unscored' : `${Math.round(selectedEvent.risk_score)} / 100`}</strong></span><span>Status <strong>{selectedEvent.status}</strong></span><span>User <strong className="mono">{selectedEvent.user}</strong></span><span>Source <strong className="mono">{selectedEvent.source}</strong></span><span>Destination <strong className="mono">{selectedEvent.destination}</strong></span><span>Timestamp <strong className="mono">{new Date(selectedEvent.timestamp).toLocaleString()}</strong></span></div></div> : null}
    </Panel>
  );
}

function GraphPanel({ graph }: { graph: GraphRead | null }) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [neighbors, setNeighbors] = useState<GraphRead['nodes']>([]);
  const [neighborState, setNeighborState] = useState<'idle' | 'loading' | 'error'>('idle');
  const selected = nodes.find((node) => node.id === selectedId);

  const selectNode = async (nodeId: string) => {
    setSelectedId(nodeId);
    setNeighborState('loading');
    try {
      setNeighbors(await getGraphNeighbors(nodeId));
      setNeighborState('idle');
    } catch {
      setNeighbors([]);
      setNeighborState('error');
    }
  };

  return (
    <Panel title="Attack graph">
      <div className="graph-toolbar">
        <div><span className="eyebrow">Entity relationship map</span><span className="graph-count">{nodes.length} nodes / {edges.length} edges</span></div>
        {selected ? <span className="chip">Focused: {selected.data.label}</span> : <span className="chip neutral">Select an entity</span>}
      </div>
      <div className="graph-stage interactive">
        <svg viewBox="0 0 1250 600" role="img" aria-label="Threat graph">
          {edges.map((edge) => {
            const src = nodes.find((node) => node.id === edge.source);
            const dst = nodes.find((node) => node.id === edge.target);
            if (!src || !dst) return null;
            return (
              <line key={edge.id} x1={src.position.x + 45} y1={src.position.y + 20} x2={dst.position.x + 45} y2={dst.position.y + 20} stroke="rgba(173,198,255,0.45)" strokeWidth={1.8} />
            );
          })}
          {nodes.map((node) => (
            <g key={node.id} className={selectedId === node.id ? 'graph-node selected' : 'graph-node'} transform={`translate(${node.position.x}, ${node.position.y})`} onClick={() => void selectNode(node.id)} tabIndex={0} role="button" aria-label={`Select ${node.data.label}`} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') void selectNode(node.id); }}>
              <circle r={selectedId === node.id ? 31 : 26} fill={node.data.risk_score > 80 ? '#ff7b72' : node.data.risk_score > 55 ? '#fbbf24' : '#7dd3fc'} opacity={0.9} />
              <text x={0} y={44} textAnchor="middle" fill="#e2e2e8" fontSize="10">{node.data.label}</text>
            </g>
          ))}
        </svg>
      </div>
      <div className="graph-detail">
        {selected ? <><div className="row-between"><div><span className="eyebrow">Selected entity</span><strong>{selected.data.label}</strong></div><span className={`severity-pill ${riskClass(selected.data.risk_score)}`}>{Math.round(selected.data.risk_score)} risk</span></div><div className="detail-meta mono">{selected.data.entity_type} · {selected.data.entity}</div><div className="neighbor-list"><span className="eyebrow">Neighbors</span>{neighborState === 'loading' ? <LoaderCircle className="spin" size={15} /> : neighborState === 'error' ? <span className="muted">Neighbor lookup unavailable</span> : neighbors.length ? neighbors.map((node) => <button key={node.id} className="chip" onClick={() => void selectNode(node.id)}>{node.data.label}</button>) : <span className="muted">No connected entities</span>}</div></> : <div className="empty-box">Select a node to inspect its real relationships</div>}
      </div>
    </Panel>
  );
}

function HoneytokenPanel({ tokens, onDeploy, onTrigger }: { tokens: HoneytokenRead[]; onDeploy: (payload: { type: string; name: string; description?: string }) => Promise<void>; onTrigger: (tokenId: string) => Promise<void> }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [events, setEvents] = useState<HoneytokenEventRead[]>([]);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [deployOpen, setDeployOpen] = useState(false);
  const [name, setName] = useState('Finance backup credential');
  const [type, setType] = useState('credential');
  const selected = tokens.find((token) => token.id === selectedId);

  const inspectToken = async (tokenId: string) => {
    setSelectedId(tokenId);
    setActionError(null);
    try {
      setEvents(await listHoneytokenEvents(tokenId));
    } catch (caught) {
      setEvents([]);
      setActionError(caught instanceof Error ? caught.message : 'Token events could not be loaded');
    }
  };

  const deploy = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setActionError(null);
    try {
      await onDeploy({ type, name });
      setDeployOpen(false);
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : 'Honeytoken deployment failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Honeytoken operations">
      <div className="panel-actions"><span className="muted">Decoys are backend-managed and never displayed as real secrets.</span><button className="action-btn" onClick={() => setDeployOpen(true)}><Plus size={14} /> Deploy token</button></div>
      {actionError ? <div className="notice error"><CircleAlert size={15} />{actionError}</div> : null}
      {deployOpen ? <form className="deploy-form" onSubmit={(event) => void deploy(event)}><label><span>Name</span><input value={name} onChange={(event) => setName(event.target.value)} required /></label><label><span>Type</span><select value={type} onChange={(event) => setType(event.target.value)}><option value="credential">credential</option><option value="file">file</option><option value="url">url</option><option value="canary">canary</option></select></label><div className="form-actions"><button className="action-btn" disabled={busy} type="submit">{busy ? <LoaderCircle className="spin" size={14} /> : <Check size={14} />} {busy ? 'Deploying...' : 'Confirm deployment'}</button><button className="text-btn" type="button" onClick={() => setDeployOpen(false)}>Cancel</button></div></form> : null}
      <div className="token-grid">
        {tokens.length ? tokens.map((token) => (
          <div key={token.id} className={`token-card ${selectedId === token.id ? 'selected' : ''}`}>
            <div className="card-header row-between">
              <div>
                <p className="eyebrow">Token</p>
                <h3>{token.name}</h3>
              </div>
              <div className={`chip ${token.status === 'triggered' ? 'alert' : 'success'}`}>{token.status}</div>
            </div>
            <div className="token-meta">
              <span>{token.type}</span>
              <span className="mono">{token.id}</span>
            </div>
            <p className="token-value mono">{token.value}</p>
            <div className="button-row"><button className="action-btn" onClick={async () => { setActionError(null); try { await onTrigger(token.id); } catch (caught) { setActionError(caught instanceof Error ? caught.message : 'Honeytoken trigger failed'); } }} disabled={token.status !== 'active'}><Crosshair size={14} /> {token.status === 'active' ? 'Trigger token' : 'Already triggered'}</button><button className="text-btn" onClick={() => void inspectToken(token.id)}>View events <ChevronRight size={14} /></button></div>
          </div>
        )) : <div className="empty-box">No active honeytokens</div> }
      </div>
      {selected ? <div className="detail-drawer"><div className="row-between"><div><span className="eyebrow">Token activity</span><h3>{selected.name}</h3></div><button className="icon-btn" onClick={() => setSelectedId(null)} aria-label="Close token details"><X size={15} /></button></div>{events.length ? events.map((entry) => <div className="event-row" key={`${entry.event.id}-${entry.duplicate}`}><span className="severity-pill critical">{entry.severity}</span><div className="event-main"><strong>{entry.event.user} · {entry.event.source}</strong><span>{entry.event.destination} · confidence {entry.confidence.toFixed(2)}</span></div><span className="score-inline">{Math.round(entry.risk_score)}</span></div>) : <div className="empty-box">No recorded trigger events</div>}</div> : null}
    </Panel>
  );
}

function SimulationPanel({ simulation, setSimulation }: { simulation: SimulationStatusRead | null; setSimulation: (value: SimulationStatusRead) => void }) {
  const state = simulation?.state ?? 'idle';
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [filePath, setFilePath] = useState('../autonomous-threat-defense/data/raw/auth.txt.gz');
  const controls = [
    { label: 'Start', allowed: state === 'idle' || state === 'stopped', action: () => startSimulation({ file_path: filePath, speed_multiplier: 1.5, limit: 250 }), icon: Play },
    { label: 'Pause', allowed: state === 'running', action: pauseSimulation, icon: TimerReset },
    { label: 'Resume', allowed: state === 'paused', action: resumeSimulation, icon: Radar },
    { label: 'Stop', allowed: state === 'running' || state === 'paused', action: stopSimulation, icon: Shield },
  ];

  const runControl = async (label: string, action: () => Promise<SimulationStatusRead>) => {
    setBusy(label);
    setError(null);
    try { setSimulation(await action()); } catch (caught) { setError(caught instanceof Error ? caught.message : 'Simulation request failed'); } finally { setBusy(null); }
  };

  return (
    <Panel title="Simulation control center">
      <div className="simulation-header">
        <div>
          <p className="eyebrow">Current state</p>
          <h3>{state}</h3>
        </div>
        <div className={`chip ${state === 'running' ? 'success' : state === 'paused' ? 'warn' : 'neutral'}`}>{state}</div>
      </div>
      <div className="simulation-config"><label><span>Replay source</span><input value={filePath} onChange={(event) => setFilePath(event.target.value)} disabled={state === 'running' || state === 'paused'} aria-label="Simulation replay source" /></label><span className="muted">Path is resolved by the backend process.</span></div>
      <div className="button-row">
        {controls.map(({ label, allowed, action, icon: Icon }) => (
          <button key={label} className="action-btn" disabled={!allowed || busy !== null} onClick={() => void runControl(label, action)}>
            {busy === label ? <LoaderCircle className="spin" size={14} /> : <Icon size={14} />} {busy === label ? 'Working...' : label}
          </button>
        ))}
      </div>
      {error ? <div className="notice error"><CircleAlert size={15} />{error}</div> : null}
      <div className="simulation-state"><span className={`state-orb ${state}`} /><div><strong>{simulation?.message || 'Waiting for backend simulation state'}</strong><small>Controls are enabled only for valid backend transitions.</small></div></div>
    </Panel>
  );
}

function ReviewPanel({ reviews, loading, error, onRefresh, onDecision, userRole }: { reviews: HumanReviewRead[]; loading: boolean; error: string | null; onRefresh: () => void; onDecision: (reviewId: string, action: 'approve' | 'reject' | 'escalate', comment?: string) => Promise<void>; userRole?: string; }) {
  const [decisionComment, setDecisionComment] = useState<Record<string, string>>({});
  const [pendingAction, setPendingAction] = useState<Record<string, 'approve' | 'reject' | 'escalate' | null>>({});
  const canDecide = userRole === 'admin' || userRole === 'analyst';

  return (
    <Panel title="Pending Reviews">
      <div className="panel-actions">
        <span className="muted">Analyst decision queue for high-risk automated actions.</span>
        <button className="action-btn" onClick={onRefresh} disabled={loading}><RefreshCw size={14} className={loading ? 'spin' : ''} /> {loading ? 'Refreshing...' : 'Refresh'}</button>
      </div>
      {error ? <div className="notice error"><CircleAlert size={15} />{error}</div> : null}
      <div className="review-list">
        {loading && !reviews.length ? <div className="empty-box">Loading review queue…</div> : reviews.length ? reviews.map((review) => (
          <div key={review.id} className="review-card">
            <div className="row-between">
              <div>
                <span className="eyebrow">Review #{review.id.slice(0, 8)}</span>
                <h3>{review.action_type ?? 'manual review'}</h3>
              </div>
              <span className={`chip ${review.status === 'approved' ? 'success' : review.status === 'rejected' ? 'neutral' : review.status === 'escalated' ? 'warn' : 'alert'}`}>{review.status}</span>
            </div>
            <div className="detail-grid review-grid">
              <span>Incident / Event <strong className="mono">{review.event_id}</strong></span>
              <span>Alert <strong className="mono">{review.alert_id ?? 'n/a'}</strong></span>
              <span>Risk <strong>{Math.round(review.risk_score)} / 100</strong></span>
              <span>Created <strong className="mono">{new Date(review.created_at).toLocaleString()}</strong></span>
              <span>Status <strong>{review.status}</strong></span>
              <span>Reviewer <strong>{review.reviewed_by ?? 'pending'}</strong></span>
            </div>
            <div className="review-summaries">
              <div><span className="eyebrow">Evidence / reason</span><p>{review.reason}</p></div>
              <div><span className="eyebrow">Decision summary</span><p>{review.review_comment ?? 'No analyst decision recorded yet.'}</p></div>
            </div>
            {canDecide && (
              <>
                <label className="review-comment">
                  <span>Analyst comment</span>
                  <textarea value={decisionComment[review.id] ?? ''} onChange={(event) => setDecisionComment((prev) => ({ ...prev, [review.id]: event.target.value }))} placeholder="Add a brief decision note…" rows={3} />
                </label>
                <div className="button-row review-actions">
                  {(['approve', 'reject', 'escalate'] as const).map((action) => (
                    <button
                      key={action}
                      className="action-btn"
                      disabled={pendingAction[review.id] === action || review.status !== 'pending'}
                      onClick={async () => {
                        setPendingAction((prev) => ({ ...prev, [review.id]: action }));
                        try {
                          await onDecision(review.id, action, decisionComment[review.id]);
                        } finally {
                          setPendingAction((prev) => ({ ...prev, [review.id]: null }));
                        }
                      }}
                    >
                      {pendingAction[review.id] === action ? 'Working...' : action}
                    </button>
                  ))}
                </div>
              </>
            )}
            {!canDecide && <div className="notice neutral">Your {userRole} role cannot perform review actions. Contact an administrator if this is incorrect.</div>}
            {review.reviewed_at ? <div className="review-footer">Decision recorded by {review.reviewed_by ?? 'unknown'} at {new Date(review.reviewed_at).toLocaleString()}</div> : null}
          </div>
        )) : <div className="empty-box">No pending human review items</div>}
      </div>
    </Panel>
  );
}

function HealthPanel({ health, socketState }: { health: HealthRead | null; socketState: ConnectionState }) {
  const backendState = health?.status === 'ok' ? 'healthy' : 'unavailable';
  const mlState = health ? (health.ml_service_usable ? 'healthy' : health.ml_service_reachable ? 'degraded' : 'unavailable') : 'unknown';
  const socketHealth = socketState === 'connected' ? 'healthy' : socketState === 'connecting' || socketState === 'reconnecting' ? 'degraded' : 'unavailable';
  return (
    <Panel title="System health">
      <div className="health-grid">
        <MetricCard icon={<Cpu size={18} />} label="Backend" value={health ? 'Online' : 'Unavailable'} status={backendState} />
        <MetricCard icon={<Gauge size={18} />} label="ML inference" value={health?.ml_inference_ready ? 'Ready' : health?.ml_service_status ?? 'unknown'} status={mlState} />
        <MetricCard icon={<Globe size={18} />} label="ML service URL" value={health?.ml_service_url ?? 'unknown'} status={health?.ml_service_reachable ? 'healthy' : health ? 'unavailable' : 'unknown'} />
        <MetricCard icon={<Wifi size={18} />} label="WebSocket" value={health ? `${health.websocket_connections} clients · ${socketState}` : socketState} status={socketHealth} />
      </div>
      {health ? <div className="health-facts"><span>Service <strong>{health.service}</strong></span><span>Version <strong className="mono">{health.version}</strong></span><span>Graph <strong>{health.graph_nodes} nodes / {health.graph_edges} edges</strong></span><span>Simulation <strong>{health.simulation_state}</strong></span></div> : <div className="empty-box">Root health endpoint is unavailable</div>}
    </Panel>
  );
}

function LoadingState() {
  return <section className="loading-state" aria-live="polite"><LoaderCircle className="spin" size={20} /><span>Loading live SOC resources</span></section>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h3>{title}</h3>
        <ChevronRight size={16} />
      </div>
      {children}
    </section>
  );
}

function MetricCard({ icon, label, value, status }: { icon: React.ReactNode; label: string; value: string; status: 'healthy' | 'degraded' | 'unavailable' | 'unknown' }) {
  return (
    <div className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
      </div>
      <StatusPill status={status} />
    </div>
  );
}

function StatusPill({ status, ok }: { status?: 'healthy' | 'degraded' | 'unavailable' | 'unknown'; ok?: boolean }) {
  const resolved = status ?? (ok ? 'healthy' : 'unavailable');
  return <span className={`status-pill inline ${resolved === 'healthy' ? 'success' : resolved === 'degraded' ? 'warn' : 'neutral'}`}><span className={`status-dot ${resolved === 'healthy' ? 'status-healthy' : resolved === 'degraded' ? 'status-warn' : 'status-alert'}`} /> {resolved}</span>;
}

function GraphPreview({ graph }: { graph: GraphRead | null }) {
  const nodes = graph?.nodes.slice(0, 6) ?? [];
  return (
    <div className="mini-graph">
      {nodes.map((node, index) => (
        <div key={node.id} className="mini-node" style={{ left: `${10 + index * 18}%`, top: `${20 + (index % 3) * 22}%` }}>
          <span>{node.data.label.slice(0, 3)}</span>
        </div>
      ))}
    </div>
  );
}

function AuthLoading() {
  return <main className="auth-shell"><section className="auth-card loading-state"><LoaderCircle className="spin" size={20} /><span>Restoring secure session</span></section></main>;
}

function LoginScreen({ error, email, password, onEmailChange, onPasswordChange, onLogin }: { error: string | null; email: string; password: string; onEmailChange: (value: string) => void; onPasswordChange: (value: string) => void; onLogin: (email: string, password: string) => Promise<void> }) {
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      await onLogin(email, password);
    } finally {
      setSubmitting(false);
    }
  };

  return <main className="auth-shell"><section className="auth-card" aria-labelledby="login-title"><div className="auth-brand"><div className="brand-mark">OS</div><div><div className="brand-name">Obsidian Sentinel</div><div className="brand-subtitle">SOC Command</div></div></div><div className="auth-heading"><span className="eyebrow">Secure access</span><h1 id="login-title">Sign in to operations</h1><p>Authenticate to access the live SOC workspace.</p></div><form className="auth-form" onSubmit={(event) => void submit(event)}><label><span>Email</span><input type="email" value={email} onChange={(event) => onEmailChange(event.target.value)} autoComplete="email" required /></label><label><span>Password</span><input type="password" value={password} onChange={(event) => onPasswordChange(event.target.value)} autoComplete="current-password" required /></label>{error ? <div className="notice error" role="alert"><CircleAlert size={15} />{error}</div> : null}<button className="action-btn auth-submit" type="submit" disabled={submitting}>{submitting ? <LoaderCircle className="spin" size={15} /> : <Shield size={15} />}{submitting ? 'Signing in...' : 'Sign in'}</button></form><div className="auth-footnote">Enterprise multi-user authentication · role-based access control</div></section></main>;
}

function getEventSeverity(event: TelemetryEventRead) {
  if (event.event_type === 'lateral_movement' || event.event_type === 'data_exfiltration' || event.status === 'failure') return 'critical';
  if (event.status === 'suspicious') return 'warn';
  return 'good';
}

function riskClass(risk: number) {
  if (risk >= 80) return 'critical';
  if (risk >= 55) return 'warn';
  return 'good';
}

function formatCurrency(value: number | null | undefined) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return '—';
  }
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 4,
  }).format(value);
}

export default App;
