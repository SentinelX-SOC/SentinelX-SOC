import { LoaderCircle, X } from 'lucide-react';
import type { GraphNodeRead, LiveEvent } from '../types/api';
import { ATTACK_ROLE_LABEL, affectedService, type AttackRole, type NodeVisualState } from './attackPath';

export function TelemetryInspector({
  node,
  role,
  state,
  events,
  neighbors,
  neighborState,
  onClose,
  onSelectNeighbor,
}: {
  node: GraphNodeRead | null;
  role: AttackRole | null;
  state: NodeVisualState | null;
  events: LiveEvent[];
  neighbors: GraphNodeRead[];
  neighborState: 'idle' | 'loading' | 'error';
  onClose: () => void;
  onSelectNeighbor: (nodeId: string) => void;
}) {
  if (!node || !role || !state) {
    return (
      <aside className="telemetry-inspector empty" aria-label="Telemetry inspector">
        <span className="eyebrow">Inspect</span>
        <h3>Select a graph node</h3>
        <p className="muted">Click an entity to open live telemetry, risk score, and the affected service.</p>
      </aside>
    );
  }

  const risk = Math.round(node.data.risk_score);

  return (
    <aside className="telemetry-inspector" aria-label={`Telemetry for ${node.data.label}`}>
      <div className="row-between">
        <div>
          <span className="eyebrow">Telemetry inspector</span>
          <h3>{node.data.label}</h3>
        </div>
        <button className="icon-btn" onClick={onClose} aria-label="Close inspector">
          <X size={15} />
        </button>
      </div>
      <div className="inspector-chips">
        <span className="chip">{ATTACK_ROLE_LABEL[role]}</span>
        <span className={`chip ${state === 'compromised' ? 'alert' : state === 'defended' ? 'success' : 'neutral'}`}>{state}</span>
      </div>
      <div className="inspector-risk">
        <span className="eyebrow">Risk score</span>
        <strong>{risk} / 100</strong>
        <div className="risk-meter" aria-hidden="true">
          <i style={{ width: `${Math.min(100, risk)}%` }} className={risk >= 70 ? 'critical' : risk >= 40 ? 'warn' : 'good'} />
        </div>
      </div>
      <div className="detail-grid inspector-facts">
        <span>Affected service <strong className="mono">{affectedService(node)}</strong></span>
        <span>Entity type <strong>{node.data.entity_type}</strong></span>
        <span>Events seen <strong>{String(node.data.properties?.event_count ?? events.length)}</strong></span>
      </div>
      <div className="inspector-section">
        <span className="eyebrow">Related telemetry</span>
        {events.length ? events.slice(0, 6).map((event) => (
          <div className="event-row" key={event.id}>
            <span className={`severity-pill ${event.status === 'blocked' ? 'good' : event.status === 'failure' || event.status === 'suspicious' ? 'critical' : 'warn'}`}>{event.event_type}</span>
            <div className="event-main">
              <strong>{event.user} → {event.destination}</strong>
              <span>{event.source} · {event.status}{typeof event.risk_score === 'number' ? ` · risk ${Math.round(event.risk_score)}` : ''}</span>
            </div>
          </div>
        )) : <p className="muted">No live telemetry for this entity yet.</p>}
      </div>
      <div className="inspector-section">
        <span className="eyebrow">Neighbors</span>
        {neighborState === 'loading' ? <LoaderCircle className="spin" size={15} /> : neighborState === 'error' ? <span className="muted">Neighbor lookup unavailable</span> : neighbors.length ? (
          <div className="neighbor-list">
            {neighbors.map((neighbor) => (
              <button key={neighbor.id} className="chip" onClick={() => onSelectNeighbor(neighbor.id)}>{neighbor.data.label}</button>
            ))}
          </div>
        ) : <span className="muted">No connected entities</span>}
      </div>
    </aside>
  );
}
