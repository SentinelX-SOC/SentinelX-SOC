import { useMemo, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { getGraphNeighbors } from '../api/graph';
import type { AlertRead, GraphNodeRead, GraphRead, HumanReviewRead, LiveEvent, RealtimeRemediation } from '../types/api';
import {
  ATTACK_ROLE_LABEL,
  GRAPH_VIEW,
  ROLE_X,
  attackRoleForNode,
  edgeVisualState,
  layoutAttackGraph,
  nodeVisualState,
  relatedEventsForNode,
  type AttackRole,
  type NodeVisualState,
} from './attackPath';
import { TelemetryInspector } from './TelemetryInspector';

const STAGE_ROLES: AttackRole[] = ['entry_point', 'internal_server', 'crown_jewel'];

export function AttackGraph({
  graph,
  liveEvents,
  lastAlert,
  remediations,
  reviews,
}: {
  graph: GraphRead | null;
  liveEvents: LiveEvent[];
  lastAlert: AlertRead | null;
  remediations: RealtimeRemediation[];
  reviews: HumanReviewRead[];
}) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [neighbors, setNeighbors] = useState<GraphNodeRead[]>([]);
  const [neighborState, setNeighborState] = useState<'idle' | 'loading' | 'error'>('idle');

  const positions = useMemo(() => layoutAttackGraph(nodes), [nodes]);
  const nodesById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selected = nodes.find((node) => node.id === selectedId) ?? null;
  const selectedRole = selected ? attackRoleForNode(selected) : null;
  const selectedState = selected
    ? nodeVisualState(selected, liveEvents, remediations, reviews, lastAlert)
    : null;

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
    <section className="panel">
      <div className="panel-header">
        <h3>Attack graph</h3>
        <ChevronRight size={16} />
      </div>
      <div className="graph-toolbar">
        <div>
          <span className="eyebrow">Live kill-chain map</span>
          <span className="graph-count">{nodes.length} nodes / {edges.length} active paths</span>
        </div>
        <div className="graph-legend">
          <span><i className="legend-swatch compromised" /> compromised</span>
          <span><i className="legend-swatch defended" /> defended</span>
          <span><i className="legend-swatch cleared" /> blocked vector</span>
        </div>
      </div>
      <div className="attack-graph-shell">
        <div className="graph-stage interactive attack-canvas">
          <svg viewBox={`0 0 ${GRAPH_VIEW.width} ${GRAPH_VIEW.height}`} role="img" aria-label="Attack graph">
            {STAGE_ROLES.map((role) => (
              <text key={role} x={ROLE_X[role]} y={36} textAnchor="middle" className="graph-stage-label">
                {ATTACK_ROLE_LABEL[role]}
              </text>
            ))}
            {STAGE_ROLES.map((role, index) => (
              index < STAGE_ROLES.length - 1 ? (
                <line
                  key={`${role}-rail`}
                  className="graph-stage-rail"
                  x1={ROLE_X[role] + 48}
                  y1={48}
                  x2={ROLE_X[STAGE_ROLES[index + 1]] - 48}
                  y2={48}
                />
              ) : null
            ))}
            {edges.map((edge) => {
              const source = positions.get(edge.source);
              const target = positions.get(edge.target);
              if (!source || !target) {
                return null;
              }
              const visual = edgeVisualState(edge, nodesById, liveEvents, remediations, reviews, lastAlert);
              return (
                <line
                  key={edge.id}
                  className={`graph-edge ${visual}`}
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                />
              );
            })}
            {nodes.length === 0 ? STAGE_ROLES.map((role) => (
              <g key={role} className="graph-node idle placeholder" transform={`translate(${ROLE_X[role]}, 220)`}>
                <circle className="node-ring" r={30} />
                <circle className="node-core" r={22} />
                <text x={0} y={52} textAnchor="middle">{ATTACK_ROLE_LABEL[role]}</text>
              </g>
            )) : nodes.map((node) => {
              const point = positions.get(node.id) ?? node.position;
              const visual: NodeVisualState = nodeVisualState(node, liveEvents, remediations, reviews, lastAlert);
              const role = attackRoleForNode(node);
              const selectedNode = selectedId === node.id;
              return (
                <g
                  key={node.id}
                  className={`graph-node ${visual}${selectedNode ? ' selected' : ''}`}
                  transform={`translate(${point.x}, ${point.y})`}
                  onClick={() => void selectNode(node.id)}
                  tabIndex={0}
                  role="button"
                  aria-label={`Inspect ${ATTACK_ROLE_LABEL[role]} ${node.data.label}`}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      void selectNode(node.id);
                    }
                  }}
                >
                  <circle className="node-ring" r={selectedNode ? 34 : 30} />
                  <circle className="node-core" r={selectedNode ? 24 : 21} />
                  <text x={0} y={48} textAnchor="middle">{node.data.label}</text>
                  <text x={0} y={64} textAnchor="middle" className="node-role">{ATTACK_ROLE_LABEL[role]}</text>
                </g>
              );
            })}
          </svg>
        </div>
        <TelemetryInspector
          node={selected}
          role={selectedRole}
          state={selectedState}
          events={selected ? relatedEventsForNode(selected, liveEvents) : []}
          neighbors={neighbors}
          neighborState={neighborState}
          onClose={() => {
            setSelectedId(null);
            setNeighbors([]);
            setNeighborState('idle');
          }}
          onSelectNeighbor={(nodeId) => void selectNode(nodeId)}
        />
      </div>
    </section>
  );
}

export function AttackGraphPreview({
  graph,
  liveEvents,
  lastAlert,
  remediations,
  reviews,
}: {
  graph: GraphRead | null;
  liveEvents: LiveEvent[];
  lastAlert: AlertRead | null;
  remediations: RealtimeRemediation[];
  reviews: HumanReviewRead[];
}) {
  const nodes = graph?.nodes ?? [];
  const byRole = STAGE_ROLES.map((role) => {
    const members = nodes.filter((node) => attackRoleForNode(node) === role);
    const hottest = [...members].sort((left, right) => right.data.risk_score - left.data.risk_score)[0] ?? null;
    const state = hottest
      ? nodeVisualState(hottest, liveEvents, remediations, reviews, lastAlert)
      : 'idle';
    return { role, hottest, state, count: members.length };
  });

  return (
    <div className="mini-graph attack-preview">
      {byRole.map(({ role, hottest, state, count }, index) => (
        <div key={role} className={`mini-stage ${state}`}>
          <span className="mini-stage-label">{ATTACK_ROLE_LABEL[role]}</span>
          <span className="mini-stage-entity">{hottest?.data.label ?? 'awaiting live data'}</span>
          <span className="mini-stage-meta">{count} entit{count === 1 ? 'y' : 'ies'}</span>
          {index < byRole.length - 1 ? <span className="mini-stage-arrow" aria-hidden="true" /> : null}
        </div>
      ))}
    </div>
  );
}
