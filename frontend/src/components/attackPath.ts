import type {
  AlertRead,
  GraphEdgeRead,
  GraphNodeRead,
  HumanReviewRead,
  LiveEvent,
  Position,
  RealtimeRemediation,
} from '../types/api';

export type AttackRole = 'entry_point' | 'internal_server' | 'crown_jewel';
export type NodeVisualState = 'compromised' | 'defended' | 'idle';
export type EdgeVisualState = 'attack' | 'cleared' | 'idle';

export const ATTACK_ROLE_LABEL: Record<AttackRole, string> = {
  entry_point: 'Entry Point',
  internal_server: 'Internal Server',
  crown_jewel: 'Crown Jewel',
};

export const GRAPH_VIEW = { width: 1100, height: 620, padY: 48 };
export const ROLE_X: Record<AttackRole, number> = {
  entry_point: 160,
  internal_server: 550,
  crown_jewel: 940,
};

const CROWN_MARKERS = ['DC', 'AD', 'EXCH', 'MAIL', 'DB', 'FINANCE', 'DOMAIN'];
const SERVER_MARKERS = ['DC', 'SRV', 'SERVER', 'AD', 'DNS', 'MAIL', 'DB', 'EXCH'];
const COMPROMISE_EVENTS = new Set([
  'lateral_movement',
  'data_exfiltration',
  'malware_detected',
  'privilege_escalation',
  'honeytoken_triggered',
  'auth_failure',
]);
const BLOCKING_ACTIONS = [
  'isolate_host',
  'isolate_device',
  'block_ip',
  'disable_account',
  'kill_process',
  'quarantine_file',
];

export function attackRoleForNode(node: GraphNodeRead): AttackRole {
  const fromProps = node.data.properties?.attack_role;
  if (fromProps === 'entry_point' || fromProps === 'internal_server' || fromProps === 'crown_jewel') {
    return fromProps;
  }
  const haystack = `${node.data.entity} ${node.data.label} ${node.data.entity_type}`.toUpperCase();
  if (node.data.entity_type === 'server' && CROWN_MARKERS.some((marker) => haystack.includes(marker))) {
    return 'crown_jewel';
  }
  if (node.data.entity_type === 'server' || SERVER_MARKERS.some((marker) => haystack.includes(marker))) {
    return 'internal_server';
  }
  return 'entry_point';
}

export function layoutAttackGraph(nodes: GraphNodeRead[]): { positions: Map<string, Position>; width: number; height: number } {
  const buckets: Record<AttackRole, GraphNodeRead[]> = {
    entry_point: [],
    internal_server: [],
    crown_jewel: [],
  };
  for (const node of nodes) {
    buckets[attackRoleForNode(node)].push(node);
  }
  const positions = new Map<string, Position>();
  const startY = 120 + GRAPH_VIEW.padY;
  let maxX = GRAPH_VIEW.width;
  let maxY = startY;
  (Object.keys(buckets) as AttackRole[]).forEach((role) => {
    const column = buckets[role];
    column.forEach((node, index) => {
      const x = ROLE_X[role];
      const y = startY + index * 88;
      positions.set(node.id, { x, y });
      maxX = Math.max(maxX, x + 160);
      maxY = Math.max(maxY, y);
    });
  });
  return {
    positions,
    width: Math.max(GRAPH_VIEW.width, maxX + GRAPH_VIEW.padY),
    height: Math.max(GRAPH_VIEW.height, maxY + GRAPH_VIEW.padY + 80),
  };
}

export function relatedEventsForNode(node: GraphNodeRead, events: LiveEvent[]): LiveEvent[] {
  const tokens = entityTokens(node);
  return events.filter((event) => eventTouchesTokens(event, tokens));
}

export function nodeVisualState(
  node: GraphNodeRead,
  events: LiveEvent[],
  remediations: RealtimeRemediation[],
  reviews: HumanReviewRead[],
  lastAlert: AlertRead | null,
): NodeVisualState {
  if (node.data.properties?.defended === true || isVectorBlocked(node, events, remediations, reviews)) {
    return 'defended';
  }
  const related = relatedEventsForNode(node, events);
  const compromisedEvent = related.some(
    (event) => COMPROMISE_EVENTS.has(event.event_type) || event.status === 'failure' || event.status === 'suspicious',
  );
  const alertHit = Boolean(lastAlert && entityTokens(node).has(lastAlert.entity.toLowerCase()));
  if (node.data.risk_score >= 70 || compromisedEvent || alertHit) {
    return 'compromised';
  }
  return 'idle';
}

export function edgeVisualState(
  edge: GraphEdgeRead,
  nodesById: Map<string, GraphNodeRead>,
  events: LiveEvent[],
  remediations: RealtimeRemediation[],
  reviews: HumanReviewRead[],
  lastAlert: AlertRead | null,
): EdgeVisualState {
  if (edge.data?.properties?.blocked === true || isEdgeBlocked(edge, nodesById, events, remediations, reviews)) {
    return 'cleared';
  }
  const source = nodesById.get(edge.source);
  const target = nodesById.get(edge.target);
  const sourceState = source ? nodeVisualState(source, events, remediations, reviews, lastAlert) : 'idle';
  const targetState = target ? nodeVisualState(target, events, remediations, reviews, lastAlert) : 'idle';
  if (sourceState === 'defended' || targetState === 'defended') {
    return 'cleared';
  }
  if (sourceState === 'compromised' || targetState === 'compromised' || edge.animated) {
    return 'attack';
  }
  return 'idle';
}

export function affectedService(node: GraphNodeRead): string {
  const typeLabel = node.data.entity_type.replace(/_/g, ' ');
  return `${node.data.entity} (${typeLabel})`;
}

function isVectorBlocked(
  node: GraphNodeRead,
  events: LiveEvent[],
  remediations: RealtimeRemediation[],
  reviews: HumanReviewRead[],
): boolean {
  const tokens = entityTokens(node);
  if (relatedEventsForNode(node, events).some((event) => event.status === 'blocked')) {
    return true;
  }
  if (remediations.some((item) => matchesBlockingAction(item.action) && tokenMatch(item.device_id, tokens))) {
    return true;
  }
  return reviews.some(
    (review) =>
      review.status === 'approved' &&
      matchesBlockingAction(review.action_type) &&
      (tokenMatch(review.reason, tokens) || relatedEventsForNode(node, events).some((event) => event.id === review.event_id)),
  );
}

function isEdgeBlocked(
  edge: GraphEdgeRead,
  nodesById: Map<string, GraphNodeRead>,
  events: LiveEvent[],
  remediations: RealtimeRemediation[],
  reviews: HumanReviewRead[],
): boolean {
  const source = nodesById.get(edge.source);
  const target = nodesById.get(edge.target);
  if (!source || !target) {
    return Boolean(edge.data?.properties?.blocked);
  }
  return isVectorBlocked(source, events, remediations, reviews) || isVectorBlocked(target, events, remediations, reviews);
}

function matchesBlockingAction(action: string | null | undefined): boolean {
  if (!action) {
    return false;
  }
  const normalized = action.toLowerCase();
  return BLOCKING_ACTIONS.some((item) => normalized.includes(item));
}

function entityTokens(node: GraphNodeRead): Set<string> {
  return new Set(
    [node.id, node.data.entity, node.data.label]
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

function eventTouchesTokens(event: LiveEvent, tokens: Set<string>): boolean {
  const fields = [event.user, event.source, event.destination].map((value) => value.trim().toLowerCase()).filter(Boolean);
  return fields.some((field) => tokens.has(field) || [...tokens].some((token) => token === field || token.endsWith(`:${field}`)));
}

function tokenMatch(value: string | null | undefined, tokens: Set<string>): boolean {
  if (!value) {
    return false;
  }
  const haystack = value.toLowerCase();
  return [...tokens].some((token) => haystack.includes(token));
}
