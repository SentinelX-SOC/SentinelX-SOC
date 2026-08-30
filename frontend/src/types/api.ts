export type EventType =
  | 'login'
  | 'logout'
  | 'auth_failure'
  | 'file_access'
  | 'process_start'
  | 'network_connection'
  | 'dns_query'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'data_exfiltration'
  | 'malware_detected'
  | 'honeytoken_triggered';

export type EventStatus =
  | 'success'
  | 'failure'
  | 'allowed'
  | 'blocked'
  | 'suspicious';

export type AlertStatus =
  | 'open'
  | 'acknowledged'
  | 'investigating'
  | 'contained'
  | 'resolved'
  | 'false_positive';

export type GraphNodeType =
  | 'user'
  | 'computer'
  | 'server'
  | 'host'
  | 'ip'
  | 'process'
  | 'file'
  | 'domain'
  | 'service'
  | 'alert'
  | 'honeytoken'
  | 'device';

export type GraphEdgeType =
  | 'authenticated_to'
  | 'connected_to'
  | 'communicated_with'
  | 'authenticated_as'
  | 'accessed'
  | 'spawned'
  | 'belongs_to'
  | 'lateral_to'
  | 'triggered';

export type HoneytokenType = 'credential' | 'file' | 'url' | 'canary';
export type HoneytokenStatus = 'active' | 'triggered' | 'inactive';
export type SimulationState = 'idle' | 'running' | 'paused' | 'stopped';
export type DeviceStatus = 'active' | 'isolated';

export interface TelemetryEventRead {
  id: string;
  timestamp: string;
  source: string;
  destination: string;
  user: string;
  event_type: EventType;
  status: EventStatus;
}

export interface TelemetryEventCreate {
  timestamp: string;
  source: string;
  destination: string;
  user: string;
  event_type: EventType;
  status: EventStatus;
}

export interface AlertRead {
  id: string;
  risk_score: number;
  entity: string;
  status: AlertStatus;
  created_at: string;
}

export interface Position {
  x: number;
  y: number;
}

export interface GraphNodeData {
  label: string;
  entity_type: GraphNodeType;
  entity: string;
  risk_score: number;
  properties: Record<string, unknown>;
}

export interface GraphNodeRead {
  id: string;
  type?: string | null;
  position: Position;
  data: GraphNodeData;
}

export interface GraphEdgeData {
  edge_type: GraphEdgeType;
  weight: number;
  properties: Record<string, unknown>;
}

export interface GraphEdgeRead {
  id: string;
  source: string;
  target: string;
  type?: string | null;
  label?: string | null;
  animated: boolean;
  data?: GraphEdgeData | null;
}

export interface GraphRead {
  nodes: GraphNodeRead[];
  edges: GraphEdgeRead[];
}

export interface MLPredictionResponse {
  event_id: string;
  prediction: 'normal' | 'anomalous' | 'suspicious';
  anomaly_score: number;
  risk_score: number;
  confidence: number;
}

export interface CostEstimate {
  estimate_label: 'ESTIMATED';
  event_count: number;
  incident_count: number;
  cost_per_event: number;
  cost_per_incident: number | null;
  total_cost: number;
}

export interface PolicyDecisionRead {
  allowed: boolean;
  action: string | null;
  reason: string;
}

export interface RemediationActionRead {
  id: string;
  alert_id: string;
  action_type: string;
  target_entity: string;
  status: string;
  parameters: Record<string, unknown>;
  result: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface DeviceStateRead {
  device_id: string;
  status: DeviceStatus;
  reason: string | null;
  isolated_at: string | null;
}

export interface InvestigationResult {
  threat_level: string;
  attack_type: string;
  confidence: number;
  evidence: string[];
  affected_assets: string[];
  recommended_action: string | null;
}

export interface EventPipelineResult {
  event: TelemetryEventRead;
  detection_source: 'ml' | 'heuristic' | 'honeytoken';
  risk_score: number;
  ml: MLPredictionResponse | null;
  alert: AlertRead | null;
  investigation: InvestigationResult | null;
  policy: PolicyDecisionRead;
  remediation: RemediationActionRead | null;
  device: DeviceStateRead | null;
  estimated_cost?: CostEstimate | null;
}

export interface TelemetryEventBatchResult {
  total: number;
  processed: number;
  failed: number;
  alerts: number;
  remediations: number;
  processing_time_ms: number;
  errors: { index: number; error: string }[];
  estimated_cost?: CostEstimate | null;
}

export type ReviewStatus = 'pending' | 'approved' | 'rejected' | 'escalated';

export interface HumanReviewRead {
  id: string;
  event_id: string;
  alert_id: string | null;
  action_type: string | null;
  risk_score: number;
  reason: string;
  status: ReviewStatus;
  created_at: string;
  reviewed_by: string | null;
  review_comment: string | null;
  reviewed_at: string | null;
}

export interface HealthRead {
  status: 'ok';
  service: string;
  version: string;
  simulation_state: string;
  websocket_connections: number;
  graph_nodes: number;
  graph_edges: number;
  ml_service_ready: boolean;
  ml_service_status: 'ready' | 'not_ready' | 'unavailable';
  ml_service_url: string;
  ml_service_reachable: boolean;
  ml_inference_ready: boolean;
  ml_service_usable: boolean;
}

export interface HoneytokenRead {
  id: string;
  type: HoneytokenType;
  name: string;
  value: string;
  status: HoneytokenStatus;
  description: string | null;
  created_at: string;
  triggered_at: string | null;
  triggered_by: string | null;
  source_ip: string | null;
  metadata: Record<string, unknown>;
}

export interface HoneytokenEventRead {
  event: TelemetryEventRead;
  severity: string;
  confidence: number;
  risk_score: number;
  honeytoken_id: string;
  user_id: string | null;
  device_id: string | null;
  source_ip: string | null;
  duplicate: boolean;
}

export interface HoneytokenTriggerResult {
  honeytoken: HoneytokenRead;
  event: TelemetryEventRead;
  severity: string;
  confidence: number;
  risk_score: number;
  alert: AlertRead | null;
  policy: PolicyDecisionRead;
  remediation: RemediationActionRead | null;
  device: DeviceStateRead | null;
  duplicate: boolean;
}

export interface SimulationStatusRead {
  state: SimulationState;
  message: string;
}

export interface WebSocketEvent {
  type: 'telemetry' | 'alert' | 'graph' | 'honeytoken_triggered' | 'remediation_executed';
  payload?: TelemetryEventRead | AlertRead | GraphRead | unknown;
  risk_score?: number;
  event?: string;
  action?: string;
  device_id?: string;
  alert_id?: string;
  severity?: string;
  honeytoken_id?: string;
}

export interface ApiError {
  message: string;
  status?: number;
}
