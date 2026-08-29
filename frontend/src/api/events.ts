import { apiRequest } from './client';
import type { EventPipelineResult, TelemetryEventCreate } from '../types/api';

export async function ingestEvent(payload: TelemetryEventCreate): Promise<EventPipelineResult> {
  return apiRequest<EventPipelineResult>('/api/v1/events', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}
