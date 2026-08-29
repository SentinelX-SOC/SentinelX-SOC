import { apiRequest } from './client';
import type { GraphNodeRead, GraphRead } from '../types/api';

export async function getGraph(): Promise<GraphRead> {
  return apiRequest<GraphRead>('/api/v1/graph/');
}

export async function getGraphNeighbors(entityId: string): Promise<GraphNodeRead[]> {
  return apiRequest<GraphNodeRead[]>(`/api/v1/graph/neighbors/${encodeURIComponent(entityId)}`);
}
