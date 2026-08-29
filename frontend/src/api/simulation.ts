import { apiRequest } from './client';
import type { SimulationStatusRead } from '../types/api';

export async function getSimulationStatus(): Promise<SimulationStatusRead> {
  return apiRequest<SimulationStatusRead>('/api/v1/simulation/status');
}

export async function startSimulation(payload: { file_path: string; speed_multiplier?: number; limit?: number }): Promise<SimulationStatusRead> {
  return apiRequest<SimulationStatusRead>('/api/v1/simulation/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function pauseSimulation(): Promise<SimulationStatusRead> {
  return apiRequest<SimulationStatusRead>('/api/v1/simulation/pause', { method: 'POST' });
}

export async function resumeSimulation(): Promise<SimulationStatusRead> {
  return apiRequest<SimulationStatusRead>('/api/v1/simulation/resume', { method: 'POST' });
}

export async function stopSimulation(): Promise<SimulationStatusRead> {
  return apiRequest<SimulationStatusRead>('/api/v1/simulation/stop', { method: 'POST' });
}
