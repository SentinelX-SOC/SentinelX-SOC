import { apiRequest } from './client';
import type { HealthRead } from '../types/api';

export async function getHealth(): Promise<HealthRead> {
  return apiRequest<HealthRead>('/');
}
