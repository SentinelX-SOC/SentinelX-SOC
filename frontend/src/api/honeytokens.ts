import { apiRequest } from './client';
import type { HoneytokenEventRead, HoneytokenRead, HoneytokenTriggerResult } from '../types/api';

export async function listHoneytokens(): Promise<HoneytokenRead[]> {
  return apiRequest<HoneytokenRead[]>('/api/v1/honeytokens');
}

export async function deployHoneytoken(payload: {
  type: string;
  name: string;
  description?: string | null;
}): Promise<HoneytokenRead> {
  return apiRequest<HoneytokenRead>('/api/v1/honeytokens/deploy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function triggerHoneytoken(tokenId: string, payload?: { user_id?: string; device_id?: string; source_ip?: string }): Promise<HoneytokenTriggerResult> {
  return apiRequest<HoneytokenTriggerResult>(`/api/v1/honeytokens/${encodeURIComponent(tokenId)}/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload ?? {}),
  });
}

export async function listHoneytokenEvents(tokenId: string): Promise<HoneytokenEventRead[]> {
  return apiRequest<HoneytokenEventRead[]>(`/api/v1/honeytokens/${encodeURIComponent(tokenId)}/events`);
}
