import { apiRequest } from './client';

export interface AuthenticatedUser {
  username: string;
  role: 'analyst';
}

export interface LoginResponse {
  user: AuthenticatedUser;
}

export async function login(username: string, password: string): Promise<AuthenticatedUser> {
  const result = await apiRequest<LoginResponse>('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return result.user;
}

export function getCurrentUser(): Promise<AuthenticatedUser> {
  return apiRequest<AuthenticatedUser>('/api/v1/auth/me');
}

export function logout(): Promise<void> {
  return apiRequest<void>('/api/v1/auth/logout', { method: 'POST' });
}
