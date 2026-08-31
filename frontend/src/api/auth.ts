import { API_BASE_URL, apiRequest } from './client';

export interface AuthenticatedUser {
  id?: string;
  username: string;
  email?: string;
  display_name?: string | null;
  role: 'admin' | 'analyst' | 'viewer';
}

export interface LoginResponse {
  user: AuthenticatedUser;
}

export interface PasswordResetRequestResponse {
  message: string;
  reset_url?: string | null;
}

export interface PasswordResetConfirmResponse {
  message: string;
}

export function googleStartUrl(): string {
  return `${API_BASE_URL}/api/v1/auth/google/start`;
}

export async function login(email: string, password: string): Promise<AuthenticatedUser> {
  const result = await apiRequest<LoginResponse>('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return result.user;
}

export async function signup(input: {
  name: string;
  email: string;
  password: string;
  confirmPassword: string;
}): Promise<AuthenticatedUser> {
  const result = await apiRequest<LoginResponse>('/api/v1/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: input.name,
      email: input.email,
      password: input.password,
      confirm_password: input.confirmPassword,
    }),
  });
  return result.user;
}

export function requestPasswordReset(email: string): Promise<PasswordResetRequestResponse> {
  return apiRequest<PasswordResetRequestResponse>('/api/v1/auth/password-reset/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
}

export function confirmPasswordReset(
  token: string,
  password: string,
  confirmPassword: string,
): Promise<PasswordResetConfirmResponse> {
  return apiRequest<PasswordResetConfirmResponse>('/api/v1/auth/password-reset/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token,
      password,
      confirm_password: confirmPassword,
    }),
  });
}

export function getCurrentUser(): Promise<AuthenticatedUser> {
  return apiRequest<AuthenticatedUser>('/api/v1/auth/me');
}

export function logout(): Promise<void> {
  return apiRequest<void>('/api/v1/auth/logout', { method: 'POST' });
}
