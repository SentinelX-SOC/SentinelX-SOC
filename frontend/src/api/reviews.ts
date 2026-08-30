import { apiRequest } from './client';
import type { HumanReviewRead, ReviewStatus } from '../types/api';

export async function listReviews(status?: ReviewStatus): Promise<HumanReviewRead[]> {
  const suffix = status ? `?status=${encodeURIComponent(status)}` : '';
  return apiRequest<HumanReviewRead[]>(`/api/v1/reviews${suffix}`);
}

export async function getReview(reviewId: string): Promise<HumanReviewRead> {
  return apiRequest<HumanReviewRead>(`/api/v1/reviews/${encodeURIComponent(reviewId)}`);
}

export async function decideReview(
  reviewId: string,
  action: 'approve' | 'reject' | 'escalate',
  comment?: string,
): Promise<HumanReviewRead> {
  const payload = comment && comment.trim() ? { comment: comment.trim() } : {};
  return apiRequest<HumanReviewRead>(`/api/v1/reviews/${encodeURIComponent(reviewId)}/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}
