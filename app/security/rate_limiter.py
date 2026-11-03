"""
Phase 7: Rate Limiting, Request Validation, and Protected Endpoint Authentication.
"""
from collections import defaultdict, deque
import time
from typing import Deque, Dict, Tuple, Any, Optional
from pydantic import BaseModel

from app.config import ADMIN_API_TOKEN, DEFAULT_SECURITY_POLICY


class ValidationCheckResult(BaseModel):
    valid: bool
    status_code: int = 200
    reason: str = "Request passed validation."


class SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter per client/session identifier."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    def check_rate_limit(self, client_id: str, max_requests: int = 60) -> Tuple[bool, int, float]:
        """
        Returns (allowed, remaining_requests, retry_after_seconds).
        """
        now = time.monotonic()
        bucket = self._buckets[client_id]
        cutoff = now - self.window_seconds

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= max_requests:
            retry_after = round(max(0.1, self.window_seconds - (now - bucket[0])), 2)
            return False, 0, retry_after

        bucket.append(now)
        remaining = max(0, max_requests - len(bucket))
        return True, remaining, 0.0

    def reset(self, client_id: Optional[str] = None) -> None:
        if client_id is None:
            self._buckets.clear()
        else:
            self._buckets.pop(client_id, None)


def validate_incoming_request(
    prompt: str,
    raw_body_bytes: int = 0,
    policy: Optional[Dict[str, Any]] = None,
) -> ValidationCheckResult:
    """Validate prompt length, payload size, and prohibited control characters."""
    active_policy = dict(DEFAULT_SECURITY_POLICY)
    if policy:
        active_policy.update(policy)

    max_len = int(active_policy.get("max_prompt_length", 4000))
    max_bytes = int(active_policy.get("max_request_bytes", 32768))

    if raw_body_bytes > max_bytes:
        return ValidationCheckResult(
            valid=False,
            status_code=413,
            reason=f"Request payload size ({raw_body_bytes} bytes) exceeds maximum allowed ({max_bytes} bytes).",
        )

    if prompt is None or not str(prompt).strip():
        return ValidationCheckResult(
            valid=False,
            status_code=422,
            reason="Prompt cannot be empty or whitespace-only.",
        )

    if "\x00" in prompt:
        return ValidationCheckResult(
            valid=False,
            status_code=400,
            reason="Prompt contains invalid null-byte control characters.",
        )

    if len(prompt) > max_len:
        return ValidationCheckResult(
            valid=False,
            status_code=413,
            reason=f"Prompt length ({len(prompt)} chars) exceeds maximum allowed ({max_len} chars).",
        )

    return ValidationCheckResult(valid=True, status_code=200, reason="Valid request.")


def verify_admin_api_key(provided_key: Optional[str]) -> bool:
    """Verify API token for protected configuration or administration endpoints."""
    if not provided_key:
        return False
    return provided_key == ADMIN_API_TOKEN


default_rate_limiter = SlidingWindowRateLimiter(window_seconds=60)
