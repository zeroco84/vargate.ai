"""
IP-based rate limiting using Redis sliding window.
Used for auth/signup/admin endpoints to prevent brute-force attacks.
"""

import secrets
import time
from fastapi import HTTPException, Request


def get_client_ip(request: Request) -> str:
    """Get client IP, preferring X-Real-IP (set by nginx) over direct connection."""
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip
    return request.client.host if request.client else "unknown"


async def check_ip_rate_limit(
    redis_pool,
    prefix: str,
    client_ip: str,
    max_requests: int,
    window_seconds: int,
) -> bool:
    """
    Check IP-based rate limit using Redis sorted set sliding window.
    Returns True if allowed, False if rate-limited.
    """
    if redis_pool is None:
        return True  # No Redis = no rate limiting

    now_ts = time.time()
    key = f"rl:{prefix}:{client_ip}"

    try:
        pipe = redis_pool.pipeline()
        pipe.zremrangebyscore(key, "-inf", now_ts - window_seconds)
        pipe.zcard(key)
        pipe.zadd(key, {f"{now_ts}:{secrets.token_hex(4)}": now_ts})
        pipe.expire(key, window_seconds + 1)
        results = await pipe.execute()

        current_count = results[1]
        return current_count < max_requests
    except Exception:
        return True  # Fail open


async def enforce_ip_rate_limit(
    redis_pool,
    request: Request,
    prefix: str,
    max_requests: int,
    window_seconds: int = 60,
):
    """Raise HTTP 429 if the client IP exceeds the rate limit."""
    client_ip = get_client_ip(request)
    allowed = await check_ip_rate_limit(redis_pool, prefix, client_ip, max_requests, window_seconds)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
