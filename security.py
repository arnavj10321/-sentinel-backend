import json
import time

import redis
from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from config import settings
from models import AuditLog

redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)

LOGIN_LIMIT = 6
LOGIN_WINDOW_SECONDS = 60

# Fallback for local development when Redis is not running.
_memory_attempts: dict[str, tuple[int, float]] = {}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _rate_limit_key(request: Request) -> str:
    return f"login:attempts:{client_ip(request)}"


def _increment(key: str) -> int:
    try:
        return int(redis_client.incr(key))
    except RedisError:
        count, expires_at = _memory_attempts.get(key, (0, 0.0))
        if expires_at <= time.monotonic():
            count, expires_at = 0, time.monotonic() + LOGIN_WINDOW_SECONDS
        count += 1
        _memory_attempts[key] = (count, expires_at)
        return count


def _expire(key: str, seconds: int) -> None:
    try:
        redis_client.expire(key, seconds)
    except RedisError:
        pass


def _delete(key: str) -> None:
    try:
        redis_client.delete(key)
    except RedisError:
        _memory_attempts.pop(key, None)


def check_login_rate_limit(request: Request) -> None:
    key = _rate_limit_key(request)
    current = _increment(key)

    if current == 1:
        _expire(key, LOGIN_WINDOW_SECONDS)

    if current >= LOGIN_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
        )


def reset_login_rate_limit(request: Request) -> None:
    _delete(_rate_limit_key(request))


def write_audit(
    db: Session,
    action: str,
    user_id: int | None = None,
    ip_address: str | None = None,
    details: dict | list | str | None = None,
) -> None:
    db.add(
        AuditLog(
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            details=json.dumps(details)
            if isinstance(details, (dict, list))
            else details,
        )
    )
    db.commit()
