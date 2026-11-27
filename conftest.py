import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import hash_password
from database import Base, get_db
from main import app
from models import User
import security


class _FakeRedis:
    """Minimal in-memory Redis replacement for the rate limiter."""

    def __init__(self):
        self._data: dict[str, int] = {}
        self._expires: dict[str, float] = {}

    def _expire_if_needed(self, key: str) -> None:
        expires_at = self._expires.get(key)
        if expires_at is not None and expires_at <= time.monotonic():
            self._data.pop(key, None)
            self._expires.pop(key, None)

    def incr(self, key: str, amount: int = 1) -> int:
        self._expire_if_needed(key)
        value = int(self._data.get(key, 0)) + amount
        self._data[key] = value
        return value

    def expire(self, key: str, seconds: int) -> None:
        self._expires[key] = time.monotonic() + seconds

    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._expires.pop(key, None)

    def flushall(self) -> None:
        self._data.clear()
        self._expires.clear()


@pytest.fixture(autouse=True)
def clear_rate_limit_state(monkeypatch):
    fake_redis = _FakeRedis()
    monkeypatch.setattr(security, "redis_client", fake_redis)
    security._memory_attempts.clear()
    yield
    fake_redis.flushall()
    security._memory_attempts.clear()


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture()
def admin_user(db_session):
    user = User(
        email="admin@sentinel.local",
        hashed_password=hash_password("changeme123"),
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def admin_token(client, admin_user):
    response = client.post(
        "/auth/login",
        json={"email": admin_user.email, "password": "changeme123"},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture()
def normal_user(db_session):
    user = User(
        email="user@test.com",
        hashed_password=hash_password("password123"),
        role="user",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
