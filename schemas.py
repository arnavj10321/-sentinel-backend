from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    source: str
    event_type: str
    severity: str = "info"
    ip_address: str | None = None
    payload: dict[str, Any] | None = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None = None
    source: str
    event_type: str
    severity: str
    ip_address: str | None = None
    payload: dict[str, Any] | None = None
    created_at: datetime


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action: str
    user_id: int | None = None
    email: str | None = None
    ip_address: str | None = None
    details: dict[str, Any] | None = None
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None = None
    event_id: int | None = None
    title: str
    status: str
    severity: str
    created_at: datetime
    resolved_at: datetime | None = None
