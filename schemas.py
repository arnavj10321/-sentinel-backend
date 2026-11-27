from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    source: str
    event_type: str
    severity: str = "info"
    ip_address: Optional[str] = None
    payload: Optional[dict[str, Any]] = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    source: str
    event_type: str
    severity: str
    ip_address: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
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
    user_id: Optional[int] = None
    email: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    event_id: Optional[int] = None
    title: str
    status: str
    severity: str
    created_at: datetime
    resolved_at: Optional[datetime] = None
