from datetime import datetime
from typing import Any

from pydantic import BaseModel,ConfigDict,EmailStr

class EventCreate(BaseModel):
    source:str
    event_type:str
    severity:str
    ip_address:str | None=None
    payload:dict[str,Any]|None=None


class EventOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)

    id:int
    source:str
    event_type:str
    serverity:str
    ip_address: str | None
    payload: dict[str,Any] | None
    created_at : datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email:EmailStr
    password: str

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    role: str
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

