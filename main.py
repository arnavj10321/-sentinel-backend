import json

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from auth import (
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
from database import get_db
from models import AuditLog, Event, User
from schemas import AuditLogOut, EventCreate, EventOut, LoginRequest, Token, UserCreate, UserOut

app = FastAPI(
    title="Sentinel API",
    description="Security event monitoring API",
    version="0.1.0",
)


def event_to_out(event: Event) -> EventOut:
    return EventOut(
        id=event.id,
        user_id=event.user_id,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        ip_address=event.ip_address,
        payload=json.loads(event.payload) if event.payload else None,
        created_at=event.created_at,
    )


def audit_log_to_out(log: AuditLog) -> AuditLogOut:
    return AuditLogOut(
        id=log.id,
        action=log.action,
        user_id=log.user_id,
        email=log.email,
        ip_address=log.ip_address,
        details=json.loads(log.details) if log.details else None,
        created_at=log.created_at,
    )


def record_audit(
    db: Session,
    action: str,
    *,
    user: User | None = None,
    email: str | None = None,
    request: Request | None = None,
    details: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            action=action,
            user_id=user.id if user else None,
            email=email or (user.email if user else None),
            ip_address=request.client.host if request and request.client else None,
            details=json.dumps(details) if details is not None else None,
        )
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/models")
def list_models():
    return {
        "object": "list",
        "data": [
            {
                "id": "sentinel-model",
                "object": "model",
                "owned_by": "sentinel",
            }
        ],
    }


@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(email=payload.email, hashed_password=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        record_audit(
            db,
            "login_failed",
            email=payload.email,
            request=request,
            details={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        record_audit(
            db,
            "login_failed",
            user=user,
            request=request,
            details={"reason": "inactive_user"},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    record_audit(db, "login_success", user=user, request=request)
    db.commit()
    return Token(access_token=create_access_token(user.email))


@app.get("/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/events", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(
    payload: EventCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = Event(
        user_id=current_user.id,
        source=payload.source,
        event_type=payload.event_type,
        severity=payload.severity,
        ip_address=payload.ip_address,
        payload=json.dumps(payload.payload) if payload.payload is not None else None,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    record_audit(
        db,
        "event_created",
        user=current_user,
        request=request,
        details={"event_id": event.id, "event_type": event.event_type},
    )
    db.commit()
    return event_to_out(event)


@app.get("/events", response_model=list[EventOut])
def list_events(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    events = db.query(Event).order_by(Event.created_at.desc()).limit(50).all()
    return [event_to_out(e) for e in events]


@app.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    action: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    logs = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit).all()
    return [audit_log_to_out(log) for log in logs]
