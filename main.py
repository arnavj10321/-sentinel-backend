import json

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

from auth import create_access_token, get_current_user, hash_password, verify_password
from database import get_db
from models import Event, User
from schemas import EventCreate, EventOut, LoginRequest, Token, UserCreate, UserOut

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
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    return Token(access_token=create_access_token(user.email))


@app.get("/auth/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/events", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def create_event(
    payload: EventCreate,
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
    return event_to_out(event)


@app.get("/events", response_model=list[EventOut])
def list_events(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    events = db.query(Event).order_by(Event.created_at.desc()).limit(50).all()
    return [event_to_out(e) for e in events]
