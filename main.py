from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from database import get_db
from models import Event
from schemas import EventOut

app = FastAPI(
    title="Sentinel API",
    description="Security event monitroing tools",
    version="0.1.0",
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


@app.get("/events", response_model=list[EventOut])
def list_event(db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.created_at.desc()).limit(50).all()
