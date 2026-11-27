from sqlalchemy import func
from sqlalchemy.orm import Session

from models import Alert, Event

BRUTE_FORCE_THRESHOLD = 5


def maybe_create_brute_force_alert(db: Session, event: Event) -> Alert | None:
    """Create one open alert after repeated failed logins from the same IP."""
    if event.event_type != "failed_login" or not event.ip_address:
        return None

    title = f"Brute force detected from {event.ip_address}"
    existing = (
        db.query(Alert).filter(Alert.title == title, Alert.status == "open").first()
    )
    if existing:
        return None

    failures = (
        db.query(func.count(Event.id))
        .filter(
            Event.event_type == "failed_login", Event.ip_address == event.ip_address
        )
        .scalar()
        or 0
    )
    if failures < BRUTE_FORCE_THRESHOLD:
        return None

    alert = Alert(
        title=title,
        status="open",
        severity="high",
        user_id=event.user_id,
        event_id=event.id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
