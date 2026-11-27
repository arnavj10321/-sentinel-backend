import json

from database import SessionLocal
from models import Event


def seed():
    db = SessionLocal()
    try:
        if db.query(Event).count() > 0:
            print("Events already exist; skipping seed.")
            return

        events = [
            Event(
                source="auth-service",
                event_type="login",
                severity="info",
                ip_address="127.0.0.1",
                payload=json.dumps({"status": "ok"}),
            ),
            Event(
                source="auth-service",
                event_type="failed_login",
                severity="warning",
                ip_address="10.0.0.5",
                payload=json.dumps({"attempts": 3}),
            ),
            Event(
                source="firewall",
                event_type="intrusion_attempt",
                severity="critical",
                ip_address="203.0.113.10",
                payload=json.dumps({"action": "blocked"}),
            ),
        ]
        db.add_all(events)
        db.commit()
        print(f"Seeded {len(events)} events.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
