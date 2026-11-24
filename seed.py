from database import SessionLocal
from models import Event


def seed():
    db = SessionLocal()
    try:
        if db.query(Event).count() > 0:
            print("Events already exist; skipping seed.")
            return

        events = [
            Event(type="login", source="auth-service", message="User login succeeded", severity="info"),
            Event(type="failed_login", source="auth-service", message="Invalid password attempt", severity="warning"),
            Event(type="intrusion_attempt", source="firewall", message="Blocked suspicious IP", severity="critical"),
        ]
        db.add_all(events)
        db.commit()
        print(f"Seeded {len(events)} events.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
