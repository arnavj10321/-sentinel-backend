from auth import hash_password
from database import SessionLocal
from models import User


# The default password is only a local bootstrap convenience.
def seed_admin(
    email: str = "admin@sentinel.local",
    password: str = "changeme123",  # nosec B107
) -> None:
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"User {email} already exists.")
            return

        user = User(
            email=email,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"Created admin user: {email}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_admin()
