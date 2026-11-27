from models import User


def test_register_hashes_password(client, db_session):
    response = client.post(
        "/auth/register", json={"email": "new@test.com", "password": "password123"}
    )

    assert response.status_code == 201

    user = db_session.query(User).filter(User.email == "new@test.com").first()
    assert user is not None
    assert user.hashed_password != "password123"
    assert user.hashed_password.startswith("$2")


def test_login_and_me(client, admin_user):
    response = client.post(
        "/auth/login", json={"email": admin_user.email, "password": "changeme123"}
    )
    assert response.status_code == 200

    token = response.json()["access_token"]
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == admin_user.email


def test_me_without_token(client):
    assert client.get("/auth/me").status_code == 401


def test_normal_user_cannot_create_event(client, normal_user):
    token = client.post(
        "/auth/login",
        json={"email": "user@test.com", "password": "password123"},
    ).json()["access_token"]

    response = client.post(
        "/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source": "auth-service",
            "event_type": "failed_login",
            "severity": "warning",
            "ip_address": "10.0.0.9",
        },
    )
    assert response.status_code == 403


def test_audit_log_records_success(client, auth_headers):
    logs = client.get("/audit-logs?action=login_success", headers=auth_headers)
    assert logs.status_code == 200
    assert len(logs.json()) >= 1
