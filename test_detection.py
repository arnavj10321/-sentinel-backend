def test_five_failed_logins_create_one_alert(client, auth_headers):
    body = {
        "source": "auth-service",
        "event_type": "failed_login",
        "severity": "warning",
        "ip_address": "10.0.0.5",
        "payload": {"attempt": 1},
    }

    for _ in range(5):
        response = client.post("/events", headers=auth_headers, json=body)
        assert response.status_code == 201

    alerts = client.get("/alerts?status_filter=open", headers=auth_headers)
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1
    assert alerts.json()[0]["title"] == "Brute force detected from 10.0.0.5"

    client.post("/events", headers=auth_headers, json=body)
    alerts_again = client.get("/alerts?status_filter=open", headers=auth_headers)
    assert len(alerts_again.json()) == 1
