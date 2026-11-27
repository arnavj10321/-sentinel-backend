def test_event_crud_and_filters(client, auth_headers):
    body = {
        "source": "auth-service",
        "event_type": "login",
        "severity": "info",
        "ip_address": "127.0.0.1",
        "payload": {"ok": True},
    }

    created = client.post("/events", headers=auth_headers, json=body)
    assert created.status_code == 201
    event_id = created.json()["id"]

    one = client.get(f"/events/{event_id}", headers=auth_headers)
    assert one.status_code == 200
    assert one.json()["id"] == event_id

    patched = client.patch(
        f"/events/{event_id}",
        headers=auth_headers,
        json={"severity": "critical"},
    )
    assert patched.status_code == 200
    assert patched.json()["severity"] == "critical"

    filtered = client.get("/events?severity=critical", headers=auth_headers)
    assert filtered.status_code == 200
    assert any(event["id"] == event_id for event in filtered.json())

    deleted = client.delete(f"/events/{event_id}", headers=auth_headers)
    assert deleted.status_code == 204

    assert client.get(f"/events/{event_id}", headers=auth_headers).status_code == 404
