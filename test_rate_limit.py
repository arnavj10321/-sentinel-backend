def test_seventh_failed_login_returns_429(client):
    body={
        "email":"noperson@test.com",
        "password":"whoknowpassword"
    }

    for _ in range(5):
        assert client.post("/auth/login",json=body).status_code==401

    assert client.post("/auth/login",json=body).status_code==429

    