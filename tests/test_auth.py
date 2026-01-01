def test_register_and_login(client):
    r = client.post("/auth/register", json={
        "email": "test@example.com",
        "password": "Password123!"
    })
    assert r.status_code in (200, 201)

    r2 = client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "Password123!"
    })
    assert r2.status_code == 200
