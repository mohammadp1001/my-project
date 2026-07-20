from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_register_rejects_password_shorter_than_minimum():
    response = client.post("/register", json={"username": "alice", "password": "short1"})
    assert response.status_code == 422


def test_register_rejects_password_without_a_digit():
    response = client.post("/register", json={"username": "alice", "password": "alletters"})
    assert response.status_code == 422


def test_register_rejects_password_without_a_letter():
    response = client.post("/register", json={"username": "alice", "password": "12345678"})
    assert response.status_code == 422


def test_register_accepts_password_meeting_all_rules():
    response = client.post("/register", json={"username": "alice", "password": "hunter22"})
    assert response.status_code == 201


def test_register_rejects_username_shorter_than_minimum():
    response = client.post("/register", json={"username": "ab", "password": "hunter22"})
    assert response.status_code == 422


def test_register_rejects_username_longer_than_maximum():
    response = client.post(
        "/register", json={"username": "a" * 33, "password": "hunter22"}
    )
    assert response.status_code == 422


def test_register_rejects_username_with_disallowed_characters():
    response = client.post("/register", json={"username": "alice!", "password": "hunter22"})
    assert response.status_code == 422


def test_register_accepts_username_with_underscore_and_hyphen():
    response = client.post(
        "/register", json={"username": "alice_bob-99", "password": "hunter22"}
    )
    assert response.status_code == 201


def test_login_still_accepts_credentials_that_predate_validation_rules():
    # Registration goes through register_user directly, bypassing the
    # HTTP-layer Pydantic validation - simulating an account that was
    # created before these rules existed (e.g. the old "hunter2" password,
    # 7 characters, which would fail today's 8-character minimum).
    import main

    main.register_user("legacyuser", "short1")

    response = client.post("/login", json={"username": "legacyuser", "password": "short1"})

    assert response.status_code == 200
