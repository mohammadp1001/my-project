from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import main
from main import app

client = TestClient(app)


def _register_and_login(username: str = "alice", password: str = "hunter22") -> dict[str, str]:
    client.post("/register", json={"username": username, "password": password})
    response = client.post("/login", json={"username": username, "password": password})
    return response.json()


def test_login_returns_both_access_and_refresh_token():
    tokens = _register_and_login()
    assert "access_token" in tokens
    assert "refresh_token" in tokens


def test_refresh_with_valid_token_returns_new_tokens():
    tokens = _register_and_login()

    response = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert new_tokens["refresh_token"] != tokens["refresh_token"]


def test_refresh_rotates_token_old_one_no_longer_works():
    tokens = _register_and_login()

    client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})
    reuse_response = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert reuse_response.status_code == 401


def test_refresh_with_unknown_token_returns_401():
    response = client.post("/refresh", json={"refresh_token": "not-a-real-token"})
    assert response.status_code == 401


def test_refresh_with_expired_token_returns_401():
    tokens = _register_and_login()
    with main._db_lock:
        main._db_connection.execute(
            "UPDATE refresh_tokens SET expires_at = ? WHERE token = ?",
            (
                (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                tokens["refresh_token"],
            ),
        )
        main._db_connection.commit()

    response = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert response.status_code == 401


def test_logout_revokes_refresh_token():
    tokens = _register_and_login()

    logout_response = client.post("/logout", json={"refresh_token": tokens["refresh_token"]})
    refresh_response = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert logout_response.status_code == 204
    assert refresh_response.status_code == 401


def test_logout_with_unknown_token_is_idempotent():
    response = client.post("/logout", json={"refresh_token": "never-issued-token"})
    assert response.status_code == 204


def test_me_route_unaffected_by_refresh_token_changes():
    tokens = _register_and_login()

    response = client.get("/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})

    assert response.status_code == 200
    assert response.json() == {"username": "alice"}
