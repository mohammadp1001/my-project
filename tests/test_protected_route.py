from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

from main import (
    JWT_ALGORITHM,
    JWT_SECRET,
    app,
    create_access_token,
    decode_access_token,
)

client = TestClient(app)


def test_decode_access_token_round_trips_subject():
    token = create_access_token(subject="alice")
    assert decode_access_token(token) == "alice"


def test_decode_access_token_rejects_expired_token():
    expired_payload = {
        "sub": "alice",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired_token)


def test_decode_access_token_rejects_tampered_signature():
    token = create_access_token(subject="alice")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tampered)


def test_me_with_valid_token_returns_username():
    client.post("/register", json={"username": "alice", "password": "hunter2"})
    login_response = client.post("/login", json={"username": "alice", "password": "hunter2"})
    token = login_response.json()["access_token"]

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"username": "alice"}


def test_me_without_authorization_header_returns_401():
    response = client.get("/me")
    assert response.status_code == 401


def test_me_with_malformed_authorization_header_returns_401():
    response = client.get("/me", headers={"Authorization": "not-a-bearer-token"})
    assert response.status_code == 401


def test_me_with_garbage_token_returns_401():
    response = client.get("/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert response.status_code == 401


def test_me_with_expired_token_returns_401():
    expired_payload = {
        "sub": "alice",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    response = client.get("/me", headers={"Authorization": f"Bearer {expired_token}"})

    assert response.status_code == 401
