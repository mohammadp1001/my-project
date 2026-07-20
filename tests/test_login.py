import jwt

from main import JWT_ALGORITHM, create_access_token

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_create_access_token_round_trips_subject():
    token = create_access_token(subject="alice")
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["sub"] == "alice"


def test_create_access_token_sets_expiry_claim():
    token = create_access_token(subject="alice")
    payload = jwt.decode(token, options={"verify_signature": False})
    assert "exp" in payload


def test_create_access_token_uses_hs256():
    token = create_access_token(subject="alice")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == JWT_ALGORITHM


def test_login_with_correct_credentials_returns_token():
    client.post("/register", json={"username": "alice", "password": "hunter2"})
    response = client.post("/login", json={"username": "alice", "password": "hunter2"})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_with_unknown_username_returns_invalid_credentials():
    response = client.post("/login", json={"username": "ghost", "password": "hunter2"})
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid credentials"}


def test_login_with_wrong_password_returns_same_error_as_unknown_username():
    client.post("/register", json={"username": "alice", "password": "hunter2"})
    unknown_user_response = client.post("/login", json={"username": "ghost", "password": "hunter2"})
    wrong_password_response = client.post("/login", json={"username": "alice", "password": "wrong"})
    assert wrong_password_response.status_code == unknown_user_response.status_code
    assert wrong_password_response.json() == unknown_user_response.json()
