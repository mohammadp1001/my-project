from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_register_new_user_succeeds():
    response = client.post("/register", json={"username": "alice", "password": "hunter2"})
    assert response.status_code == 201
    assert response.json() == {"username": "alice"}


def test_register_duplicate_username_fails():
    client.post("/register", json={"username": "alice", "password": "hunter2"})
    response = client.post("/register", json={"username": "alice", "password": "different"})
    assert response.status_code == 409


def test_register_rejects_empty_username():
    response = client.post("/register", json={"username": "", "password": "hunter2"})
    assert response.status_code == 422


def test_register_rejects_empty_password():
    response = client.post("/register", json={"username": "alice", "password": ""})
    assert response.status_code == 422


def test_register_response_does_not_leak_password():
    response = client.post("/register", json={"username": "alice", "password": "hunter2"})
    assert "password" not in response.json()
    assert "hunter2" not in response.text
