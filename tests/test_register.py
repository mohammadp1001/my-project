import threading

from fastapi.testclient import TestClient

import main
from main import app, register_user, UsernameAlreadyRegisteredError

client = TestClient(app)


def test_register_new_user_succeeds():
    response = client.post("/register", json={"username": "alice", "password": "hunter22"})
    assert response.status_code == 201
    assert response.json() == {"username": "alice"}


def test_register_duplicate_username_fails():
    client.post("/register", json={"username": "alice", "password": "hunter22"})
    response = client.post("/register", json={"username": "alice", "password": "different1"})
    assert response.status_code == 409


def test_register_rejects_empty_username():
    response = client.post("/register", json={"username": "", "password": "hunter22"})
    assert response.status_code == 422


def test_register_rejects_empty_password():
    response = client.post("/register", json={"username": "alice", "password": ""})
    assert response.status_code == 422


def test_register_response_does_not_leak_password():
    response = client.post("/register", json={"username": "alice", "password": "hunter22"})
    assert "password" not in response.json()
    assert "hunter22" not in response.text


def test_concurrent_registration_of_same_username_only_succeeds_once():
    username = "racer"
    results: list[bool] = []
    results_lock = threading.Lock()

    def attempt() -> None:
        try:
            register_user(username, "hunter22")
            ok = True
        except UsernameAlreadyRegisteredError:
            ok = False
        with results_lock:
            results.append(ok)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1
    assert results.count(False) == 19
    assert main.authenticate_user(username, "hunter22")
