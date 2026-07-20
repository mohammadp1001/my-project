import os

os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use-in-production")

import pytest

import main


@pytest.fixture(autouse=True)
def clear_user_store():
    main._users.clear()
    yield
    main._users.clear()
