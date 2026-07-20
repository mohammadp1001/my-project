import os

os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("DATABASE_PATH", ":memory:")

import pytest

import main


def _clear_users_table() -> None:
    with main._db_lock:
        main._db_connection.execute("DELETE FROM users")
        main._db_connection.execute("DELETE FROM refresh_tokens")
        main._db_connection.commit()


@pytest.fixture(autouse=True)
def clear_user_store():
    _clear_users_table()
    yield
    _clear_users_table()
