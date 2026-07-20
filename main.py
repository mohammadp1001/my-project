import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

load_dotenv()

app = FastAPI(title="Simple Auth Webserver")

JWT_ALGORITHM = "HS256"
JWT_EXPIRY = timedelta(minutes=30)
REFRESH_TOKEN_EXPIRY = timedelta(days=7)

try:
    JWT_SECRET = os.environ["JWT_SECRET"]
except KeyError as exc:
    raise RuntimeError(
        "JWT_SECRET environment variable must be set before starting the app"
    ) from exc


# --- Auth/security module -------------------------------------------------
# Password hashing and JWT issuance. Has no dependency on FastAPI or the
# user store: it only deals with turning a plaintext password into a hash
# and back, and with signing/reading tokens.


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(subject: str) -> str:
    payload = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + JWT_EXPIRY,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> str:
    payload = jwt.decode(
        token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["sub", "exp"]}
    )
    return payload["sub"]


# --- User store module ------------------------------------------------
# SQLite-backed user store. A single connection is opened once for the
# process lifetime (required for DATABASE_PATH=":memory:" to actually
# persist across calls - a fresh connection per call would each get its
# own empty in-memory database). sqlite3.Connection objects aren't safe
# for concurrent use from multiple threads even with
# check_same_thread=False, so all access goes through _db_lock.

DATABASE_PATH = os.environ.get("DATABASE_PATH", "./data.db")

_db_lock = threading.Lock()
_db_connection = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
with _db_lock:
    _db_connection.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, "
        "password_hash TEXT NOT NULL"
        ")"
    )
    _db_connection.execute(
        "CREATE TABLE IF NOT EXISTS refresh_tokens ("
        "token TEXT PRIMARY KEY, "
        "username TEXT NOT NULL, "
        "expires_at TEXT NOT NULL, "
        "revoked INTEGER NOT NULL DEFAULT 0"
        ")"
    )
    _db_connection.commit()


class UsernameAlreadyRegisteredError(Exception):
    pass


def register_user(username: str, password: str) -> None:
    password_hash = hash_password(password)
    with _db_lock:
        try:
            _db_connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            _db_connection.commit()
        except sqlite3.IntegrityError:
            raise UsernameAlreadyRegisteredError(username)


def authenticate_user(username: str, password: str) -> bool:
    with _db_lock:
        row = _db_connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row is None:
        return False
    return verify_password(password, row[0])


# --- Refresh token module --------------------------------------------------
# Unlike the access token, a refresh token is not a JWT - it's an opaque
# random string the server tracks server-side (username, expiry, revoked).
# That's what makes revocation possible at all: a stateless JWT can never
# be revoked before its own expiry, which would defeat the point of
# /logout. Longer-lived than the access token, but still expires.


class InvalidRefreshTokenError(Exception):
    pass


def create_refresh_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY
    with _db_lock:
        _db_connection.execute(
            "INSERT INTO refresh_tokens (token, username, expires_at, revoked) "
            "VALUES (?, ?, ?, 0)",
            (token, username, expires_at.isoformat()),
        )
        _db_connection.commit()
    return token


def rotate_refresh_token(token: str) -> tuple[str, str]:
    """Validate `token`, revoke it, and issue a replacement.

    Returns (new_refresh_token, username). Rotating on every use limits
    the blast radius of a leaked refresh token: it's single-use, so a
    subsequent use of the old value (by either party) is now detectable.
    """
    with _db_lock:
        row = _db_connection.execute(
            "SELECT username, expires_at, revoked FROM refresh_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if row is None:
            raise InvalidRefreshTokenError(token)
        username, expires_at_str, revoked = row
        if revoked or datetime.fromisoformat(expires_at_str) < datetime.now(timezone.utc):
            raise InvalidRefreshTokenError(token)

        _db_connection.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,)
        )
        new_token = secrets.token_urlsafe(32)
        new_expires_at = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRY
        _db_connection.execute(
            "INSERT INTO refresh_tokens (token, username, expires_at, revoked) "
            "VALUES (?, ?, ?, 0)",
            (new_token, username, new_expires_at.isoformat()),
        )
        _db_connection.commit()
    return new_token, username


def revoke_refresh_token(token: str) -> None:
    with _db_lock:
        _db_connection.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,)
        )
        _db_connection.commit()


# --- API routes module (FastAPI wiring) -----------------------------------


# Username/password rules apply only at registration - login is checked
# against whatever was actually stored, so it must keep accepting
# credentials that predate a rules change.
USERNAME_PATTERN = r"^[A-Za-z0-9_-]{3,32}$"
PASSWORD_MIN_LENGTH = 8


class RegisterRequest(BaseModel):
    username: str = Field(
        pattern=USERNAME_PATTERN,
        description="3-32 characters: letters, digits, underscore, or hyphen",
    )
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        description="At least 8 characters, including a letter and a digit",
    )

    @field_validator("password")
    @classmethod
    def _password_has_letter_and_digit(cls, value: str) -> str:
        if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
            raise ValueError("password must contain at least one letter and one digit")
        return value


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


_bearer_scheme = HTTPBearer(auto_error=False)


def get_current_username(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        return decode_access_token(credentials.credentials)
    except jwt.InvalidTokenError:
        raise unauthorized


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest) -> dict[str, str]:
    try:
        register_user(body.username, body.password)
    except UsernameAlreadyRegisteredError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username already registered",
        )
    return {"username": body.username}


@app.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    if not authenticate_user(body.username, body.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    access_token = create_access_token(subject=body.username)
    refresh_token = create_refresh_token(body.username)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@app.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest) -> TokenResponse:
    try:
        new_refresh_token, username = rotate_refresh_token(body.refresh_token)
    except InvalidRefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired refresh token",
        )
    access_token = create_access_token(subject=username)
    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)


@app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: LogoutRequest) -> None:
    revoke_refresh_token(body.refresh_token)


@app.get("/me")
def me(username: str = Depends(get_current_username)) -> dict[str, str]:
    return {"username": username}
