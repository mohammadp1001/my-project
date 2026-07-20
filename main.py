import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

load_dotenv()

app = FastAPI(title="Simple Auth Webserver")

JWT_ALGORITHM = "HS256"
JWT_EXPIRY = timedelta(minutes=30)

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


# --- API routes module (FastAPI wiring) -----------------------------------


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


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
    token = create_access_token(subject=body.username)
    return TokenResponse(access_token=token)


@app.get("/me")
def me(username: str = Depends(get_current_username)) -> dict[str, str]:
    return {"username": username}
