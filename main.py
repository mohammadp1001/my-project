import os
import threading
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
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


# --- User store module ------------------------------------------------
# In-memory user store, reset on process restart. No persistence.

_users: dict[str, str] = {}
_users_lock = threading.Lock()


class UsernameAlreadyRegisteredError(Exception):
    pass


def register_user(username: str, password: str) -> None:
    with _users_lock:
        if username in _users:
            raise UsernameAlreadyRegisteredError(username)
        _users[username] = hash_password(password)


def authenticate_user(username: str, password: str) -> bool:
    hashed = _users.get(username)
    if hashed is None:
        return False
    return verify_password(password, hashed)


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
