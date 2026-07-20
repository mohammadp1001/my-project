# Simple Auth Webserver

A small FastAPI server that implements JWT-based authentication from
scratch, built as a learning project. It favors clarity over production
hardening: no password complexity rules, and a single access token with
no refresh flow. The goal is to see exactly how each piece of "auth"
works, not to hide it behind a library.

## Setup

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env
# edit .env and set JWT_SECRET to a long random value
```

Users are stored in a SQLite database, whose file path is controlled by
`DATABASE_PATH` (see `.env.example`; defaults to `./data.db` if unset).
The database file is created automatically on first run and is
gitignored - delete it if you want to start from a clean slate.

## Running

```bash
uv run uvicorn main:app --reload
```

The server starts on `http://127.0.0.1:8000`. Open
`http://127.0.0.1:8000/docs` for FastAPI's interactive Swagger UI, where you
can call `/register`, `/login`, and `/me` directly from the browser without
writing a client - use "Authorize" in the top right to paste in a token
from `/login` before calling `/me`.

## Running tests

```bash
uv run pytest
```

## The concepts

### Hashing vs. encryption

Passwords are **hashed** with bcrypt (`hash_password`/`verify_password` in
`main.py`), not encrypted. Encryption is reversible if you have the key;
hashing is not reversible by design. The server never needs to recover a
user's original password - it only ever needs to check whether a
freshly-submitted password produces the same hash as the one on file. If
the user store ever leaked, encrypted passwords would be recoverable by
whoever also had the key; properly hashed ones are not recoverable at all,
only guessable at whatever cost bcrypt's work factor imposes.

### Why JWTs are stateless

After `/login`, the server doesn't keep a session record anywhere. The JWT
returned to the client *is* the proof of authentication: it's a signed
document containing the username (`sub`) and an expiry (`exp`). On each
request to `/me`, the server re-verifies the signature and expiry and
trusts the claims inside - it never looks anything up in a sessions table,
because there isn't one. This is what "stateless" means here, and it's the
opposite of traditional server-side session cookies, where the cookie is
just an opaque ID and all the actual state (who you are, when it expires)
lives in server-side storage that the ID points to. Statelessness is why
JWTs scale easily across multiple servers with no shared session store,
and also why they're hard to revoke early: once issued, a token stays
valid until it expires, since there's no server-side record to delete.

### What the secret key protects

`JWT_SECRET` (loaded from the environment, see `.env.example`) is the only
thing standing between "this token is genuine" and "anyone could forge a
token for any user." The server signs every token with this secret using
HS256, and re-checks that signature on every protected request. Anyone who
obtains the secret can mint a valid token for any username they like,
without ever registering or logging in - so it must never be committed to
source control (hence `.env` being gitignored and only `.env.example`,
with a placeholder, being checked in).

### Why login errors are generic

`/login` returns the same `{"detail": "invalid credentials"}` response
whether the username doesn't exist or the password is wrong. If those two
cases returned different errors, an attacker could use the difference to
enumerate valid usernames one guess at a time, even without ever guessing
a correct password. Collapsing both cases into one indistinguishable
response closes that off, at the cost of being slightly less helpful to a
legitimate user who mistyped their username.

## API

| Method | Path        | Auth              | Description                          |
|--------|-------------|-------------------|---------------------------------------|
| GET    | `/health`   | none              | Liveness check                        |
| POST   | `/register` | none              | Create a user (`username`, `password`) |
| POST   | `/login`    | none              | Exchange credentials for a JWT        |
| GET    | `/me`       | `Bearer <token>`  | Return the authenticated username     |

## Out of scope

This is intentionally minimal. Not included: persistent storage, refresh
tokens/logout, password complexity rules, rate limiting, and role-based
authorization. See the project's tracked issues for the full list of
deliberate omissions.
