"""FastAPI authentication backend suitable for Flutter clients.

Run locally:
    uvicorn main:app --reload

This app provides:
- POST /register   -> create a user account
- POST /login      -> OAuth2 password flow that returns JWT access token
- POST /logout     -> stateless JWT logout placeholder
- GET  /protected  -> protected route requiring valid bearer token

Storage uses SQLite via Python's built-in sqlite3 module.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# -----------------------------------------------------------------------------
# Security configuration
# -----------------------------------------------------------------------------
SECRET_KEY = "change-this-in-production-use-a-long-random-secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# -----------------------------------------------------------------------------
# Database setup (SQLite)
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "auth.db"


def get_db_connection() -> sqlite3.Connection:
    """Create and return a SQLite connection with Row objects."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create users table if it does not exist."""
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr


# -----------------------------------------------------------------------------
# Utility functions
# -----------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Generate a signed JWT with expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_username(username: str) -> sqlite3.Row | None:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_email(email: str) -> sqlite3.Row | None:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return row


def create_user(user: UserCreate) -> sqlite3.Row:
    conn = get_db_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO users (username, email, hashed_password, created_at) VALUES (?, ?, ?, ?)",
        (user.username, user.email, hash_password(user.password), now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=500, detail="Could not create user")
    return row


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> sqlite3.Row:
    """Decode and validate JWT token, then load current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user


# -----------------------------------------------------------------------------
# FastAPI app
# -----------------------------------------------------------------------------
app = FastAPI(title="FastAPI JWT Auth for Flutter")

# Allow Flutter apps during development (adjust origins in production).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.post("/register", response_model=UserResponse)
def register(user: UserCreate) -> UserResponse:
    """Register a new user with bcrypt-hashed password."""
    if get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    created = create_user(user)
    return UserResponse(id=created["id"], username=created["username"], email=created["email"])


@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """Authenticate user and return bearer JWT token."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user["username"]})
    return TokenResponse(access_token=access_token)


@app.post("/logout")
def logout() -> dict[str, str]:
    """JWT is stateless, so logout is handled client-side by deleting the token."""
    return {"message": "Logout successful on client side. Discard the token."}


@app.get("/protected")
def protected_route(current_user: sqlite3.Row = Depends(get_current_user)) -> dict[str, str]:
    """Example protected endpoint requiring a valid bearer token."""
    return {"message": f"Hello, {current_user['username']}! You are authenticated."}
