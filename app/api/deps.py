"""
Project: SentinAI NetGuard
Module: Dependencies
Description:
    FastAPI dependencies for route protection.
    Handles JWT validation, user context retrieval,
    and serialization of raw MongoDB documents into typed User objects.
"""
from fastapi import Depends, HTTPException, status, Request
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId

from app.core.config import config
from app.db.connection import db
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# User model — JSON-safe representation of a MongoDB user document
# ---------------------------------------------------------------------------
class User(BaseModel):
    id: Optional[str] = None          # Mongo _id as string
    username: str
    role: str = "SOC Analyst"
    email: Optional[str] = None
    created_at: Optional[str] = None  # ISO 8601 string
    last_login: Optional[str] = None  # ISO 8601 string

    class Config:
        # Allow construction from a raw dict (e.g. Mongo document)
        from_attributes = True


def _mongo_doc_to_user(doc: dict) -> User:
    """
    Convert a raw MongoDB document to a typed User.
    - ObjectId  → str
    - datetime  → ISO 8601 string
    - hashed_password is intentionally dropped.
    """
    safe: dict = {}
    for key, value in doc.items():
        if key == "_id":
            safe["id"] = str(value)
        elif key in ("hashed_password", "password"):
            continue                             # never expose credentials
        elif isinstance(value, ObjectId):
            safe[key] = str(value)
        elif isinstance(value, datetime):
            safe[key] = value.isoformat()
        else:
            safe[key] = value
    return User(**safe)


# ---------------------------------------------------------------------------
# Dependency: get_current_user
# ---------------------------------------------------------------------------
async def get_current_user(request: Request) -> User:
    """
    Validates the JWT token from HttpOnly cookie or Authorization header.
    Returns a typed User on success; raises 401 on failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # --- Token extraction: Bearer header first, then cookie ---
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]

    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise credentials_exception

    # --- JWT validation ---
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        expiry_time = payload.get("exp")
        logger.info(
            f"Token accepted: {token[:10]}...  sub={payload.get('sub')}  exp={expiry_time}"
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT Validation Error: {e}")
        raise credentials_exception

    # --- User lookup ---
    # Ensure the Motor async connection is established before querying
    if not db.client:
        await db.connect()
    database = db.get_db()
    if database is None:
        # Emergency admin fallback during DB outages
        if username == "admin" and getattr(config, "ALLOW_EMERGENCY_ADMIN", False):
            return User(id="emergency", username="admin", role="admin")
        raise credentials_exception

    collection = database["users"]
    doc = await collection.find_one({"username": username})

    if doc is None:
        raise credentials_exception

    return _mongo_doc_to_user(doc)
