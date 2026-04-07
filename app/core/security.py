"""
Project: SentinAI NetGuard
Module: Security Utils
Description: Handles password hashing (bcrypt) and JWT token generation/validation.
License: MIT / Academic Use Only
"""
from datetime import datetime, timedelta
from typing import Optional
import jwt 
from passlib.context import CryptContext
from app.core.config import config

# Secure JWT Configuration
ALGORITHM = "HS256"
# Must match the cookie max_age set in api_gateway.py (3600*24 = 86400s = 1440min)
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=4)

def verify_password(plain_password, hashed_password):
    """Verifies a plain password against the stored hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def get_password_hash(password):
    """Generates a bcrypt hash for the password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token with expiration."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        # BUG FIX: was hardcoded timedelta(minutes=15), now uses the constant so
        # token lifetime (1440 min = 24 h) matches cookie max_age=3600*24.
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
