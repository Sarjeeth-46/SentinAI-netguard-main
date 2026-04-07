import pytest
from datetime import datetime, timedelta
from app.core.security import verify_password, get_password_hash, create_access_token

def test_password_hashing():
    password = "SuperSecretPassword123!"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_create_access_token():
    data = {"sub": "admin_user", "role": "admin"}
    token = create_access_token(data, expires_delta=timedelta(minutes=15))
    assert isinstance(token, str)
    assert len(token) > 20
