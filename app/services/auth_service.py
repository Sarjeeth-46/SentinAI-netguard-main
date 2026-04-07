"""
Project: SentinAI NetGuard
Module: Authentication Service
Description: Manages user authentication, registration, and password updates via MongoDB.
License: MIT / Academic Use Only
"""
from datetime import datetime
import os
from typing import Optional, List, Dict
from app.core.config import config
from app.core.security import verify_password, get_password_hash, create_access_token
from app.db.connection import db

class AuthService:
    """Service for handling User Authentication and Credentials (MongoDB Based)."""
    
    def __init__(self):
        self.collection_name = "users"

    async def _get_collection(self):
        """
        Helper to get the Motor async collection object.
        Ensures the MongoDB connection is established before returning.
        """
        # Trigger lazy connection if not yet connected
        if not db.client:
            await db.connect()
        database = db.get_db()
        if database is not None:
            return database[self.collection_name]
        return None

    async def get_user(self, username: str) -> Optional[Dict]:
        """Retrieves a user by username from MongoDB."""
        collection = await self._get_collection()
        if collection is None:
            # Emergency Fallback for admin during outages
            if username == "admin" and config.ALLOW_EMERGENCY_ADMIN:
                print(f"[SECURITY WARNING] Emergency Admin Fallback Triggered for {username}")
                return {"username": "admin", "role": "admin", "hashed_password": "unused_in_lookup"}
            return None
        return await collection.find_one({"username": username})

    async def authenticate_user(self, username, password):
        """
        Authenticates a user against MongoDB.
        Falls back to emergency admin if MongoDB is unavailable.
        Returns None (→ 401) rather than raising on any DB connectivity error.
        """
        try:
            collection = await self._get_collection()
        except Exception:
            collection = None

        if collection is None:
            emergency_pass = os.getenv("EMERGENCY_ADMIN_PASSWORD", "")
            if username == "admin" and password == emergency_pass and emergency_pass:
                return create_access_token(data={"sub": "admin", "role": "admin"})
            return None

        try:
            user = await collection.find_one({"username": username})
        except Exception as exc:
            print(f"[Auth] DB lookup failed during authenticate_user: {exc}")
            return None

        if not user:
            return None

        if not verify_password(password, user["hashed_password"]):
            return None

        return create_access_token(data={"sub": username, "role": user.get("role", "analyst")})


    async def create_user(self, username, password, role="analyst"):
        """Creates a new user."""
        collection = await self._get_collection()
        if collection is None:
            return False

        if await collection.find_one({"username": username}):
            return False  # User exists

        hashed_password = get_password_hash(password)
        new_user = {
            "username": username,
            "hashed_password": hashed_password,
            "role": role,
            "created_at": datetime.now()
        }

        await collection.insert_one(new_user)
        return True

    async def change_password(self, username, old_password, new_password):
        """Updates the user's password."""
        collection = await self._get_collection()
        if collection is None:
            return False

        user = await collection.find_one({"username": username})
        if not user:
            return False

        if not verify_password(old_password, user["hashed_password"]):
            return False

        new_hash = get_password_hash(new_password)
        await collection.update_one(
            {"username": username},
            {"$set": {"hashed_password": new_hash}}
        )
        return True

    async def ensure_admin_user(self):
        """
        Ensures the default admin exists on startup.
        If INITIAL_ADMIN_PASSWORD is explicitly set in the environment,
        the admin password is always updated to match it — this prevents
        stale hashes from a previous seed from blocking logins.
        """
        collection = await self._get_collection()
        if collection is None:
            print("[Auth] MongoDB not available. Skipping admin seed.")
            return

        initial_pass = os.getenv("INITIAL_ADMIN_PASSWORD", "")
        existing = await collection.find_one({"username": "admin"})

        if not existing:
            # First run: create the admin with the configured password
            seed_pass = initial_pass if initial_pass else "changeme_in_prod!"
            print(f"[Auth] Seeding default admin user with configured password...")
            await self.create_user("admin", seed_pass, role="admin")
        elif initial_pass:
            # INITIAL_ADMIN_PASSWORD is explicitly set: keep the stored hash in sync.
            # This handles the case where the admin was seeded in a previous run with
            # a different default, and the env var is now overriding it.
            new_hash = get_password_hash(initial_pass)
            await collection.update_one(
                {"username": "admin"},
                {"$set": {"hashed_password": new_hash}}
            )
            print("[Auth] Admin password synced to INITIAL_ADMIN_PASSWORD.")

auth_service = AuthService()
