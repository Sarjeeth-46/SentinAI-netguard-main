"""
Script to reset the admin user logic.
Run this to fix 'Invalid Credential' issues.
"""
import sys
import os
import asyncio

from app.db.connection import db
from app.services.auth_service import auth_service
from app.core.config import config

def reset_admin():
    print("--- Resetting Admin User ---")
    
    async def run_reset():
        if not db.client:
            await db.connect()
        database = db.get_db()

        if database is None:
            print("[Error] Database object is None. Is MongoDB running?")
            print("Note: The system uses a Circuit Breaker. If you just started DB, wait 10s.")
            return

        users_col = database["users"]
        
        # 1. Remove existing admin
        print("Removing existing 'admin' user...")
        await users_col.delete_many({"username": "admin"})
        
        # 2. Create fresh admin
        print("Creating new 'admin' user with password 'admin'...")
        success = await auth_service.create_user("admin", "admin", role="admin")
        
        if success:
            print("[Success] Admin user created/reset successfully.")
            print("Try logging in with: admin / admin")
        else:
            print("[Error] Failed to create admin user.")

        # verify
        u = await users_col.find_one({"username": "admin"})
        if u:
            print(f"[Verify] Found user in DB: {u.get('username')}")
            print(f"[Verify] Hashed Pwd len: {len(u.get('hashed_password'))}")
        else:
            print("[Verify] Could not find user after creation!")
            
    asyncio.run(run_reset())

if __name__ == "__main__":
    reset_admin()
