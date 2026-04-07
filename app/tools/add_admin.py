
import sys
import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Load env vars
load_dotenv()

# Add project root to path (Up 2 levels from backend/tools)
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.services.auth_service import auth_service
from backend.core.config import config

def main():
    print(f"Testing connection to: {config.MONGO_URI}")
    try:
        client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        print("MongoDB Connection Successful!")
    except Exception as e:
        print(f"MongoDB Connection FAILED: {e}")
        return

    print("Ensuring admin user...")
    try:
        # We need to manually initialize the db instance in auth_service if not already doing so, 
        # but auth_service uses the global 'db' object which lazy loads.
        # Let's try calling ensure_admin_user directly.
        auth_service.ensure_admin_user()
        print("Admin user check completed.")
        
        # Verify user exists
        db = client[config.DB_NAME]
        users = db["users"]
        admin = users.find_one({"username": "admin"})
        if admin:
            print("Admin user FOUND in database.")
            print(f"Role: {admin.get('role')}")
        else:
            print("Admin user NOT FOUND in database after ensure_admin_user().")
            
    except Exception as e:
        print(f"Error checking/creating admin: {e}")

if __name__ == "__main__":
    main()
