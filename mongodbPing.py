import os
import sys
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ConfigurationError
from dotenv import load_dotenv

# Load variables from .env automatically
load_dotenv()

def verify_mongodb_connection():
    # 1. Retrieve the connection string from environment variables.
    # It checks both the standard MONGODB_URI and your project's specific MONGO_URI
    uri = os.environ.get("MONGO_URI") or os.environ.get("MONGODB_URI", "")
    
    if not uri:
        print("❌ Error: MONGO_URI is not set in your .env file.")
        print("Please set it in your '.env' file like this: MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority")
        sys.exit(1)

    print("Attempting to connect to MongoDB Atlas...")
    
    # 2. Initialize the MongoDB client.
    # We set serverSelectionTimeoutMS to 5000 (5 seconds) to fail fast instead of hanging indefinitely.
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    
    try:
        # 3. Verify the connection with a lightweight 'ping' command.
        # The 'admin' database is accessible to all users by default and provides diagnostic commands.
        client.admin.command('ping')
        print("✅ Success: Successfully connected to MongoDB Atlas and pinged the cluster!")
        
    except ConnectionFailure as e:
        print("❌ Error: Failed to connect to the MongoDB cluster. Check your network, IP whitelist, and credentials.")
        print(f"Details: {e}")
    except ConfigurationError as e:
        print("❌ Error: Configuration issue with the connection string (e.g., missing 'mongodb+srv://').")
        print(f"Details: {e}")
    except Exception as e:
        print("❌ Error: An unexpected error occurred during the connection attempt.")
        print(f"Details: {e}")
    finally:
        # 4. Always close the connection pool to release resources gracefully before exiting.
        print("Closing the MongoDB client connection...")
        client.close()
        print("Done.")

if __name__ == "__main__":
    verify_mongodb_connection()
