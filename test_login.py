from fastapi.testclient import TestClient
from app.api.api_gateway import app
import traceback

client = TestClient(app)

try:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    print("Status:", response.status_code)
    print("Text:", response.text)
except Exception as e:
    traceback.print_exc()
