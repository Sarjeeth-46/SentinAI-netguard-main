
import paramiko
import time
import os
import sys

TARGET_IP = os.getenv("TARGET_SERVER_IP", "192.168.56.10")
TARGET_USER = "test_aggregation_user"
WRONG_PASS = "wrongpassword123"

def simulate_failed_login():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Attempting login to {TARGET_USER}@{TARGET_IP}...")
        client.connect(TARGET_IP, username=TARGET_USER, password=WRONG_PASS, timeout=2)
    except paramiko.AuthenticationException:
        print("Login Failed (Expected)")
    except Exception as e:
        print(f"Connection Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    print("Simulating 6 Failed SSH Attempts within 10 seconds...")
    for i in range(6):
        simulate_failed_login()
        time.sleep(1)
    print("Done. Check logs for SINGLE alert.")
