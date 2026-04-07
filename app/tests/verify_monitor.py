
import paramiko
import time
import os

HOST = "192.168.56.10"
USER = "cloud"
WRONG_PASS = "wrongpassword123"

def simulate_attack():
    print(f"Attempting SSH connection to {HOST} with wrong password...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, username=USER, password=WRONG_PASS, timeout=5)
    except paramiko.AuthenticationException:
        print("Authentication Success (Wait, I mean Failure! Which is Success for us!)")
    except Exception as e:
        print(f"Connection Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    simulate_attack()
