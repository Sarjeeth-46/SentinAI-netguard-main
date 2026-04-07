# Migration Guide: Transferring to a New Windows Machine

This guide explains how to move the entire **SentinAI NetGuard** project from your current computer to a new Windows Desktop.

## Phase 1: Preparation (On Old Machine)

### 1. Clean Up
Remove heavy folders that can be strictly re-downloaded to save space and transfer time.
*   **Delete** `frontend/node_modules/` (This is huge and contains thousands of files).
*   **Delete** `backend/__pycache__/` folders (Optional, but cleaner).

### 2. Package the Code
1.  Go to the parent folder `c:\`.
2.  Right-click the `SentinAI-netguard` folder.
3.  Select **Send to > Compressed (zipped) folder**.
4.  Name it `SentinAI-netguard-backup.zip`.
5.  Copy this `.zip` file to a USB drive or Cloud Storage (Google Drive/OneDrive).

### 3. Save Environment Variables
If you have a `.env` file in `backend/`, make sure it is included in the zip. If you set variables manually in the terminal, write them down (e.g., `SECRET_KEY`, `TARGET_SERVER_IP`).

---

## Phase 2: Setup (On New Machine)

### 1. Install Prerequisites
Before copying the code, install the foundational software on the new Windows machine:
1.  **Python** (3.10 or newer): [Download Here](https://www.python.org/downloads/).
    *   *Crucial*: Check **"Add Python to PATH"** during installation.
2.  **Node.js** (LTS Version): [Download Here](https://nodejs.org/).
3.  **MongoDB Community Server**: [Download Here](https://www.mongodb.com/try/download/community).
    *   Install checks: "Install MongoDB as a Service".
    *   (Optional) Install **MongoDB Compass** for a UI.
4.  **Npcap** (Required for Packet Sniffing on Windows): [Download Here](https://npcap.com/).
    *   Check **"Install Npcap in WinPcap API-compatible Mode"**.

### 2. Unpack the Project
1.  Copy `SentinAI-netguard-backup.zip` to the new computer (e.g., `C:\Users\YourName\Documents`).
2.  Right-click and **Extract All**.

### 3. Re-Hydrate Dependencies

**Open Command Prompt (cmd) or PowerShell** and run:

**Backend Setup:**
```powershell
cd C:\Users\YourName\Documents\SentinAI-netguard\backend
pip install -r requirements.txt
```

**Frontend Setup:**
```powershell
cd C:\Users\YourName\Documents\SentinAI-netguard\frontend
npm install
```

### 4. Verify Installation
We have a tool for this! Run it to make sure the new environment is ready.
```powershell
cd C:\Users\YourName\Documents\SentinAI-netguard
python backend\tools\verify_installation.py
```
*   If it prints "✅ READY FOR DEPLOYMENT", you are good to go.

---

## Phase 3: Launching

**Terminal 1 (Backend):**
```powershell
cd backend
$env:DEBUG="False"
python main.py
```

**Terminal 2 (Frontend):**
```powershell
cd frontend
npm start
```
