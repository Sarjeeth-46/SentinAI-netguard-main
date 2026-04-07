# 4-VM Live Monitoring Implementation Plan

## Goal Description
Implement a realistic "Live Monitoring" environment for SentinAI NetGuard using four virtual machines. This setup will demonstrate the system's ability to detect attacks in real-time from a dedicated attacker against a target server, while normal user traffic is also present.
We will also update the `packet_sniffer.py` to perform *actual* ML inference using the trained model instead of using placeholders.

## User Review Required
> [!IMPORTANT]
> This plan requires provisioning **4 Virtual Machines**. You (the user) must set these up in your virtualization software (VirtualBox/VMware/Proxmox). This plan provides the *configuration* for them.

> [!WARNING]
> The `packet_sniffer.py` changes will enable *real* detection. Ensure the trained model (`rf_model.pkl`) is present in `backend/models/`.

## Architecture Overview

We will use a "Promiscuous Monitor" architecture. The NetGuard Machine (VM 2) will passively sniff all traffic going to the Target Server (VM 3).

| VM ID | Role | OS | IP Address (Example) | Software Stack |
| :--- | :--- | :--- | :--- | :--- |
| **VM 1** | **Attacker** | Kali Linux | `192.168.1.101` | `hping3`, `hydra`, `nmap` |
| **VM 2** | **NetGuard Core** | Ubuntu Desktop | `192.168.1.102` | **Frontend**, **Backend**, **MongoDB**, **Packet Sniffer** |
| **VM 3** | **Target Server** | Ubuntu Server | `192.168.1.103` | Apache/Nginx (Web), SSH |
| **VM 4** | **Normal User** | Windows/Ubuntu | `192.168.1.104` | Web Browser, `ping`, SSH Client |

**Network Config:** All VMs must be on the same **Bridged Network** (or internal Network with Promiscuous Mode "Allow All" enabled for VM 2).

## Proposed Changes

### Backend Component

#### [MODIFY] [packet_sniffer.py](file:///c:/SentinAI-netguard/backend/services/packet_sniffer.py)
- Import `InferenceEngine` from `backend.engine.inference`.
- Remove hardcoded heuristics (lines 66-80).
- Call `InferenceEngine.predict(telemetry)` to get real `label` and `risk_score`.
- Ensure `scapy.sniff` captures on the correct interface.

#### [MODIFY] [run_sniffer_service.py](file:///c:/SentinAI-netguard/backend/tools/run_sniffer_service.py)
- Create a new script (or modify existing) to easily launch the sniffer with proper permissions.

## VM Setup Instructions (Manual Steps for User)

### 1. VM 2 (NetGuard Core) Setup
This is where the code resides.
1.  **Dependencies**: Install Python, Node.js, MongoDB.
2.  **Code**: Clone/Copy the `SentinAI-netguard` repo here.
3.  **Promiscuous Mode**: Configure the VM network adapter settings to **"Promiscuous Mode: Allow All"**. This is CRITICAL for it to see VM 3's traffic.
4.  **Run**: Start Backend, Frontend, and the Sniffer.

### 2. VM 3 (Target) Setup
1.  Install a web server: `sudo apt install apache2`.
2.  Ensure SSH is running: `sudo systemctl start ssh`.
3.  **No NetGuard code needed here** (Agentless monitoring via VM 2).

### 3. VM 1 (Attacker) Setup
1.  Use Kali Linux.
2.  Attack Scripts:
    - **DDoS**: `hping3 -S --flood -p 80 192.168.1.103` (Targeting VM 3)
    - **Brute Force**: `hydra -l root -P passlist.txt ssh://192.168.1.103`
    - **Port Scan**: `nmap -sS -p- 192.168.1.103`

### 4. VM 4 (Normal User) Setup
1.  Just browse the website hosted on VM 3 (`http://192.168.1.103`).
2.  SSH into VM 3 normally.

## Verification Plan

### Automated Tests
- **Simulate Sniffing**: Run `packet_sniffer.py` locally and generate local traffic (ping google.com) to verify it detects flows and writes to DB with "Normal" label.
- **Unit Test Inference**: Verify `packet_sniffer.py` successfully imports and calls `InferenceEngine.predict`.

### Manual Verification (Once VMs are up)
1.  **Start NetGuard** on VM 2.
2.  **Generate Traffic** from VM 1 (Attack) and VM 4 (Normal) towards VM 3.
3.  **Check Dashboard**: Verify that the NetGuard Dashboard on VM 2 starts showing "Brute Force" or "DDoS" alerts originating from VM 1's IP.
