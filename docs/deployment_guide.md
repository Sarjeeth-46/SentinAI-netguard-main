# SentinAI NetGuard: 4-VM Deployment Guide

This guide provides step-by-step instructions to deploy the SentinAI NetGuard system across four virtual machines.

## 1. Virtualization Prerequisites

You will need virtualization software (VirtualBox, VMware, or Proxmox) capable of running 4 simultaneous VMs.

**Network Configuration:**
All 4 VMs must be on the same **Bridged Network** or a dedicated **NAT Network** so they can communicate with each other.
*   **Subnet:** `192.168.1.0/24` (Example)
*   **Gateway:** `192.168.1.1`

> [!IMPORTANT]
> **Promiscuous Mode**: For the **NetGuard Core** VM, you MUST enable "Promiscuous Mode: Allow All" in your hypervisor's network settings. This allows it to see traffic destined for other VMs.

---

## 2. VM Provisioning & Setup

### VM 1: The Attacker (Kali Linux)
*   **OS:** Kali Linux (Latest)
*   **Role:** Simulates cyber attacks.
*   **Static IP (Recommended):** `192.168.1.101`
*   **Tools Required:** `nmap`, `hydra`, `hping3` (Pre-installed on Kali).

### VM 2: NetGuard Core (Ubuntu Desktop)
*   **OS:** Ubuntu 22.04 LTS Desktop
*   **Role:** Runs the Dashboard, Backend, AI Model, and Sniffer.
*   **Static IP (Recommended):** `192.168.1.102`
*   **Hardware:** 4GB RAM, 2 vCPUs (minimum for ML).

**Setup Steps:**
1.  **Install System Dependencies:**
    ```bash
    sudo apt update
    sudo apt install python3-pip nodejs npm mongodb-org net-tools git
    ```
2.  **Start MongoDB:**
    ```bash
    sudo systemctl start mongod
    sudo systemctl enable mongod
    ```
3.  **Deploy Code:**
    *   Copy the `SentinAI-netguard` project folder to `/home/user/SentinAI-netguard`.
4.  **Install Python Deps:**
    ```bash
    cd /home/user/SentinAI-netguard/backend
    pip install -r requirements.txt
    ```
    *Ensure `scikit-learn`, `pandas`, `scapy`, `pymongo` are installed.*
5.  **Install Frontend Deps:**
    ```bash
    cd /home/user/SentinAI-netguard/frontend
    npm install
    ```

### VM 3: Target Server (Ubuntu Server)
*   **OS:** Ubuntu 22.04 Server (Headless)
*   **Role:** The victim machine hosting a web service.
*   **Static IP (Recommended):** `192.168.1.103`

**Setup Steps:**
1.  **Install Web Server:**
    ```bash
    sudo apt update
    sudo apt install apache2
    sudo systemctl start apache2
    ```
2.  **Enable SSH:**
    ```bash
    sudo apt install openssh-server systemctl start ssh
    ```
    *This provides ports 80 (HTTP) and 22 (SSH) for VM 1 to attack.*

### VM 4: Normal User (Windows or Ubuntu)
*   **OS:** Windows 10/11 or Ubuntu Desktop
*   **Role:** Generates benign background traffic.
*   **Static IP (Recommended):** `192.168.1.104`

---

## 3. Running the System

### Step 0: Pre-Flight Check (Crucial)
Run the verification tool to ensure all dependencies and authentications are working.
```bash
python backend/tools/verify_installation.py
```
*   **Success Criteria**: Output says "✅ READY FOR DEPLOYMENT".

### Step 1: Start NetGuard (On VM 2)

Open 4 Terminal Tabs on **VM 2**:

**Tab 1: Backend API**
```bash
cd /home/user/SentinAI-netguard
# Ensure DEBUG=False for production
export DEBUG=False
python -m backend.main
```

**Tab 2: Frontend Dashboard**
```bash
cd /home/user/SentinAI-netguard/frontend
npm start
```

**Tab 3: Packet Sniffer (Network Monitor)**
```bash
cd /home/user/SentinAI-netguard
sudo python backend/tools/run_sniffer_service.py [interface_name]
```

**Tab 4: Log Collector (System Monitor)**
```bash
cd /home/user/SentinAI-netguard
# Ensure you configured TARGET_SERVER_IP in backend/core/config.py
python backend/tools/run_log_collector.py
```

### Step 2: Generate Normal Traffic (From VM 4)
1.  Open two terminal windows on VM 4.
2.  **Web Browsing:** Open a browser and refresh `http://192.168.1.103` repeatedly.
3.  **SSH Connection:** Connect normally: `ssh user@192.168.1.103`.
4.  **Verification:** Check the NetGuard Dashboard (VM 2). You should see "Normal" traffic with Low Risk scores appearing in the Live Feed.

### Step 3: Launch Attacks (From VM 1)
Now, simulate threats from the Kali machine.

**Attack A: Port Scan (Nmap)**
```bash
nmap -sS -p- 192.168.1.103
```
*   **Result:** NetGuard should detect "Port Scan" (Risk: High).

**Attack B: Brute Force (Hydra)**
```bash
hydra -l root -p password ssh://192.168.1.103
```
*   **Result:** NetGuard should detect "Brute Force" on port 22.

**Attack C: DoS Flood (Hping3)**
```bash
sudo hping3 -S --flood -p 80 192.168.1.103
```
*   **Result:** NetGuard should detect "DDoS" (Risk: Critical).

---

## Troubleshooting

*   **No Traffic Detected?**
    *   Check Promiscuous Mode on VM 2.
    *   Ensure all VMs are on the same subnet.
    *   Verify the interface name passed to `run_sniffer_service.py`.
*   **MongoDB Connection Error?**
    *   Ensure MongoDB is running on VM 2: `systemctl status mongod`.
    *   Check `backend/core/config.py` for the correct DB URI.
