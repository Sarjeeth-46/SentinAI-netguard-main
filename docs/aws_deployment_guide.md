# SentinAI NetGuard: AWS Deployment Guide

This guide provides step-by-step instructions for deploying SentinAI NetGuard to Amazon Web Services (AWS) using the AWS Management Console. 

Since AWS does not support hypervisor-level "Promiscuous Mode" required for our local packet sniffing setup, this guide utilizes **AWS VPC Traffic Mirroring** to seamlessly copy and forward network traffic to our ML Engine.

---

## Architecture Overview

1.  **VPC:** Custom VPC (e.g., `10.0.0.0/16`)
2.  **NetGuard Core VM:** EC2 instance (Ubuntu, `t3.medium`) running FastAPI, ML Engine, MongoDB, and the `scapy` sniffer.
3.  **Target Server VM:** EC2 instance (Ubuntu, `t3.micro`) hosting the victim web server (Apache).
4.  **Kali Attacker VM:** EC2 instance used for launching external threats.
5.  **Frontend Dashboard:** S3 Static Hosting with CloudFront or AWS Amplify.

---

## Step 1: Network Preparation (VPC & Subnets)

1.  Navigate to **VPC Console** -> **Your VPCs** -> **Create VPC**.
2.  Select **VPC and more**.
3.  Set the IPv4 CIDR block to `10.0.0.0/16`.
4.  Configure 1 Public Subnet and 1 Private Subnet.
5.  Click **Create VPC**.

### Define Security Groups (SGs)

1.  Navigate to **EC2 Console** -> **Security Groups** -> **Create security group**.
2.  **NetGuard-Core-SG**:
    *   **Inbound**: 
        *   Port `8000` (TCP) from Anywhere (For the Frontend to hit the API).
        *   Port `22` (SSH) from your IP.
        *   Port `4789` (UDP) from the VPC `10.0.0.0/16` (Crucial for VPC Traffic Mirroring VXLAN decapsulation).
        *   Port `27017` (TCP) from `localhost` or specific internal IPs for MongoDB.
3.  **Target-Server-SG**:
    *   **Inbound**: Ports `80` (HTTP) and `22` (SSH) from Anywhere (so the Attacker can test it).

---

## Step 2: Provisioning EC2 Instances

### 1. Launch the Target Server (Victim)
1.  **AMI:** Ubuntu 22.04 LTS
2.  **Instance Type:** `t3.micro`
3.  **Network:** Place it in your Public Subnet (so it has internet access for the attacker).
4.  **Security Group:** Attach `Target-Server-SG`.
5.  **User Data (Optional):**
    ```bash
    #!/bin/bash
    apt update -y
    apt install apache2 -y
    systemctl start apache2
    systemctl enable apache2
    ```

### 2. Launch the NetGuard Core Node (Analyzer)
1.  **AMI:** Ubuntu 22.04 LTS
2.  **Instance Type:** `t3.medium` (Minimum requirement for Scikit-Learn memory overhead).
3.  **Network:** Place it in the Public Subnet (for easy Dashboard access).
4.  **Security Group:** Attach `NetGuard-Core-SG`.

---

## Step 3: Configure VPC Traffic Mirroring (The Secret Sauce)

This replaces Promiscuous Mode. We will mirror all inbound/outbound packets from the Target Server explicitly into the NetGuard Core server.

1.  **Create Traffic Mirror Target**:
    *   Navigate to **VPC Console** -> **Traffic Mirroring** -> **Mirror Targets**.
    *   Click **Create traffic mirror target**.
    *   **Target Type:** Network Interface.
    *   **Target:** Select the Elastic Network Interface (ENI) belonging to the **NetGuard Core Node**.
2.  **Create Traffic Mirror Filter**:
    *   Navigate to **Traffic Mirror Filters** -> **Create**.
    *   Name it `Capture-All`.
    *   Add an **Inbound Rule** and **Outbound Rule**: Action = `Accept`, Protocol = `All Protocols` (0-65535).
3.  **Create Traffic Mirror Session**:
    *   Navigate to **Traffic Mirror Sessions** -> **Create**.
    *   **Mirror source:** The ENI of the **Target Server**.
    *   **Mirror target:** Select the Target you created in step 1.
    *   **Filter:** Select the `Capture-All` filter.
    *   Click **Create**.

---

## Step 4: Software Configuration (On NetGuard Core)

SSH into the **NetGuard Core** instance.

### 1. Decapsulate VXLAN Traffic
Traffic mirroring wraps mirrored packets in a VXLAN header. You must attach a virtual interface to decapsulate them for `scapy`.
```bash
# Extract the IP of the Core Node
LOCAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

# Create the VXLAN interface
sudo ip link add vxlan0 type vxlan id 1 local $LOCAL_IP dstport 4789
sudo ip link set vxlan0 up
```

### 2. Install Dependencies & DB
```bash
sudo apt update -y
sudo apt install python3-pip npm mongodb-org net-tools git -y
sudo systemctl start mongod
```

### 3. Deploy SentinAI NetGuard
```bash
git clone <your-repo-link> SentinAI-netguard
cd SentinAI-netguard/backend
pip install -r requirements.txt
```

### 4. Run the Services
*Ensure you update `backend/core/config.py` with the accurate AWS IPs!*
```bash
# Terminal 1 - Backend
export DEBUG=False
export MONGO_URI="mongodb://localhost:27017/threat_detection"
python -m backend.main

# Terminal 2 - VXLAN Sniffer
sudo python backend/tools/run_sniffer_service.py vxlan0

# Terminal 3 - System Log Collector (targeting the Target Server IP)
export TARGET_SERVER_IP="<Target_Private_IP>"
python backend/tools/run_log_collector.py
```

---

## Step 5: Frontend Hosting (AWS Amplify / S3)

To decouple the UI from the ML engine:
1.  Navigate to **AWS Amplify** -> **Host a web app**.
2.  Connect your GitHub repository.
3.  In the Build settings, inject your Environment Variables:
    *   `VITE_API_BASE_URL=http://<NetGuard_Core_Public_IP>:8000/api`
    *   `VITE_WS_BASE_URL=ws://<NetGuard_Core_Public_IP>:8000/api/ws`
4.  Deploy! Use the given Amplify URL to log in.

*Note: In a true production environment, attach an Application Load Balancer to the NetGuard EC2 instance with an SSL certificate to ensure secure HTTPS communication for the dashboard.*
