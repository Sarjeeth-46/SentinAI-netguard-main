# SentinAI - AWS Deployment Guide & Architecture Setup

This guide explicitly covers Phase 5 (Architecture Design) and Phase 6 (Detailed Deployment Steps) for deploying the NetGuard threat detection platform on AWS Infrastructure.

## Architecture Blueprint
For scalable and high-performance ingestion, our production architecture maps to the following services:

- **Compute & Ingestion**: Application Load Balancer (ALB) directly fronts **Amazon EC2 instances (Amazon Linux 2023)**. This layer runs the FastAPI Backend processing telemetry logs.
- **Log Generator/Source**: A separate EC2 instance acting as the network tap or log-shipper, which forwards logs to the internal ALB endpoint.
- **Database**: **MongoDB Atlas** (M10 cluster minimum) deployed in the same AWS Region. VPC Peering is highly recommended to keep database traffic strictly internal.
- **Monitoring**: Logs are scraped by the **CloudWatch Agent** directly from EC2 systemd logs.
- **Frontend Dashboard**: Hosted on **Vercel** or an S3 Static Website with CloudFront. Ensure API endpoint maps to ALB's domain.

## Deployment Steps (EC2)

### 1. Provision EC2 Instance
- **AMI**: Amazon Linux 2023
- **Type**: t3.medium or larger (due to ML model memory footprint)
- **Security Group**:
   - Inbound SSH (Port 22) - restricted to your IP
   - Inbound HTTP (Port 80) / HTTPS (Port 443) - ALB or anywhere
   - Inbound Custom TCP (Port 8000) - For testing direct access

### 2. Environment Initialization
SSH into the newly created EC2 instance and run the following execution commands.
Do NOT use Ubuntu assumptions (`apt-get`).

```bash
# Update System Packages
sudo yum update -y

# Install Core Build Tools & Python 3.10+
sudo yum groupinstall "Development Tools" -y
sudo yum install python3 python3-pip git -y

# Install Node.js (If running frontend on the same VM)
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install nodejs -y

# Clone your project repository
git clone https://github.com/your-org/SentinAI-netguard.git
cd SentinAI-netguard
```

### 3. Backend Setup & Run

```bash
# Setup Python Virtual Environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Create .env dynamically for Production
cat <<EOT > .env
SECRET_KEY=$(openssl rand -hex 32)
DEBUG=False
MONGO_URI=mongodb+srv://<REPLACE_USER>:<REPLACE_PASS>@cluster.mongodb.net
EOT

# Ensure trained Model Exists
# You should place your trained model `model_real.pkl` in the root or app/models.
```

### 4. Create Production SystemD Service
Running `uvicorn` in a detached screen session is volatile. We will use `systemd`.

```bash
sudo tee /etc/systemd/system/sentinai.service > /dev/null <<EOT
[Unit]
Description=SentinAI Backend FastAPI Service
After=network.target

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/SentinAI-netguard
Environment="PATH=/home/ec2-user/SentinAI-netguard/venv/bin"
ExecStart=/home/ec2-user/SentinAI-netguard/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

[Install]
WantedBy=multi-user.target
EOT

# Enable and start the daemon
sudo systemctl daemon-reload
sudo systemctl enable sentinai.service
sudo systemctl start sentinai.service

# Check logs
sudo journalctl -u sentinai.service -f
```

### 5. Frontend & Ingestion Shipper Setup
Since you established a `synthetic_log_generator.py`:

To start the log generation on the *source* EC2 to simulate traffic flowing to the *backend* EC2:
```bash
# Change to point to your new AWS backend endpoints
cd SentinAI-netguard
python3 app/tools/synthetic_log_generator.py 1 10
```

## Maintenance & Common Failures

- **Connection Refused on Dashboard**: Ensure your frontend environment variables point to the ALB or EC2 Public IP, not `localhost`.
- **MongoDB Timeout (IP Whitelisting)**: Ensure your EC2's Elastic IP or VPC NAT Gateway IP is explicitly whitelisted in the MongoDB Atlas Network Access pane.
- **WebSockets Keep Dropping**: An AWS ALB will drop idle sockets. Configure `idle_timeout` on the Target Group to `3600` seconds (1 hour).
