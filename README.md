# SentinAI NetGuard: AI-Powered Network Security Operations Center

**SentinAI NetGuard** is an enterprise-grade threat detection & response platform designed to simulate, detect, and mitigate cyber-attacks in real-time. It leverages advanced Machine Learning profiles to distinguish between organic traffic and adversarial vectors (DDoS, Brute Force, Port Scanning) with high precision.

---

## 🏛️ System Architecture

The platform follows a **Domain-Driven Design (DDD)** micro-architecture, split into three core pillars:

### 1. The Cortex (Backend)
*   **Application Controller** (`api_gateway`): High-performance FastAPI router managing authentication and data flow.
*   **Network Sentinel** (`run_live_detection`): Persistent monitoring engine that orchestrates the detection loop.
*   **Inference Engine** (`detector`): Scikit-learn wrapper implementing the Random Forest classification logic.
*   **Telemetry Synthesizer** (`log_generator`): Probabilistic engine for generating realistic organic and malicious network packets.

### 2. The Persistence Layer
*   **Intelligence Persistence** (`database`): A hybrid data access layer supporting **MongoDB Cluster** (Production) and **Local Fallback** (Disconnected/Lab Mode).
*   **Metric Pipeline** (`analytics_service`): Real-time server-side aggregation for dashboard analytics (Risk Histograms, Attack Vectors).

### 3. The Visual Command Center (Frontend)
*   React 18 + Vite dashboard featuring:
    *   **Live Threat Feed**: Real-time websocket-style (polling) table.
    *   **Geo-Spatial Map**: Visualizing threat origins.
    *   **Network Topology**: Interactive node graphs.
    *   **Admin Tools**: User management and Mitigation (Block) controls.

---

## 🚀 Quick Start

### Docker (Recommended)
Deploy the full stack in minutes using the containerized build.

```bash
docker-compose up --build
```
Access the dashboard at `http://localhost`.

### Lab / Virtual Machine Deployment
For detailed instructions on deploying to a distributed **3-VM Lab (Server, Analyst, Client)**, see:
*   [📄 LAB_SETUP.md](./LAB_SETUP.md)

### Production Deployment
For deploying to a Linux VM (Ubuntu) with Systemd and Nginx:
*   [📄 DEPLOYMENT.md](./DEPLOYMENT.md)

---

## 🛠️ Developer Tools

### Attack Simulation (Red Team)
Trigger specific attack patterns to test the detection engine:
```bash
# Simulate a DDoS attack
python backend/tools/simulate_attack.py --type ddos --count 100

# Simulate a Brute Force attempt
python backend/tools/simulate_attack.py --type brute_force
```

---

## 🔒 Security & Compliance
*   **Auth**: JWT-based session management with role-based access control (SOC Analyst vs Admin).
*   **Audit**: Full telemetry logging for post-incident forensics.
*   **Resilience**: Circuit-breaker patterns implemented for Database connections.

---
© 2024 SentinAI Research Team. All Rights Reserved.
