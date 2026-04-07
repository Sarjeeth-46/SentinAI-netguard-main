# SentinAI NetGuard: Project Modules

This document provides a technical breakdown of the entire system, categorized by functional module.

## 1. Backend Core (`backend/core/` & `backend/`)
**Purpose**: The central nervous system of the application, handling API requests, configuration, and security.

*   **`api_gateway.py`**: The main FastAPI application. Defines all HTTP endpoints (REST API) and WebSocket channels for real-time communication.
*   **`main.py`**: The entry point. Launches the Uvicorn server to serve the API.
*   **`core/config.py`**: Central Management for settings (DB URI, Secret Keys, Debug Mode). Loads from `.env`.
*   **`core/security.py`**: Cryptographic utilities. Handles Password Hashing (Bcrypt) and JWT Token generation.
*   **`core/deps.py`**: Dependency Injection. Contains `get_current_user` to secure API routes.

## 2. Detection Services (`backend/services/`)
**Purpose**: The "Active" workers that gather data from the environment.

*   **`packet_sniffer.py`**: **Network Monitor**. Uses Scapy to capture live packets from the network card (`eth0`). Calls the ML Engine for prediction and broadcasts results.
*   **`log_collector.py`**: **System Monitor (HIDS)**. Uses SSH (Paramiko) to connect to remote servers and tail system logs (e.g., `/var/log/auth.log`) for intrusion attempts.
*   **`auth_service.py`**: **User Management**. Handles login logic, user creation, and password rotation.

## 3. Intelligent Engine (`backend/engine/`)
**Purpose**: The "Brain" that analyzes raw data.

*   **`inference.py`**: Loads the trained Random Forest model (`model_real.pkl`). Receives raw packet data, extracts features, and returns a classification (e.g., "DDoS") and Risk Score.
*   **`traffic_generator.py`**: (Development Tool) Simulates network traffic flow for testing without a real network.

## 4. Operational Tools (`backend/tools/`)
**Purpose**: Helper scripts for deployment and verification.

*   **`verify_installation.py`**: **Pre-flight Checker**. Verifies Python libraries, DB connection, and API security.
*   **`run_sniffer_service.py`**: Launcher for the Packet Sniffer (handles sudo/path issues).
*   **`run_log_collector.py`**: Launcher for the SSH Log Collector.
*   **`add_admin.py`**: Utility to manually create an admin user in the system.

## 5. Frontend Dashboard (`frontend/src/`)
**Purpose**: The Visual Command Center for the SOC Analyst.

*   **`App.jsx`**: Main Controller. Orchestrates layout and global state.
*   **`hooks/useSecurityDashboard.js`**: **Data Layer**. Manages API polling and WebSocket connections to the backend.
*   **`hooks/useAuth.js`**: **Security Layer**. Manages JWT tokens and Login/Logout state.
*   **`components/Visualizers/`**:
    *   `GeoThreatMap.jsx`: Visualizes attack origins.
    *   `TopologyGraph.jsx`: Shows network node relationships.
*   **`components/Layout/`**:
    *   `ThreatTable.jsx`: The live feed of incidents.
    *   `KPIGrid.jsx`: Top-level metrics (High Risk Count, System Health).

## 6. Database
**Purpose**: Persistence Layer.

*   **MongoDB**: Stores user profiles (`users` collection) and historical threat data (`events` collection).
