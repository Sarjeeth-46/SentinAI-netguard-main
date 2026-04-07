
# Tasks

- [x] Investigate current live monitoring capabilities <!-- id: 0 -->
    - [x] Check backend for packet capturing (Scapy, sockets) <!-- id: 1 -->
    - [x] Check data ingestion pipeline (how data gets to the model) <!-- id: 2 -->
    - [x] Verify if "live" means real-time network traffic or file monitoring <!-- id: 3 -->
- [x] Create Detailed 4-VM Implementation Plan <!-- id: 4 -->
    - [x] Define roles and software stack for Ubuntu Server (Security Logs) <!-- id: 5 -->
    - [x] Define roles and software stack for Ubuntu Desktop (Project Host) <!-- id: 6 -->
    - [x] Define roles and software stack for Normal User <!-- id: 7 -->
    - [x] Define roles and software stack for Attacker (Kali) <!-- id: 8 -->
    - [x] Design network topology and addressing <!-- id: 9 -->
    - [x] Define data flow (Logs -> Collector -> Analysis -> Dashboard) <!-- id: 10 -->
    - [x] Create separate `deployment_guide.md` manual <!-- id: 15 -->
- [ ] Implement Live Monitoring Code <!-- id: 11 -->
    - [x] Modify `packet_sniffer.py` to use `InferenceEngine` <!-- id: 12 -->
    - [x] Create `run_sniffer_service.py` tool <!-- id: 13 -->
    - [x] Create `verify_installation.py` tool <!-- id: 15 -->
    - [x] Verify local execution (Simulation) <!-- id: 14 -->

- [x] system Hardening & Polish (The "Perfect" Update) <!-- id: 16 -->
    - [x] Secure API Routes (Add Authentication Middleware) <!-- id: 17 -->
    - [x] Optimize Configuration (Env Vars for Secrets, Debug Mode Toggle) <!-- id: 18 -->
    - [x] Improve Error Handling & Logging <!-- id: 19 -->
    - [x] Add Input Validation (Pydantic Models) <!-- id: 20 -->

- [x] Implement Host-Based Log Collector (HIDS) <!-- id: 21 -->
    - [x] Update Config with SSH Credentials <!-- id: 22 -->
    - [x] Create `log_collector.py` (Paramiko SSH Logic) <!-- id: 23 -->
    - [x] Create `run_log_collector.py` runner <!-- id: 24 -->
    - [x] Create `log_collector.py` (Paramiko SSH Logic) <!-- id: 23 -->
    - [x] Create `run_log_collector.py` runner <!-- id: 24 -->
    - [x] Update Architecture Data Flow Doc <!-- id: 25 -->
    - [x] Create `migration_guide.md` for Windows transfer <!-- id: 26 -->
