# Threat Detection Data Schema

This document outlines the log structures and telemetry schemas used by SentinAI NetGuard's detection engines (`LogCollector` and `PacketSniffer`) to identify and report threats.

## 1. System Logs (SSH / Syslog)
The `LogCollector` service monitors `/var/log/auth.log` via SSH and uses Regex pattern matching to detect specific events.

### Detection Logic
| Event Type | Log Pattern (Keyword Match) | Extracted Fields | Risk Score |
| :--- | :--- | :--- | :--- |
| **SSH Brute Force** | `Failed password` | `attacker_ip` (captured via `from (\d+\.\d+\.\d+\.\d+)`) | **75 (High)** |
| **SSH Successful Login** | `Accepted password` | `attacker_ip` | **50 (Medium)** |
| **Privilege Escalation** | `sudo:` AND `COMMAND=` | `attacker_ip` (Local User) | **60 (Medium)** |

### Example Log Lines
**Brute Force Attempt:**
```
Jan 10 14:32:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
```
*   **Extracted IP:** `192.168.1.100`

**Successful Login:**
```
Jan 10 14:32:05 server sshd[1234]: Accepted password for user ubuntu from 192.168.1.50 port 54322 ssh2
```
*   **Extracted IP:** `192.168.1.50`

---

## 2. Network Telemetry (Packet Sniffer)
The `PacketSniffer` captures raw network packets and converts them into a structured JSON payload for Machine Learning analysis.

### Telemetry Schema
The ML model expects the following features for real-time classification:

```json
{
  "timestamp": "2024-03-15T10:30:00Z",  // ISO 8601 UTC
  "source_ip": "192.168.1.100",         // Attacker IP
  "destination_ip": "10.0.0.5",         // Victim IP
  "source_country": "UNK",              // Geo-tag (Optional)
  "protocol": "TCP",                    // TCP, UDP, ICMP
  "packet_size": 64,                    // Integer (bytes)
  "dest_port": 22,                      // Target Port
  "predicted_label": "SSH Brute Force", // ML Classification Output
  "attack_probability": 0.95            // Confidence Score (0.0 - 1.0)
}
```

### Detection Logic
The ML model classifies traffic based on behavioral patterns (e.g., high packet frequency, small packet sizes, specific port targeting) rather than static signatures. Common detections include:
*   **DDoS** (High volume, many connections)
*   **Port Scan** (Sequential port access)
*   **Brute Force** (Repeated small packets to port 22)
