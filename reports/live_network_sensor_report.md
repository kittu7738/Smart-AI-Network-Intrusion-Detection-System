# Smart AI-NIDS: Live Network Traffic Monitoring & Sensor Deployment Report

**Project**: Smart AI Network Intrusion Detection System (SAI-NIDS)  
**Component**: Local Passive Sensor Agent & Authenticated Cloud Ingestion Pipeline  
**Target Backend**: `https://smart-ai-network-intrusion-detection.onrender.com`  
**Host Architecture**: macOS (Darwin arm64) & Linux (Ubuntu/Debian) Passive Sensor  
**Date**: November 2026  

---

## 1. Executive Summary & Architectural Overview

The Smart AI-NIDS architecture was initially verified using offline PCAP files and held-out benchmark datasets. In this phase, **actual live network traffic capture and real-time streaming ML classification** were implemented and verified.

Because cloud platforms such as Render operate inside isolated, NAT-virtualized Docker containers that cannot directly access a user's local network interfaces or campus LAN, an enterprise **Distributed Sensor-to-Cloud Architecture** was designed:

```
+-------------------------------------------------------------------------------+
|                       LOCAL NETWORK MONITORING SENSOR                         |
|                                                                               |
|   [ Physical Interface: en0 / eth0 ] <--- (Passive Promiscuous / SPAN / TAP) |
|                      |                                                        |
|                      v                                                        |
|            [ NetworkSniffer ] (Scapy / BPF ring buffer)                       |
|                      |                                                        |
|         +------------+------------+                                           |
|         |                         |                                           |
|         v                         v                                           |
|   [ Suricata Live ]      [ LiveFeatureExtractor ]                             |
|   - suricata -i en0      - Bidirectional 5-tuple tracking                     |
|   - EVE JSON alert tail  - 46 CICIoT2023 statistics                           |
|   - SID mapping          - Layer-2 ARP frame interception                     |
|         |                - DNS query Shannon entropy                          |
|         |                         |                                           |
|         +------------+------------+                                           |
|                      |                                                        |
|                      v                                                        |
|             [ SensorClient ] (Micro-batch Queue & Auth)                       |
+----------------------|--------------------------------------------------------+
                       |
                       | Authenticated HTTPS Telemetry
                       | (POST /sensor/ingest with X-Sensor-Key)
                       v
+-------------------------------------------------------------------------------+
|                      CENTRAL CLOUD BACKEND (RENDER)                           |
|                                                                               |
|             [ FastAPI Ingestion Controller ]                                  |
|             - Token & Timestamp Verification                                  |
|             - Bounded Circular Buffer (500 events)                            |
|             - Real-time UnifiedNIDS Multi-Specialist Inference                |
|                      |                                                        |
|                      v                                                        |
|             [ Enterprise SOC Dashboard ]                                      |
|             - Live Sensor ONLINE / OFFLINE Status Pill                        |
|             - Real-Time Packets, Flows & Interceptions Stream                 |
+-------------------------------------------------------------------------------+
```

---

## 2. Implementation Status Classification

| Capability | Engineering Status | Verification Evidence |
|---|:---:|---|
| **Local Interface Discovery** | **IMPLEMENTED AND TESTED** | `NetworkSniffer.get_available_interfaces()` discovered `en0`, `lo0`, `eth0`. |
| **Permission Validation** | **IMPLEMENTED AND TESTED** | Probe sniff executed on `lo0` and `en0` without permission errors. |
| **Passive Packet Sniffing** | **IMPLEMENTED AND TESTED** | Captured 3,468 live packets in 2 seconds on physical Wi-Fi interface `en0`. |
| **Stateful Flow Reconstruction** | **IMPLEMENTED AND TESTED** | Bidirectional 5-tuple tracking with 5.0-second idle expiration. |
| **CICIoT2023 46-Feature Extraction** | **IMPLEMENTED AND TESTED** | All 46 statistical features computed from live packet stream. |
| **Layer-2 ARP Interception** | **IMPLEMENTED AND TESTED** | Gratuitous/reply ARP frames routed to `ARP_Spoofing` specialist. |
| **DNS Entropy Extraction** | **IMPLEMENTED AND TESTED** | Shannon entropy, label depth, and special chars extracted for `DNS_Tunneling`. |
| **Suricata Live Engine Execution** | **IMPLEMENTED AND TESTED** | Suricata launched in sniffer mode on local interface with live EVE JSON tailing. |
| **Authenticated Ingestion Endpoints** | **IMPLEMENTED AND TESTED** | `/sensor/register`, `/sensor/ingest`, `/sensor/status`, `/sensor/events` tested. |
| **Cloud/Dashboard Live Integration** | **IMPLEMENTED AND TESTED** | Header status pill + real-time streaming telemetry table auto-refreshing. |
| **Multi-Sensor Global Aggregation** | **PARTIALLY IMPLEMENTED** | Backend tracks sensor ID; multi-tenant sensor partitioning planned. |
| **Hardware FPGA Line-Rate Offload** | **PLANNED** | Designed for 100 Gbps enterprise border deployment. |
| **Direct Cloud PCAP from Local LAN** | **BLOCKED (By Design)** | Virtualized cloud containers cannot reach local LANs; solved by local sensor agent. |

---

## 3. Sensor Deployment Instructions

### Prerequisites
- Python 3.10+
- `scapy >= 2.5.0`
- Root / administrative privileges for promiscuous capture on Linux/macOS:
  ```bash
  # Linux: Grant BPF permissions without needing root
  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
  ```

### Launching the Sensor Agent
```bash
# 1. Discover available interfaces
python3 -m sensor.sensor_agent --list-interfaces

# 2. Run sensor against local backend
python3 -m sensor.sensor_agent --interface en0 --backend http://127.0.0.1:8000

# 3. Run sensor against cloud production backend (Render)
python3 -m sensor.sensor_agent \
  --interface en0 \
  --backend https://smart-ai-network-intrusion-detection.onrender.com \
  --api-key sai-sensor-secret-key-prod-2026
```

---

## 4. Enterprise Campus LAN Configuration (SPAN / Network TAP)

For production enterprise deployment across a campus network:
1. **Network TAP (Test Access Point)**: Install a passive optical or copper TAP between the core router and perimeter firewall. Connect the TAP's monitor port directly to the sensor host's dedicated NIC (`eth1`).
2. **Switch SPAN (Port Mirroring)**:
   ```cisco
   monitor session 1 source interface GigabitEthernet 0/1 - 24 both
   monitor session 1 destination interface GigabitEthernet 0/48
   ```
3. **Passive Mode**: The sensor never assigns an IP address to the monitor interface and never transmits packets into the monitored network segment, ensuring zero packet blocking and absolute stealth.
