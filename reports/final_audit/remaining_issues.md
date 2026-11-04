# Smart AI-NIDS: Known Limitations & Operational Considerations

**Date**: November 4, 2026  
**Status**: Documented Engineering Constraints (No Critical Defects)  

---

## 1. Cloud Network Interface Isolation (Render vs Local LAN)

### Constraint:
Cloud hosting platforms (Render, Railway, Hugging Face Spaces) run inside containerized virtual networks with isolated NAT interfaces (`eth0` sees only container ingress/egress). They cannot bind to a physical enterprise switch SPAN port or campus LAN in promiscuous mode.

### System Solution & Documentation:
The project architecture correctly uses a **Distributed Sensor Model**:
1. The **Local Sensor Agent** (`sensor/sensor_agent.py`) runs on the monitored physical or virtual host (e.g., macOS `en0` or Linux `eth0`).
2. The sensor captures packets, extracts 46-feature flows, executes local Suricata live inspection, and streams authenticated telemetry (`POST /sensor/ingest`) to the cloud backend.
3. The Render dashboard receives and displays live telemetry in real time.
4. **Demonstration Guidance**: When presenting on Render alone without a running local sensor, the dashboard accurately displays "Sensor Offline" until an authenticated sensor agent connects.

---

## 2. Suricata Layer-2 Architectural Boundary

### Constraint:
Traditional NIDS (Suricata) operates strictly at the Network (Layer 3), Transport (Layer 4), and Application (Layer 7) layers. It does not inspect Layer 2 Ethernet frames or ARP opcodes (`arp_opcode`).

### Operational Impact:
Suricata has a 0.0% detection rate for **ARP Spoofing (Class 9)** in offline PCAP evaluation. This is not a defect in our canonical ruleset (`suricata/rules/canonical_threats.rules`), but an inherent design boundary of Suricata. The Smart AI-NIDS specialized L2 Decision Tree model achieves 100.0% recall on ARP spoofing, proving the architectural advantage of our multi-specialist approach.

---

## 3. Dataset Class Imbalance in Minority Attack Categories

### Constraint:
In the raw **CICIoT2023** dataset, certain attack categories have severe class imbalance relative to millions of volumetric DDoS/DoS flows:
- Infiltration: 85 samples
- Brute Force: 300 samples
- Web Attack: 509 samples

### Mitigation Implemented:
`utils/threshold_tuner.py` applies validation-tuned probability multipliers and sqrt-balanced sample weights during training to boost minority class sensitivity without inflating the benign false-alarm rate.

---

## 4. Large Dataset Separation from Production Artifacts

### Constraint:
The complete raw CSE-CIC-IDS2018 and CICIoT2023 datasets exceed 10 GB.

### Project Design:
The GitHub repository and Render production container deliberately exclude raw multi-gigabyte datasets. Only verified lightweight preprocessor artifacts (`preprocessor.joblib`) and trained model weights (`XGBoost.joblib`, `DecisionTree.joblib`, etc.) are committed. This maintains rapid container builds (< 2 minutes) and a low memory footprint (< 512 MB RAM).
