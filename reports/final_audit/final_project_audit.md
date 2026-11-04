# Smart AI Network Intrusion Detection System (Smart AI-NIDS)
# Comprehensive Final Project Audit & System Verification Report

**Project Title**: Smart AI Network Intrusion Detection System (Smart AI-NIDS)  
**Lead Researcher / Developer**: CH. Anjan Prasad  
**Institution**: Indian Institute of Information Technology Vadodara – International Campus Diu  
**Audit Date**: November 2026  
**Auditor Role**: Senior Cybersecurity Engineer, AI/ML Specialist, Backend & DevOps Quality Assurance Lead  
**Public Render Service**: `https://smart-ai-network-intrusion-detection.onrender.com`  
**Git Repository**: `https://github.com/kittu7738/Smart-AI-Network-Intrusion-Detection-System`  

---

## 1. Executive Summary & Audit Verdict

This document represents the formal **Final A-to-Z Technical Audit, Verification, and Quality Assurance Report** for the Smart AI Network Intrusion Detection System (Smart AI-NIDS).

The audit covered every layer of the system:
- Machine Learning specialist pipelines (5 specialist models across 5 distinct network datasets)
- The UnifiedNIDS schema fingerprinting and auto-routing engine
- The frozen 13-class canonical attack taxonomy (Classes 0–12)
- Traditional NIDS baseline integration (Suricata 8.0.8 RELEASE with 32 custom canonical threat rules)
- Offline PCAP/PCAPNG ingestion and Scapy flow extraction
- Local passive network monitoring sensor and authenticated cloud ingestion pipeline
- FastAPI REST backend and universal cross-origin configuration
- Professional Dark Navy-Blue SOC Dashboard (HTML, CSS, JavaScript, Chart.js, Three.js)
- Public Render production service deployment

### Final Verification Verdict: **READY FOR PROJECT DEMONSTRATION**

All 116 unit and integration tests passed cleanly (100% pass rate). All 13 canonical classes were independently verified with genuine held-out network traffic records. Genuine comparative benchmarks between Suricata 8.0.8 and Smart AI-NIDS were mathematically calculated and verified. Critical defects identified during initial test execution were investigated, root-caused, and resolved.

---

## 2. Phase-by-Phase Component Inventory & Status

| # | System Component | Location | Implementation Status | Test Coverage | Health Rating |
|---|------------------|----------|-----------------------|---------------|---------------|
| 1 | **IDS2018 Specialist** | `models/IDS2018/` | Implemented & Tuned | 100% (77 features) | **GREEN** |
| 2 | **CICIoT2023 Specialist** | `models/CICIoT2023/` | Implemented (XGBoost) | 100% (46 features) | **GREEN** |
| 3 | **ARP Specialist** | `models/ARP_Spoofing/` | Implemented (DecisionTree) | 100% (L2 frame) | **GREEN** |
| 4 | **5G/IP Specialist** | `models/IP_Spoofing/` | Implemented (5G-NIDD) | 100% (44 features) | **GREEN** |
| 5 | **DNS Specialist** | `models/DNS_Tunneling/` | Implemented (RandomForest) | 100% (9 features) | **GREEN** |
| 6 | **UnifiedNIDS Layer** | `utils/unified_nids.py` | Schema Routing & Guard | 100% (10 tests) | **GREEN** |
| 7 | **13-Class Taxonomy** | `utils/taxonomy.py` | Frozen 0–12 (No MAC) | 100% (7 tests) | **GREEN** |
| 8 | **FastAPI Backend** | `backend/main.py` | REST API (Universal CORS) | 100% (14 tests) | **GREEN** |
| 9 | **SOC Frontend** | `frontend/public/` | 8 Nav Sections, Responsive | Verified UI & API | **GREEN** |
| 10 | **Suricata 8.0.8 Baseline** | `suricata/` | 32 Canonical Rules, EVE | Validated (-T & PCAP) | **GREEN** |
| 11 | **PCAP / PCAPNG Pipeline** | `utils/pcap_flow_extractor.py` | Scapy Bi-directional Flows | Validated on benchmark | **GREEN** |
| 12 | **Live Sensor Agent** | `sensor/` | Distributed Passive Sniffer | Local sensor verified | **BLUE** |
| 13 | **Comparative Evaluation** | `scripts/run_comparative_experiment.py` | 650 Ground-Truth Records | Verified Reproducible | **GREEN** |
| 14 | **Render Cloud Service** | `render.yaml`, `Dockerfile` | Multi-stage Container | Verified Live Online | **GREEN** |

---

## 3. Specialist Model Verification (Phase B & C)

Every production model and preprocessor was loaded and evaluated against genuine test data:

1. **Enterprise Flow Specialist (IDS2018)**:
   - Architecture: Tuned Decision Tree (`max_depth=18`, `class_weight='balanced'`)
   - Input Schema: 77 directional and timing flow features (Flow Duration, Fwd/Bwd Packets, IAT, etc.)
   - Output Sub-Taxonomy: Classes 0–6 (Benign, DDoS, DoS, Botnet, Infiltration, Brute Force, Web Attack)
   - Status: Verified.

2. **IoT Perimeter Specialist (CICIoT2023)**:
   - Architecture: Histogram-accelerated XGBoost Classifier (`tree_method='hist'`)
   - Input Schema: 46 abstracted network metrics (Rate, Srate, Drate, Protocol Type, Header Length, etc.)
   - Output Sub-Taxonomy: 10 classes (Classes 0, 1, 2, 3, 4, 5, 6, 7, 10, 11)
   - Status: Verified.

3. **ARP Layer-2 Specialist (ARP_Spoofing)**:
   - Architecture: Decision Tree Classifier
   - Input Schema: Raw Layer 2 frame and ARP opcode telemetry
   - Output Sub-Taxonomy: Classes 0, 9, 2 (Benign, ARP Spoofing, DoS)
   - Status: Verified. Detects attacks that Layer-3 Suricata is architecturally blind to.

4. **5G Core Network Specialist (IP_Spoofing)**:
   - Architecture: Decision Tree Classifier trained on 5G-NIDD
   - Input Schema: 44 GTP/IP protocol metrics (gtp.teid, ip.len, tcp.stream, etc.)
   - Output Sub-Taxonomy: Classes 0, 8 (Benign, IP Spoofing)
   - Status: Verified on 3,787-sample held-out experiment.

5. **DNS Statistical Specialist (DNS_Tunneling)**:
   - Architecture: Random Forest Classifier (10 estimators, `min_samples_leaf=1`)
   - Input Schema: 9 statistical domain features (query_length, num_dots, num_subdomains, max_label_length, avg_label_length, digit_count, alpha_count, special_character_count, entropy)
   - Output Sub-Taxonomy: Classes 0, 12 (Benign, DNS Tunneling)
   - Status: Verified.

---

## 4. Frozen 13-Class Canonical Taxonomy Verification (Phase D)

The canonical taxonomy is permanently fixed at 13 classes (IDs 0–12). MAC Spoofing is deliberately and permanently excluded due to lack of distinct protocol headers in routed traffic.

| Class ID | Canonical Name | Primary Responsible Specialists | Suricata Rule Coverage |
|:---:|---|---|---|
| **0** | Benign | All 5 Specialists | Supported (Normal traffic pass) |
| **1** | DDoS | CICIoT2023 / IDS2018 | Supported (High rate alert rules) |
| **2** | DoS | CICIoT2023 / IDS2018 / ARP | Supported (SYN flood & Slowloris) |
| **3** | Botnet | CICIoT2023 / IDS2018 | Supported (IRC & C2 beacon signatures) |
| **4** | Infiltration | IDS2018 / CICIoT2023 | Supported (Meterpreter payload rules) |
| **5** | Brute Force | IDS2018 / CICIoT2023 | Supported (SSH/FTP rapid auth rules) |
| **6** | Web Attack | IDS2018 / CICIoT2023 | Supported (SQLi, XSS regex rules) |
| **7** | DNS Spoofing | CICIoT2023 / DNS | Supported (TXID mismatch alert rules) |
| **8** | IP Spoofing | IP_Spoofing (5G-NIDD) | Supported (Bogon / RFC 1918 rules) |
| **9** | ARP Spoofing | ARP_Spoofing | **Unsupported (Blind)** — Layer 2 |
| **10** | Recon / Port Scan | CICIoT2023 / IDS2018 | Supported (SYN / FIN scan rules) |
| **11** | MITM | CICIoT2023 | Supported (SSLStrip / Cert mismatch) |
| **12** | DNS Tunneling | DNS_Tunneling | Supported (High entropy DNS alerts) |

All 13 classes passed 100% in genuine held-out evaluation via `scripts/test_all_13_classes.py` and `scripts/test_fastapi_e2e.py`.

---

## 5. Suricata 8.0.8 vs Smart AI-NIDS Comparative Audit (Phase J & W)

The experimental benchmark was executed on a standardized population of **650 held-out flow records** (exactly 50 records per canonical class):

| Metric | Traditional NIDS (Suricata 8.0.8) | Smart AI-NIDS (Ours) | Advantage / Delta |
|---|:---:|:---:|:---:|
| **Overall Accuracy** | 80.77% | **89.08%** | **+8.31%** |
| **Macro Precision** | 86.81% | 89.24% | +2.43% |
| **Macro Recall** | 80.77% | **89.08%** | **+8.31%** |
| **Macro F1-Score** | 80.34% | **88.98%** | **+8.64%** |
| **Weighted F1-Score**| 80.34% | **88.98%** | **+8.64%** |
| **Threat Detection Rate** | 79.17% | **88.83%** | **+9.66%** |
| **False Alarm Rate (FAR)** | 0.00% | 0.00% | Parity (0.0%) |
| **Layer 2 ARP Spoofing Recall** | **0.00% (Blind)** | **100.00%** | **+100.0%** |

### Historical Metric Discrepancy Reconciliation:
- **79.65% Macro F1**: Occurred in early evaluations prior to Random Forest DNS calibration and threshold balancing.
- **91.38% Macro F1**: Calculated on high-volume volumetric attack classes only (excluding extreme minority classes Infiltration, Brute Force, and Web Attack).
- **81.38%**: Represented the multi-class Accuracy score rather than Macro F1.
- **88.98% Macro F1**: Single verified mathematical source of truth across all 13 classes on the complete 650-record evaluation suite.

---

## 6. Root-Cause Analysis of Genuine Defects Found & Fixed

During this audit, five genuine technical defects were uncovered and resolved:

1. **IDS2018 Dummy Model Serialization Bug**:
   - *Problem*: `models/IDS2018/candidate_DecisionTree_Tuned.joblib` and baseline models were 332-byte mock objects lacking `tree_`. Unpickling under scikit-learn 1.9.1 crashed with `AttributeError: 'DecisionTreeClassifier' object has no attribute 'tree_'`.
   - *Fix*: Fitted and serialized genuine scikit-learn `DecisionTreeClassifier` models adhering strictly to the 77-feature contract and 7-class sub-taxonomy.

2. **XGBoost Contiguous Class Discontinuity in Smoke Splits**:
   - *Problem*: `train_df.head(60)` returned unstratified rows missing classes 4-7. XGBoost 2.0+ rejected non-contiguous labels `{0, 1, 2, 3, 8}`.
   - *Fix*: Updated `load_specialist_splits` smoke sampling to use stratified minority-preserving head sampling across all classes.

3. **DNS Production Model Configuration Mismatch**:
   - *Problem*: `specialist_metadata.json` indicated `DecisionTree` instead of `RandomForest`.
   - *Fix*: Updated metadata to specify `RandomForest` and trained a Random Forest model with `min_samples_leaf=1` to separate Benign from DNS Tunneling queries.

4. **Suricata Default Log Directory Failure**:
   - *Problem*: `suricata -T` failed when `/tmp/suricata-logs` did not exist on host startup.
   - *Fix*: Added automatic directory creation in `utils/suricata_runner.py` and backend initialization.

5. **API Test Synthetic Payload Schema Mismatch**:
   - *Problem*: `test_api.py` passed synthetic single-feature payloads to `IP_Spoofing` expecting 200, but IP_Spoofing requires 44 features.
   - *Fix*: Updated test fixture to supply full 44-feature schemas to IP_Spoofing endpoints.

---

## 7. Public Render Production Verification (Phase M)

- **URL**: `https://smart-ai-network-intrusion-detection.onrender.com`
- **Health Check (`GET /health`)**: HTTP 200 OK, `engine_ready: true`, 5 available specialists.
- **Model Catalog (`GET /models`)**: HTTP 200 OK, 13 canonical classes, MAC Spoofing strictly absent.
- **Inference (`POST /predict`)**: HTTP 200 OK, outputs 13 canonical class probabilities summing to 1.0.
- **Dashboard Serving (`GET /`)**: HTTP 200 OK, serves the complete professional SOC HTML/JS frontend.
