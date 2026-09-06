# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

> A Multi-Model Machine Learning-based Network Intrusion Detection System that detects malicious network traffic using AI algorithms, specializing in both enterprise and IoT networks, and providing real-time attack analysis through an interactive web dashboard.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-orange)
![Security](https://img.shields.io/badge/Cybersecurity-NIDS-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

# 📌 Overview

The **AI-Powered Network Intrusion Detection System (NIDS)** is a cybersecurity application that leverages advanced Machine Learning to identify malicious network traffic and classify complex cyber attacks. 

To ensure maximum accuracy without sacrificing critical feature semantics or forcing incompatible data into a single schema, this project utilizes a strict **source-specific multi-model architecture**:
1. **Enterprise Flow Model:** Trained on the **CSE-CIC-IDS2018** dataset, utilizing 77 directional and timing-based flow features to catch complex attacks like Infiltration and Slowloris.
2. **IoT NIDS Model:** Trained on the **CICIoT2023** dataset, utilizing 46 abstracted network metrics to catch rapid, high-volume IoT-centric attacks.
3. **ARP/Packet Model:** Trained on an ARP/SYN/PING dataset using defensible packet-level features (e.g., tcp_flags, frame metrics).
4. **5G IP Spoofing Model:** Trained on the 5G-NIDD dataset targeting IP Spoofing scenarios using generic 5G/GTP packet metrics (raw IPs are excluded).
5. **DNS Statistical Model:** Trained on a DNS Tunneling dataset, evaluating statistical features derived from raw DNS queries (e.g., entropy, subdomain counts, length) without relying on verbatim query strings.

The backend dynamically routes traffic to the appropriate model and unifies their outputs into a single **frozen 13-class taxonomy**.

---

# 🚀 Features

## 🔍 Network Traffic Analysis
- Upload CSV traffic datasets
- Analyze captured network traffic
- Multi-model intelligent routing
- Display unified attack statistics

## 🤖 Machine Learning Models
- Random Forest / XGBoost Classifiers
- **Dual Architecture:** Standard Network Model (7 classes) & IoT Network Model (13 classes)
- Feature Importance Analysis

## 🛡️ Unified Attack Detection (13-Class Taxonomy)
Smart AI NIDS uses a 13-class intrusion/traffic classification taxonomy.
- Benign
- DDoS
- DoS
- Botnet
- Infiltration
- Brute Force
- Web Attack
- DNS Spoofing
- IP Spoofing
- ARP Spoofing
- Recon / Port Scan
- MITM
- DNS Tunneling

---

# 📁 Datasets Used

1. **CSE-CIC-IDS2018** (Enterprise Traffic) -> `processed/IDS2018/`
2. **CICIoT2023** (IoT Traffic) -> `processed/CICIoT2023/`
3. **ARP/SYN/PING Dataset** (Packet data for ARP/DoS) -> `processed/additional/ARP_Spoofing/`
4. **5G-Intrusion-Detection-Dataset** (Used specifically for IP Spoofing) -> `processed/additional/IP_Spoofing/`
5. **DNS Tunneling Dataset** (Raw queries translated to statistical metrics) -> `processed/additional/DNS_Tunneling/`

*(Note: Data cleaning pipelines extract source-specific features safely without injecting target leakage. MAC Spoofing is deliberately excluded from the taxonomy. Raw IP/MAC addresses are stripped. The 5G dataset provides a binary Normal/Attack label, but it is explicitly mapped to IP Spoofing based on its documented Distributed IP Spoofing scenario.)*

---

# 🏗️ System Architecture

```text
                  Internet Traffic (PCAP/CSV)
                              │
                    Backend Routing Layer
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
    Enterprise NIDS Model                 IoT NIDS Model
    (CSE-CIC-IDS2018 based)             (CICIoT2023 based)
            │                                   │
            └─────────────────┬─────────────────┘
                              ▼
                Taxonomy Normalization Layer
                    (13 Unified Classes)
                              │
                              ▼
                     Flask Web Server
                              │
                              ▼
                    Interactive Dashboard
```

---

# 📂 Project Structure

```text
AI-Network-Intrusion-Detection-System
│
├── config/                  # Label and feature mappings
├── data/
│   ├── processed/           # Cleaned train/val/test splits (ignored in git)
│   └── samples/             # 100-row sample CSVs for testing
├── dataset/                 # Raw datasets (ignored in git)
├── notebooks/               # Colab/Jupyter environment setup scripts
├── reports/                 # Pipeline JSON reports (inspection, alignment, splits)
├── uploads/                 # User-uploaded traffic files
├── captures/                # Network captures
├── models/                  # Trained serialized ML models
├── preprocessing/           # Data cleaning modules
├── training/                # Model training scripts
├── templates/               # Flask HTML templates
├── static/                  # CSS/JS and assets
├── database/                # SQLite DB files
├── utils/                   # Python utility scripts
├── app.py                   # Main Flask application
├── requirements.txt         # Project dependencies
├── env_config.json          # Pipeline state checkpointing
└── README.md
```

---

# ⚙️ Installation

## 1. Clone Repository

```bash
git clone https://github.com/kittu7738/Smart-AI-Network-Intrusion-Detection-System.git
cd Smart-AI-Network-Intrusion-Detection-System
```

## 2. Create Virtual Environment

```bash
python -m venv venv
```

**Activate:**
- Windows: `venv\Scripts\activate`
- Mac/Linux: `source venv/bin/activate`

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 4. Prepare Data & Train Models
*(Scripts for data prep and training must be executed before starting the server. Data processing reports are available in `reports/`.)*

## 5. Run Application

```bash
python app.py
```

---

# 👨‍💻 Author

**CH. Anjan Prasad**
B.Tech Computer Science Engineering
Indian Institute of Information Technology Vadodara – International Campus Diu

Note: MAC Spoofing is not part of the current taxonomy.
