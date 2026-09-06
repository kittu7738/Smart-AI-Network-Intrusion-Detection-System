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

To ensure maximum accuracy without sacrificing critical feature semantics, this project utilizes a **multi-model architecture**:
1. **Enterprise NIDS Model:** Trained on the **CSE-CIC-IDS2018** dataset, utilizing 77 directional and timing-based flow features (via CICFlowMeter) to catch complex attacks like Infiltration and Slowloris.
2. **IoT NIDS Model:** Trained on the **CICIoT2023** dataset, utilizing 46 abstracted network metrics to catch rapid, high-volume IoT-centric attacks like Mirai, ARP Spoofing, and DNS Spoofing.

The backend dynamically routes traffic to the appropriate model and unifies their outputs into a single **10-class taxonomy**.

---

# 🚀 Features

## 🔍 Network Traffic Analysis
- Upload CSV traffic datasets
- Analyze captured network traffic
- Multi-model intelligent routing
- Display unified attack statistics

## 🤖 Machine Learning Models
- Random Forest / XGBoost Classifiers
- **Dual Architecture:** Standard Network Model (7 classes) & IoT Network Model (10 classes)
- Feature Importance Analysis

## 🛡️ Unified Attack Detection (10-Class Taxonomy)
Smart AI NIDS uses a 10-class intrusion/traffic classification taxonomy.
- Benign
- DDoS
- DoS
- Botnet (including Mirai)
- Infiltration
- Brute Force
- Web Attack
- Spoofing
- Recon / Port Scan
- MITM

---

# 📁 Datasets Used

1. **CSE-CIC-IDS2018** (Enterprise Traffic)
2. **CICIoT2023** (IoT Traffic)

*(Note: Data cleaning pipelines heavily process these into `data/processed/` using specialized schema alignments available in `config/`.)*

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
                    (10 Unified Classes)
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