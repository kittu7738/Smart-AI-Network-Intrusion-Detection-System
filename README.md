# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

> A Machine Learning-based Network Intrusion Detection System that detects malicious network traffic using AI algorithms and provides real-time attack analysis through an interactive web dashboard.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-orange)
![Security](https://img.shields.io/badge/Cybersecurity-NIDS-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

# 📌 Overview

The **AI-Powered Network Intrusion Detection System (NIDS)** is a cybersecurity application that uses Machine Learning to identify malicious network traffic and classify different cyber attacks.

Unlike traditional signature-based Intrusion Detection Systems, this project leverages Artificial Intelligence to analyze network traffic patterns and accurately detect both known and unknown attacks.

The application provides a modern web dashboard for monitoring traffic, uploading datasets, analyzing attacks, and generating security reports.

---

# 🚀 Features

## 🔍 Network Traffic Analysis

- Upload CSV traffic datasets
- Analyze captured network traffic
- Detect malicious packets
- Display attack statistics

---

## 🤖 Machine Learning

- Random Forest Classifier
- XGBoost Classifier
- Decision Tree
- Model Performance Comparison
- Feature Importance Analysis

---

## 🛡️ Attack Detection

Detects multiple cyber attacks including:

- DDoS
- DoS
- Brute Force
- Botnet
- Heartbleed
- Web Attack
- Infiltration
- Benign Traffic

---

## 📊 Interactive Dashboard

- Total Traffic
- Total Attacks
- Normal Traffic
- Attack Distribution
- Risk Analysis
- Live Statistics
- Detection History

---

## 📁 Dataset Support

Supported Formats

- CSV
- PCAP (via CICFlowMeter)

Dataset Used

**CSE-CIC-IDS2018**

---

## 📈 Reports

Generate

- PDF Reports
- CSV Reports
- Attack History
- Detection Logs

---

## 💾 Database

Stores

- Detection History
- Attack Logs
- Prediction Results
- User Activity

---

# 🏗️ System Architecture

```
                Internet
                    │
                    ▼
           Wireshark Capture
                    │
             traffic.pcapng
                    │
                    ▼
            CICFlowMeter
                    │
              traffic.csv
                    │
                    ▼
          Data Preprocessing
                    │
                    ▼
          Machine Learning
      (Random Forest/XGBoost)
                    │
                    ▼
            Attack Prediction
                    │
                    ▼
             Flask Backend
                    │
                    ▼
          Interactive Dashboard
                    │
     ┌──────────────┼──────────────┐
     ▼              ▼              ▼
 Attack History   Reports     Live Charts
```

---

# 🛠️ Technology Stack

## Programming

- Python

## Machine Learning

- Scikit-learn
- XGBoost
- Pandas
- NumPy

## Backend

- Flask

## Frontend

- HTML
- CSS
- JavaScript
- Bootstrap
- Chart.js

## Database

- SQLite

## Network Analysis

- Wireshark
- CICFlowMeter

---

# 📂 Project Structure

```
AI-Network-Intrusion-Detection-System
│
├── app.py
├── requirements.txt
├── README.md
│
├── dataset/
├── uploads/
├── captures/
├── models/
├── preprocessing/
├── training/
├── notebooks/
├── templates/
├── static/
├── reports/
├── database/
└── utils/
```

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/AI-Network-Intrusion-Detection-System.git
```

---

## Create Virtual Environment

```bash
python -m venv venv
```

Activate

Windows

```bash
venv\Scripts\activate
```

Mac/Linux

```bash
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Run Application

```bash
python app.py
```

---

# 📊 Machine Learning Workflow

```
Dataset
   │
   ▼
Cleaning
   │
   ▼
Feature Engineering
   │
   ▼
Model Training
   │
   ▼
Evaluation
   │
   ▼
Prediction
   │
   ▼
Dashboard
```

---

# 📈 Evaluation Metrics

The project evaluates the models using:

- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix
- ROC Curve

---

# 🎯 Future Enhancements

- Real-time Packet Capture
- Live Intrusion Detection
- Email Alerts
- Explainable AI (SHAP)
- Docker Deployment
- Cloud Deployment
- Threat Intelligence Integration
- User Authentication
- Role-Based Access Control

---

# 📚 Dataset

Dataset Used

**CSE-CIC-IDS2018**

Includes

- DDoS
- DoS
- Brute Force
- Botnet
- Heartbleed
- Infiltration
- Web Attack
- Benign

---

# 🤝 Contributing

Contributions are welcome.

Fork the repository and submit a Pull Request.

---

# 📄 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

**CH. Anjan Prasad**

B.Tech Computer Science Engineering

Indian Institute of Information Technology Vadodara – International Campus Diu

Interested in

- Cybersecurity
- Artificial Intelligence
- Network Security
- Machine Learning

---

⭐ If you like this project, consider giving it a Star.