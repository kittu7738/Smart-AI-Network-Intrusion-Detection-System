# Experimental Methodology: Suricata vs Smart AI-NIDS Comparative Evaluation

## 1. Objective and Theoretical Framework
The goal of this experiment is to execute a scientifically defensible comparative evaluation between:
1. **Traditional NIDS (T-NIDS)**: Suricata This is Suricata version 8.0.8 RELEASE operating on deterministic signature matching, threshold flow tracking, and application protocol decoders.
2. **Proposed Smart AI-NIDS**: Multi-specialist machine learning architecture (13 canonical classes, 5 specialist ML models) coordinated through the UnifiedNIDS hierarchical routing engine.

## 2. Experimental Architecture
The evaluation is divided into two rigorously isolated phases:

### Experiment Part A: Stream-Level Empirical Evaluation (Identical PCAP Stream)
- **Input Source**: `sample_traffic/benchmark.pcapng` (3,765,252 bytes, 3,659 packets).
- **Evaluation Unit**: Reconstructed Bidirectional Flow (Canonical 5-tuple: `(src_ip, dest_ip, src_port, dest_port, protocol)`).
- **Suricata Path**: Raw packet stream parsed by Suricata offline engine (`suricata -r`) utilizing `suricata.yaml` and `canonical_threats.rules` (32 active threat rules). EVE JSON events (`alert`, `flow`, `dns`) captured and mapped via `SuricataEveParser` and `SuricataMapper`.
- **Smart AI-NIDS Path**: Raw packet stream parsed by `PcapFlowExtractor` using streaming `scapy.all.PcapReader`. Flows aggregated into 46-feature telemetry records, supplemented by high-entropy DNS query analysis, then classified by `UnifiedNIDS`.
- **Correlation Method**: Suricata alert timestamps and 5-tuples are correlated directly against reconstructed bidirectional AI-NIDS flows.

### Experiment Part B: Stratified 13-Class Ground-Truth Benchmark
- **Input Source**: Stratified held-out test records assembled from verified benchmark datasets:
  - Classes 0-7, 10-11: `data/processed/CICIoT2023/test.parquet`
  - Class 8: `data/processed/additional/IP_Spoofing/test.parquet`
  - Class 9: `data/processed/additional/ARP_Spoofing/` (Layer-2 ARP frames)
  - Class 12: `data/processed/additional/DNS_Tunneling/` (Statistical exfiltration queries)
- **Ground Truth Integrity**: Labels are completely withheld from the inference engines during prediction.
- **Evaluation Metrics**:
  - Accuracy: $\frac{\sum TP + \sum TN}{Total}$
  - Macro Precision, Recall, F1: Unweighted mean across all 13 canonical classes.
  - Weighted F1: Weighted by class support to reflect real-world distributions.
  - Per-class True Positives (TP), False Positives (FP), False Negatives (FN), False Positive Rate (FPR), False Negative Rate (FNR).
  - Processing Latency: Mean, median, and 99th-percentile inference time per flow.

## 3. Threat Taxonomy Mapping Transparency
Both systems are strictly mapped into the frozen 13-class canonical taxonomy:
- **Class 0**: Benign
- **Class 1**: DDoS
- **Class 2**: DoS
- **Class 3**: Botnet
- **Class 4**: Infiltration
- **Class 5**: Brute Force
- **Class 6**: Web Attack
- **Class 7**: DNS Spoofing
- **Class 8**: IP Spoofing
- **Class 9**: ARP Spoofing (*Documented Structural Limitation in Suricata*)
- **Class 10**: Recon / Port Scan
- **Class 11**: MITM
- **Class 12**: DNS Tunneling

## 4. Hardware and Runtime Environment
- **Host System**: macOS Darwin arm64 (Apple Silicon) & Linux container.
- **Suricata Engine**: `/opt/homebrew/bin/suricata`.
- **Python Environment**: Python 3.13 / 3.11 with scikit-learn, xgboost, pandas, scapy.
