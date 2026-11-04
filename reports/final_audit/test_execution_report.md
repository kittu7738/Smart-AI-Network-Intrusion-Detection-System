# Smart AI-NIDS: Comprehensive Test Execution Report

**Execution Timestamp**: November 4, 2026  
**Environment**: Darwin arm64 / Python 3.13.1 / Suricata 8.0.8 RELEASE  
**Test Framework**: Pytest 9.0.3, Unittest, FastAPI TestClient, Scapy  
**Overall Status**: **100% PASSED (0 FAILURES, 0 ERRORS)**  

---

## 1. Pytest Regression Test Suite Summary

Total Collected Tests: **116**  
Passed: **116**  
Failed: **0**  
Skipped: **0**  
Execution Time: **32.58 seconds**  

### Test Module Breakdown:
1. `tests/test_api.py` (14/14 Passed):
   - `test_01_health_endpoint_returns_200`: PASSED
   - `test_02_models_endpoint_returns_all_five_specialists`: PASSED
   - `test_03_predict_valid_synthetic_payload_succeeds`: PASSED
   - `test_04_prediction_response_contains_all_required_fields`: PASSED
   - `test_05_probabilities_length_is_exactly_13`: PASSED
   - `test_06_probabilities_sum_approximately_to_one`: PASSED
   - `test_07_automated_specialist_routing_works`: PASSED
   - `test_08_raw_dns_query_input_works`: PASSED
   - `test_09_missing_required_features_produces_clean_4xx`: PASSED
   - `test_10_invalid_json_produces_clean_4xx`: PASSED
   - `test_11_empty_features_dict_produces_clean_4xx`: PASSED
   - `test_12_mac_spoofing_payload_rejected_with_clean_4xx`: PASSED
   - `test_13_batch_prediction_succeeds`: PASSED
   - `test_14_empty_batch_rejected_clean_4xx`: PASSED

2. `tests/test_unified_nids.py` (10/10 Passed):
   - `test_specialist_loading_and_registration`: PASSED
   - `test_inference_path_all_five_specialists`: PASSED
   - `test_automatic_schema_routing`: PASSED
   - `test_invalid_and_ambiguous_schema_rejection`: PASSED
   - `test_mac_spoofing_strict_rejection`: PASSED
   - `test_batch_prediction_vectorization`: PASSED
   - `test_dns_production_model_identity_random_forest`: PASSED
   - `test_model_preprocessor_dimension_agreement`: PASSED
   - `test_raw_dns_query_automatic_feature_extraction`: PASSED
   - `test_missing_features_raises_value_error`: PASSED

3. `tests/test_specialist_training.py` (45/45 Passed):
   - All candidate preprocessor, threshold calibration, gatekeeper evaluation, and dataset splitting tests passed.

4. `tests/test_preparation.py` (23/23 Passed):
   - Label mapping, feature normalization, zero-leakage, and parquet split derivations passed.

5. `tests/test_optimization.py` (10/10 Passed):
   - Progressive optimizer Stage A screening and Stage B finalist validation passed.

6. `tests/test_taxonomy.py` (7/7 Passed):
   - Canonical IDs 0–12, MAC spoofing absence, and specialist sub-taxonomy consistency passed.

7. `tests/test_unified_taxonomy_and_routing.py` (7/7 Passed):
   - Schema fingerprinting and routing paths passed.

---

## 2. 13 Canonical Class End-to-End Verification (`scripts/test_all_13_classes.py`)

| Canonical ID | Class Name | Routed Specialist | Model Architecture | Predicted Class | Confidence | Status |
|:---:|---|---|---|---|:---:|:---:|
| 0 | Benign | CICIoT2023 | XGBoost | Benign | 0.7189 | **MATCH** |
| 1 | DDoS | CICIoT2023 | XGBoost | DDoS | 0.9691 | **MATCH** |
| 2 | DoS | CICIoT2023 | XGBoost | DoS | 0.9886 | **MATCH** |
| 3 | Botnet | CICIoT2023 | XGBoost | Botnet | 0.9894 | **MATCH** |
| 4 | Infiltration | CICIoT2023 | XGBoost | Infiltration | 0.9762 | **MATCH** |
| 5 | Brute Force | CICIoT2023 | XGBoost | Brute Force | 0.9689 | **MATCH** |
| 6 | Web Attack | CICIoT2023 | XGBoost | Web Attack | 0.9738 | **MATCH** |
| 7 | DNS Spoofing | CICIoT2023 | XGBoost | DNS Spoofing | 0.7836 | **MATCH** |
| 8 | IP Spoofing | IP_Spoofing | DecisionTree (5G) | IP Spoofing | 1.0000 | **MATCH** |
| 9 | ARP Spoofing | ARP_Spoofing | DecisionTree | ARP Spoofing | 1.0000 | **MATCH** |
| 10 | Recon / Port Scan | CICIoT2023 | XGBoost | Recon / Port Scan | 0.9645 | **MATCH** |
| 11 | MITM | CICIoT2023 | XGBoost | MITM | 0.9777 | **MATCH** |
| 12 | DNS Tunneling | DNS_Tunneling | RandomForest | DNS Tunneling | 0.9000 | **MATCH** |

**Summary**: 13/13 Canonical Classes Verified (100% Match Rate). Probability vectors verified (length 13, sum = 1.0000).

---

## 3. FastAPI HTTP E2E Verification (`scripts/test_fastapi_e2e.py`)

- `GET /health`: Verified (HTTP 200)
- `GET /models`: Verified (HTTP 200, 5 specialists, 13 classes)
- `POST /predict` (Single): 13/13 classes passed
- `POST /predict/batch` (Heterogeneous): 13/13 records passed
- Overall Status: **ALL PASSED (13/13)**

---

## 4. Suricata 8.0.8 Traditional Baseline Verification

- Binary: `/opt/homebrew/bin/suricata` (Version 8.0.8 RELEASE)
- Configuration Validation (`suricata -T -c suricata/suricata.yaml`): **PASSED (32 active rules loaded, 0 failed)**
- Offline PCAP Benchmark (`sample_traffic/benchmark.pcapng`):
  - Execution Status: **SUCCESS**
  - Processing Time: **0.0876s**
  - Packet Throughput: **41,769.4 pkts/s**
  - Alerts Triggered: **3 alerts** (EVE JSON parsed with 0 errors)
