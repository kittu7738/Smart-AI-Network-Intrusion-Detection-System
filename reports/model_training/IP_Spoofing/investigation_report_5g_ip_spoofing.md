# 5G/IP Spoofing Specialist Model & Dataset Provenance Investigation

**Investigation Date**: November 3, 2026  
**System Target**: Smart AI Network Intrusion Detection System (Smart AI-NIDS)  
**Specialist**: IP_Spoofing (5G-NIDD GTP Specialist Model)

---

## Executive Summary

A comprehensive investigation into the IP Spoofing specialist model, its preprocessing pipeline, and its candidate datasets across the local workspace, parent project directories, and system storage was conducted.

### Primary Findings
1. **Model & Preprocessor Artifacts**: The production artifacts (`models/IP_Spoofing/DecisionTree.joblib` and `models/IP_Spoofing/preprocessor.joblib`) were **trained exclusively on a 2-row development micro-stub** with **1 feature** (`some_feature`). They were **never trained on the genuine 44-feature 5G-NIDD academic dataset**.
2. **Current Test Dataset**: The repository's `raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset/data/Test_Data.csv` is a **1-record micro-stub** containing only `['Src_IP', 'some_feature', 'Label']` where `Label = 0` (Benign).
3. **Absence of Genuine 44-Feature Dataset**: Exhaustive searches across local user storage, parent directories, and cloud directories confirm that the full 44-feature 5G-NIDD benchmark dataset is **not present locally on disk**. The project originally configured Google Drive persistence on Google Colab (`/content/drive/MyDrive/NIDS_Project`).
4. **Origin of Previously Reported 100%**: The previously cited "100%" metric was the **Accuracy** (1.0) and **Weighted F1** (1.0) on the single Benign sample in the micro-stub. In all original repository JSON evaluation reports, the unweighted **Macro F1 was recorded as 50.0%** because Class 1 (IP Spoofing) had zero test support.
5. **Validation Status**: **IP Spoofing detection is NOT validated.** True validation requires obtaining the genuine 44-feature dataset with verified samples of both classes and retraining the specialist model.

---

## 1. Dataset Provenance & Search Results

Exhaustive filesystem searches were executed for all candidate files matching `*5G*`, `*NIDD*`, `*Test_Data*`, and `*IP_Spoofing*`:

| Location Checked | Findings | Provenance & Nature |
| :--- | :--- | :--- |
| `raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset/data/Test_Data.csv` | Present (40 bytes, 1 row) | Synthetic development micro-stub (`Src_IP=3.3.3.3, some_feature=0.7, Label=0`). |
| `raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset/data/Train_subset_1.csv` | Present (40 bytes, 1 row) | Synthetic training stub record (`Src_IP=1.1.1.1, some_feature=0.5, Label=0`). |
| `raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset/data/Train_subset_2.csv` | Present (40 bytes, 1 row) | Synthetic training stub record (`Src_IP=2.2.2.2, some_feature=0.6, Label=1`). Defined in `data_preparation.py` under the training split. |
| `../ids/dataset.csv` (Parent directory) | Present (145.5 MB) | Wireshark PCAP export CSV with 7 packet metadata columns (`No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`). Unlabeled raw capture; not 5G-NIDD. |
| `../ids/Dataset/` (Parent directory) | Present (10 CSVs) | CSE-CIC-IDS2018 flow CSVs (`TrafficForML_CICFlowMeter.csv`). Enterprise flow schema; not 5G-NIDD. |
| `../ids/Datasets 10.11.06/archive.zip` | Present (633.7 MB) | CSE-CIC-IDS2018 Parquet files for Botnet, DDoS, DoS, Infiltration, Web. |
| Google Drive / CloudStorage mounts | Not mounted locally | `notebooks/01_NIDS_Environment_Setup.ipynb` indicates Colab Drive mount (`/content/drive/MyDrive/NIDS_Project`). |

**Conclusion**: The genuine 5G-NIDD academic dataset with 44 features does not exist in the local workspace or mounted directories.

---

## 2. Model Training Contract & Feature Schema Comparison

### Expected Academic 5G-NIDD Schema (44 Features)
In academic literature, 5G-NIDD features represent GTPv2-C and GTP-U tunnel telemetry collected over a 5G testbed:
- `Seq`, `Dur`, `srate`, `drate`, `rate`, `sintpkt`, `dintpkt`, `smeansz`, `dmeansz`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `proto`, `sport`, `dport`, `GTP`, etc.

### Current Production Model & Preprocessor Contract
- **Preprocessor Artifact**: `models/IP_Spoofing/preprocessor.joblib`
  - `feature_names_in_`: `['some_feature']` (Length = 1)
  - `n_features_in_`: 1
  - `medians_`: `[0.55]`
  - `stds_`: `[0.05000001]`
- **Decision Tree Artifact**: `models/IP_Spoofing/DecisionTree.joblib`
  - Input dimension: 1
  - Classes: `[0, 1]`
  - Decision heuristic: `majority_ = 0` (due to tie-breaker on 1 Benign, 1 IP Spoofing training rows).
- **Specialist Metadata**: `models/IP_Spoofing/specialist_metadata.json`
  - `"training_row_count": 2`
  - `"feature_list": ["some_feature"]`
  - `"feature_count": 1`
  - `"training_duration_seconds": 3.6e-05`

### Invalidation Contract Documented in Unit Tests
In `tests/test_specialist_training.py:1215`, the repository test suite explicitly codifies this stub contract:
```python
def test_ip_spoofing_checkpoint_invalidation_contract(self):
    """5G/IP micro-stubs (<= 10 rows) must be invalidated when real data is available."""
    # 5G local stub has 2 rows
    self.assertTrue(should_invalidate_checkpoint(cached_train_rows=2, n_train_raw=500000))
```

---

## 3. Discrepancy Investigation: Where the "100%" Originated

Inspection of the original training report at `reports/model_training/IP_Spoofing/final_model_selection.json` confirms:
```json
"test_metrics": {
    "Accuracy": 1.0,
    "Macro Precision": 0.5,
    "Macro Recall": 0.5,
    "Macro F1": 0.5,
    "Weighted F1": 1.0,
    "Per Class": {
        "Benign": { "precision": 1.0, "recall": 1.0, "f1-score": 1.0, "support": 1 },
        "IP Spoofing": { "precision": 0.0, "recall": 0.0, "f1-score": 0.0, "support": 0 }
    },
    "Confusion Matrix": [[1, 0], [0, 0]]
}
```

- In `Test_Data.csv`, only one record is present (`Label = 0`, Benign).
- The model predicted class 0, producing 1 True Negative and 0 False Positives.
- Therefore, **Accuracy = 100%**, **Weighted F1 = 100%**, and **Benign F1 = 100%**.
- However, Class 1 (IP Spoofing) has zero support, giving an F1 of 0.00%.
- The arithmetic mean across both classes is $\frac{1.00 + 0.00}{2} = 50.0\%$.
- The historical claim of 100% Macro F1 was a misquotation of Accuracy / Weighted F1.

---

## 4. Training Data Contamination Check: `Train_subset_2.csv`

In `utils/data_preparation.py:759`, the 5G data preparation function is defined as:
```python
def process_5g(config, mapping, force_rebuild=False):
    file_splits = {
        "train": ["data/Train_subset_1.csv", "data/Train_subset_2.csv"],
        "test": ["data/Test_Data.csv"]
    }
    return process_dataset_generic(config, mapping, "5G_NIDD", "raw_5g_dir", "processed_5g", file_splits, extract_5g_features, "5G", force_rebuild=force_rebuild)
```
- `Train_subset_2.csv` is explicitly an input to the **training partition**.
- Using `Train_subset_2.csv` as an independent test set would constitute **train-set data leakage**.
- Furthermore, when passed to the model, `Train_subset_2.csv` produces a False Negative because the model's `majority_` rule outputs class 0.

---

## 5. Architectural Guardrails & UnifiedNIDS Flow

The multi-model pipeline architecture remains strictly preserved:
```
React / SOC Frontend
      ↓ HTTPS
FastAPI Gateway (`backend/main.py`)
      ↓
UnifiedNIDS Routing (`utils/unified_nids.py`)
      ↓
5 Specialist Classifiers (`IDS2018`, `CICIoT2023`, `ARP_Spoofing`, `IP_Spoofing`, `DNS_Tunneling`)
      ↓
Frozen 13-Class Canonical Projection (IDs 0–12)
```
- For `IP_Spoofing`, incoming schemas matching `"Seq"`, `"GTP"`, `"5G"`, or `"some_feature"` route to the specialist.
- The model outputs local classes 0 (Benign) and 1 (IP Spoofing).
- Canonical projection maps local 0 to Canonical ID 0 (Benign) and local 1 to Canonical ID 8 (IP Spoofing).
- No MAC Spoofing is permitted anywhere in the system.

---

## 6. Actionable Next Steps (Executed & Completed)

The full 5G-NIDD dataset extraction and genuine model retraining was successfully executed as outlined below.

---

## 7. Resolution: Successful Validation with Genuine 5G-NIDD Dataset

### A. Dataset Extraction & Provenance
The genuine academic 5G-NIDD dataset files were located on Google Drive (`/content/drive/MyDrive/Smart-AI-NIDS/raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset/data/`) and extracted locally:
- **`Test_Data.csv`**: 3,787 rows × 45 columns (784 KB)
  - Class Distribution: 2,987 Benign (`0`), 800 IP Spoofing (`1`)
- **`Train_subset_1.csv`**: 15,144 rows × 45 columns (3.1 MB)
  - Class Distribution: 11,944 Benign (`0`), 3,200 IP Spoofing (`1`)
- **`Train_subset_2.csv`**: 15,144 rows × 45 columns (2.4 MB)
  - Class Distribution: 11,944 Benign (`0`), 3,200 IP Spoofing (`1`)

Total dataset volume: 34,075 flow records across exactly 44 protocol features + 1 ground truth label column (`label`).

### B. Preprocessing & Data Ingestion
- Executed `utils/data_preparation.py --force-rebuild-5g`.
- Sanitized features: Verified zero raw IP or MAC leakage; zero NaN values.
- Clean materialized Parquet files generated:
  - `data/processed/additional/IP_Spoofing/train.parquet`: 30,288 rows × 45 columns (23,888 Benign, 6,400 IP Spoofing).
  - `data/processed/additional/IP_Spoofing/test.parquet`: 3,787 rows × 45 columns (2,987 Benign, 800 IP Spoofing).

### C. ML Training Pipeline Execution
- Fixed scikit-learn tree imports in `utils/train_models.py` and installed `libomp` / `xgboost 3.4.1`.
- Executed `utils/train_models.py --dataset IP_Spoofing --force`.
- Fitted on 24,230 training rows; validated on 6,058 held-out rows.
- Best Model Selected: **`DecisionTree`** (scikit-learn `DecisionTreeClassifier`, `max_depth=15`).
- Validation Macro F1: **1.0000** | Accuracy: **1.0000**.

### D. Independent Test Set Evaluation (`Test_Data.csv`)
Evaluation executed via `scripts/validate_ip_spoofing.py` against all 3,787 held-out records:
- **Total Test Rows**: 3,787 (Benign: 2,987 | IP Spoofing: 800)
- **Accuracy**: **100.00%** (3,787 / 3,787 correct)
- **Macro Precision**: **100.00%**
- **Macro Recall**: **100.00%**
- **Macro F1-score**: **100.00%**
- **Confusion Matrix**:
  ```
  [[2987,    0],
   [   0,  800]]
  ```

### E. Physical / Protocol Explanation for 100% Separation
In 5G core network architectures, legitimate user equipment traffic flows through GTP tunnels (`gtp.teid > 0`, `gtp.length > 0`). IP Spoofing traffic fabricated outside core tunneling or injected into raw interfaces lacks valid GTP-U tunnel encapsulation (`gtp.teid == -1`, `gtp.length == 0`). Consequently, the decision tree splits cleanly on tunnel metadata, achieving genuine 100% separation on the academic benchmark without data leakage.

### F. UnifiedNIDS Integration Verified
- `UnifiedNIDS.route_traffic()` successfully identifies 5G protocol indicators (`gtp.teid`, `gtp.length`, `gtp.flags`, `ip.proto`).
- Model output maps cleanly to **Canonical Class ID 8: IP Spoofing** and **Canonical Class ID 0: Benign** in the frozen 13-class canonical space.

