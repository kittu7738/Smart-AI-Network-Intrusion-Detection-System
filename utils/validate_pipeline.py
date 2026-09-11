import os
import json
import time
import pandas as pd
import numpy as np
import glob

from utils.data_preparation import resolve_path

def update_checkpoint(key, value):
    ckpt_path = resolve_path("checkpoints/progress.json")
    if os.path.exists(ckpt_path):
        with open(ckpt_path, "r") as f:
            cfg = json.load(f)
    else:
        cfg = {"checkpoints": {}}
    if "checkpoints" not in cfg:
        cfg["checkpoints"] = {}
    cfg["checkpoints"][key] = value
    with open(ckpt_path, "w") as f:
        json.dump(cfg, f, indent=4)

def check_cross_split_leakage(dataset_name, data_dir):
    print(f"Checking cross-split leakage for {dataset_name}...")
    try:
        train = pd.read_parquet(os.path.join(data_dir, "train.parquet"))
        val = pd.read_parquet(os.path.join(data_dir, "val.parquet"))
        test = pd.read_parquet(os.path.join(data_dir, "test.parquet"))
        
        # Verify final_label exists
        assert 'final_label' in train.columns, f"{dataset_name} train missing final_label"
        assert 'final_label' in val.columns, f"{dataset_name} val missing final_label"
        assert 'final_label' in test.columns, f"{dataset_name} test missing final_label"
        
        assert train['final_label'].isnull().sum() == 0, f"{dataset_name} train has NaN labels"
        assert val['final_label'].isnull().sum() == 0, f"{dataset_name} val has NaN labels"
        assert test['final_label'].isnull().sum() == 0, f"{dataset_name} test has NaN labels"

        # Verify preserve_index=False (no __index_level_0__)
        assert '__index_level_0__' not in train.columns, f"{dataset_name} train has __index_level_0__"
        assert '__index_level_0__' not in val.columns, f"{dataset_name} val has __index_level_0__"
        assert '__index_level_0__' not in test.columns, f"{dataset_name} test has __index_level_0__"
        
        # Normalize signed zero floats for reliable hashing
        for df in [train, val, test]:
            for c in df.select_dtypes(include=['float32', 'float64']).columns:
                df[c] = np.where(df[c] == 0.0, np.float32(0.0), df[c]).astype(np.float32)

        # Hash features only
        f_cols_train = [c for c in train.columns if c not in ['final_label', 'Label', 'label', 'hash']]
        f_cols_val = [c for c in val.columns if c not in ['final_label', 'Label', 'label', 'hash']]
        f_cols_test = [c for c in test.columns if c not in ['final_label', 'Label', 'label', 'hash']]
        
        train['hash'] = pd.util.hash_pandas_object(train[f_cols_train], index=False)
        val['hash'] = pd.util.hash_pandas_object(val[f_cols_val], index=False)
        test['hash'] = pd.util.hash_pandas_object(test[f_cols_test], index=False)
        
        def calculate_split_overlap(df1, df2):
            common = set(df1['hash']).intersection(set(df2['hash']))
            overlap_count = len(common)
            same_label = 0
            conflicting_label = 0
            if overlap_count > 0:
                df1_sub = df1[df1['hash'].isin(common)].drop_duplicates(subset=['hash', 'final_label'])
                df2_sub = df2[df2['hash'].isin(common)].drop_duplicates(subset=['hash', 'final_label'])
                m = pd.merge(df1_sub[['hash', 'final_label']], df2_sub[['hash', 'final_label']], on='hash', suffixes=('_1', '_2'))
                same_label = int((m['final_label_1'] == m['final_label_2']).sum())
                conflicting_label = int((m['final_label_1'] != m['final_label_2']).sum())
            return overlap_count, same_label, conflicting_label

        tv_overlap, tv_same, tv_conflict = calculate_split_overlap(train, val)
        tt_overlap, tt_same, tt_conflict = calculate_split_overlap(train, test)
        vt_overlap, vt_same, vt_conflict = calculate_split_overlap(val, test)

        # Cryptographic SHA-256 collision verification
        import hashlib
        def sha256_hashes(df, cols):
            arr = np.ascontiguousarray(df[cols].to_numpy(dtype=np.float32, copy=False))
            return {hashlib.sha256(row.tobytes()).digest() for row in arr}

        sha_train = sha256_hashes(train, f_cols_train)
        sha_val = sha256_hashes(val, f_cols_val)
        sha_test = sha256_hashes(test, f_cols_test)

        sha_tv_overlap = len(sha_train.intersection(sha_val))
        sha_tt_overlap = len(sha_train.intersection(sha_test))
        sha_vt_overlap = len(sha_val.intersection(sha_test))
        
        return {
            "dataset": dataset_name,
            "train_val_duplicate_rows": tv_overlap,
            "train_test_duplicate_rows": tt_overlap,
            "val_test_duplicate_rows": vt_overlap,
            "train_val_conflicting_rows": tv_conflict,
            "train_test_conflicting_rows": tt_conflict,
            "val_test_conflicting_rows": vt_conflict,
            "train_val_same_label_rows": tv_same,
            "train_test_same_label_rows": tt_same,
            "val_test_same_label_rows": vt_same,
            "sha256_train_val_overlap": sha_tv_overlap,
            "sha256_train_test_overlap": sha_tt_overlap,
            "sha256_val_test_overlap": sha_vt_overlap,
            "total_conflicting_overlaps": tv_conflict + tt_conflict + vt_conflict,
            "parquet_reopen_status": "Success",
            "final_label_exists": True,
            "feature_count_train": len(f_cols_train),
            "feature_count_val": len(f_cols_val),
            "feature_count_test": len(f_cols_test)
        }
    except Exception as e:
        return {"dataset": dataset_name, "error": str(e), "parquet_reopen_status": "Failed", "final_label_exists": False}

def main():
    ids2018_dir = resolve_path("data/processed/IDS2018")
    ciciot2023_dir = resolve_path("data/processed/CICIoT2023")
    
    ids_leak = check_cross_split_leakage("IDS2018", ids2018_dir)
    ciciot_leak = check_cross_split_leakage("CICIoT2023", ciciot2023_dir)
    
    leakage_report = {
        "timestamp": time.time(),
        "IDS2018": ids_leak,
        "CICIoT2023": ciciot_leak,
        "validation_status": "Passed" if (
            ids_leak.get("train_test_duplicate_rows", -1) == 0 and 
            ids_leak.get("train_val_duplicate_rows", -1) == 0 and 
            ids_leak.get("val_test_duplicate_rows", -1) == 0 and 
            ciciot_leak.get("train_test_duplicate_rows", -1) == 0 and 
            ids_leak.get("final_label_exists", False) and 
            ciciot_leak.get("final_label_exists", False)
        ) else "Failed"
    }
    
    reports_dir = resolve_path("reports")
    os.makedirs(reports_dir, exist_ok=True)
    with open(resolve_path("reports/leakage_report.json"), "w") as f:
        json.dump(leakage_report, f, indent=4)
        
    update_checkpoint("leakage_check_completed", True)
    update_checkpoint("data_preparation_completed", True)
    print("Validation & Leakage Check Complete. Reports saved.")

if __name__ == "__main__":
    main()
