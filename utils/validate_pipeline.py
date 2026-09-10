import os
import json
import time
import pandas as pd
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
        
        # Hash features only
        f_cols_train = [c for c in train.columns if c not in ['final_label', 'Label', 'label']]
        f_cols_val = [c for c in val.columns if c not in ['final_label', 'Label', 'label']]
        f_cols_test = [c for c in test.columns if c not in ['final_label', 'Label', 'label']]
        
        train_hashes = pd.util.hash_pandas_object(train[f_cols_train], index=False)
        val_hashes = pd.util.hash_pandas_object(val[f_cols_val], index=False)
        test_hashes = pd.util.hash_pandas_object(test[f_cols_test], index=False)
        
        train_val_overlap = len(set(train_hashes).intersection(set(val_hashes)))
        train_test_overlap = len(set(train_hashes).intersection(set(test_hashes)))
        val_test_overlap = len(set(val_hashes).intersection(set(test_hashes)))
        
        return {
            "dataset": dataset_name,
            "train_val_duplicate_rows": train_val_overlap,
            "train_test_duplicate_rows": train_test_overlap,
            "val_test_duplicate_rows": val_test_overlap,
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
