import os
import json
import time
import pandas as pd
import glob

BASE_DIR = os.environ.get("NIDS_PROJECT_ROOT", os.getcwd())

def update_checkpoint(key, value):
    ckpt_path = os.path.join(BASE_DIR, "checkpoints", "progress.json")
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
        
        # We hash the rows to avoid massive memory merge overhead
        train_hashes = pd.util.hash_pandas_object(train, index=False)
        val_hashes = pd.util.hash_pandas_object(val, index=False)
        test_hashes = pd.util.hash_pandas_object(test, index=False)
        
        train_val_overlap = len(set(train_hashes).intersection(set(val_hashes)))
        train_test_overlap = len(set(train_hashes).intersection(set(test_hashes)))
        val_test_overlap = len(set(val_hashes).intersection(set(test_hashes)))
        
        return {
            "dataset": dataset_name,
            "train_val_duplicate_rows": train_val_overlap,
            "train_test_duplicate_rows": train_test_overlap,
            "val_test_duplicate_rows": val_test_overlap,
            "parquet_reopen_status": "Success",
            "feature_count_train": len(train.columns),
            "feature_count_val": len(val.columns),
            "feature_count_test": len(test.columns)
        }
    except Exception as e:
        return {"dataset": dataset_name, "error": str(e), "parquet_reopen_status": "Failed"}

def main():
    ids2018_dir = os.path.join(BASE_DIR, "data", "processed", "IDS2018")
    ciciot2023_dir = os.path.join(BASE_DIR, "data", "processed", "CICIoT2023")
    
    ids_leak = check_cross_split_leakage("IDS2018", ids2018_dir)
    ciciot_leak = check_cross_split_leakage("CICIoT2023", ciciot2023_dir)
    
    leakage_report = {
        "timestamp": time.time(),
        "IDS2018": ids_leak,
        "CICIoT2023": ciciot_leak,
        "action_required": "None" if (ids_leak.get("train_test_duplicate_rows", 0) == 0 and ciciot_leak.get("train_test_duplicate_rows", 0) == 0) else "Investigate cross-split leakage."
    }
    
    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    with open(os.path.join(BASE_DIR, "reports", "leakage_report.json"), "w") as f:
        json.dump(leakage_report, f, indent=4)
        
    update_checkpoint("leakage_check_completed", True)
    update_checkpoint("data_preparation_completed", True)
    print("Validation & Leakage Check Complete. Reports saved.")

if __name__ == "__main__":
    main()
