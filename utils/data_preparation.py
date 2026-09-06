import os
import json
import time
import pandas as pd
import numpy as np
import pyarrow.parquet as pq
import gc
import pyarrow as pa
from collections import defaultdict

def resolve_path(rel_path):
    """Resolve paths dynamically based on NIDS_DATA_ROOT, NIDS_PROJECT_ROOT, or CWD."""
    data_root = os.environ.get("NIDS_DATA_ROOT")
    if data_root:
        # Map local config paths to Colab Drive structure
        if rel_path == "Datasets/ids2018_combined_7attacks_benign.parquet":
            return os.path.join(data_root, "raw", "IDS2018", "ids2018_combined_7attacks_benign.parquet")
        if rel_path == "Datasets/CICIOT23":
            return os.path.join(data_root, "raw", "CICIoT2023")
        if rel_path.startswith("data/processed"):
            return os.path.join(data_root, rel_path.replace("data/", "", 1))
        if rel_path.startswith("data/samples"):
            return os.path.join(data_root, rel_path.replace("data/", "", 1))
        
        return os.path.join(data_root, rel_path)
        
    base_dir = os.environ.get("NIDS_PROJECT_ROOT", os.getcwd())
    return os.path.join(base_dir, rel_path)

def load_config():
    with open(resolve_path("config/preprocessing_config.json"), "r") as f:
        return json.load(f)

def load_label_mapping():
    with open(resolve_path("config/label_mapping.json"), "r") as f:
        return json.load(f)

def update_env_checkpoint(key, value):
    env_path = resolve_path("checkpoints/progress.json")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            cfg = json.load(f)
    else:
        cfg = {"checkpoints": {}}
    cfg["checkpoints"][key] = value
    
    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    with open(env_path, "w") as f:
        json.dump(cfg, f, indent=4)

def check_existing_files(processed_dir, required_files):
    dir_path = resolve_path(processed_dir)
    if not os.path.exists(dir_path):
        return False
    for req in required_files:
        if not os.path.exists(os.path.join(dir_path, req)):
            return False
    return True

def handle_invalid_numeric(df):
    """Replace Inf with NaN, then drop NaNs to avoid synthesizing artificial values."""
    df = df.replace([np.inf, -np.inf], np.nan)
    initial_rows = len(df)
    df = df.dropna()
    dropped = initial_rows - len(df)
    return df, dropped

def check_leakage(df, target_col):
    suspicious = []
    constant = []
    for c in df.columns:
        if c == target_col:
            continue
        c_lower = c.lower()
        if "ip" in c_lower or "timestamp" in c_lower or "time" in c_lower or "id" in c_lower or "port" in c_lower:
            suspicious.append(c)
        if df[c].nunique() <= 1:
            constant.append(c)
    return suspicious, constant

def split_stratified(df, label_col, seed):
    """Perform a manual 70/15/15 stratified split natively in Pandas to avoid external ML dependencies."""
    train_dfs, val_dfs, test_dfs = [], [], []
    for label in df[label_col].unique():
        class_df = df[df[label_col] == label]
        if len(class_df) < 3:
            train_dfs.append(class_df)
            continue
        train_class = class_df.sample(frac=0.7, random_state=seed)
        rem = class_df.drop(train_class.index)
        val_class = rem.sample(frac=0.5, random_state=seed)
        test_class = rem.drop(val_class.index)
        train_dfs.extend([train_class])
        val_dfs.extend([val_class])
        test_dfs.extend([test_class])
        
    X_train = pd.concat(train_dfs).sample(frac=1, random_state=seed)
    X_val = pd.concat(val_dfs).sample(frac=1, random_state=seed)
    X_test = pd.concat(test_dfs).sample(frac=1, random_state=seed)
    return X_train, X_val, X_test

def downcast_dtypes(df):
    """Downcast float64 to float32 to save RAM."""
    float_cols = df.select_dtypes(include=['float64']).columns
    df[float_cols] = df[float_cols].astype('float32')
    return df

def process_ids2018(config, mapping):
    processed_dir = config["paths"]["processed_ids2018"]
    if check_existing_files(processed_dir, ["train.parquet", "val.parquet", "test.parquet"]):
        print("IDS2018 already processed. Skipping.")
        with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ids2018_preparation_report.json")), "r") as f:
            return json.load(f)
            
    print("Processing IDS2018 memory-safely (Option C)...")
    raw_path = resolve_path(config["paths"]["raw_ids2018"])
    
    if not os.path.exists(raw_path):
        print(f"Missing {raw_path}")
        return None
        
    ids_map = mapping["IDS2018"]
    valid_classes = config["classes"]["ids2018"]
    
    # 1. We will load in batches, map labels, drop invalid, and hash
    # To keep memory extremely low, we store only the hashes and their labels
    try:
        parquet_file = pq.ParquetFile(raw_path)
    except Exception as e:
        print(f"Could not open IDS2018 parquet: {e}")
        return None
        
    hash_to_labels = defaultdict(set)
    initial_rows = 0
    mapped_rows = 0
    dropped_invalid_numeric = 0
    
    print("  Pass 1: Identifying conflicting hashes...")
    for batch in parquet_file.iter_batches(batch_size=500000):
        df = batch.to_pandas()
        initial_rows += len(df)
        
        df["final_label"] = df["Label"].map(ids_map)
        df = df[df["final_label"].isin(valid_classes)]
        mapped_rows += len(df)
        
        df, dropped = handle_invalid_numeric(df)
        dropped_invalid_numeric += dropped
        
        feat_cols = [c for c in df.columns if c not in ["Label", "label", "final_label"]]
        df['hash'] = pd.util.hash_pandas_object(df[feat_cols], index=False)
        
        # Track which labels each hash is associated with
        for h, l in zip(df['hash'], df['final_label']):
            hash_to_labels[h].add(l)
            
        del df
        gc.collect()
        
    # Identify conflicting hashes
    conflicting_hashes = {h for h, labels in hash_to_labels.items() if len(labels) > 1}
    conflicting_groups = len(conflicting_hashes)
    del hash_to_labels
    gc.collect()
    
    # Pass 2: Extract valid rows, downcast, drop exact duplicates, and split
    print("  Pass 2: Extracting clean data and splitting...")
    clean_dfs = []
    seen_hashes = set()
    conflicting_rows_removed = 0
    
    for batch in parquet_file.iter_batches(batch_size=500000):
        df = batch.to_pandas()
        df["final_label"] = df["Label"].map(ids_map)
        df = df[df["final_label"].isin(valid_classes)]
        df, _ = handle_invalid_numeric(df)
        
        feat_cols = [c for c in df.columns if c not in ["Label", "label", "final_label"]]
        df['hash'] = pd.util.hash_pandas_object(df[feat_cols], index=False)
        
        # Option C: Drop all rows with conflicting hashes
        is_conflict = df['hash'].isin(conflicting_hashes)
        conflicting_rows_removed += is_conflict.sum()
        df = df[~is_conflict]
        
        # Deduplicate globally
        is_dup = df['hash'].isin(seen_hashes)
        df = df[~is_dup]
        seen_hashes.update(df['hash'])
        
        df = df.drop(columns=["hash", "Label"])
        df = downcast_dtypes(df)
        clean_dfs.append(df)
        
    df_clean = pd.concat(clean_dfs) if clean_dfs else pd.DataFrame()
    del clean_dfs, seen_hashes, conflicting_hashes
    gc.collect()
    
    clean_rows = len(df_clean)
    features_before = len(df_clean.columns) - 1
    
    suspicious, constant = check_leakage(df_clean, "final_label")
    X_train, X_val, X_test = split_stratified(df_clean, "final_label", config["parameters"]["random_seed"])
    
    os.makedirs(resolve_path(processed_dir), exist_ok=True)
    # Write to tmp first
    tmp_train = resolve_path(os.path.join(processed_dir, "train.tmp.parquet"))
    tmp_val = resolve_path(os.path.join(processed_dir, "val.tmp.parquet"))
    tmp_test = resolve_path(os.path.join(processed_dir, "test.tmp.parquet"))
    
    X_train.to_parquet(tmp_train)
    X_val.to_parquet(tmp_val)
    X_test.to_parquet(tmp_test)
    
    os.rename(tmp_train, resolve_path(os.path.join(processed_dir, "train.parquet")))
    os.rename(tmp_val, resolve_path(os.path.join(processed_dir, "val.parquet")))
    os.rename(tmp_test, resolve_path(os.path.join(processed_dir, "test.parquet")))
    
    report = {
        "pipeline_version": config["version"],
        "timestamp": time.time(),
        "random_seed": config["parameters"]["random_seed"],
        "source_path": raw_path,
        "output_path": resolve_path(processed_dir),
        "initial_rows": initial_rows,
        "mapped_rows": mapped_rows,
        "clean_rows": clean_rows,
        "dropped_invalid_numeric": dropped_invalid_numeric,
        "conflicting_groups_found": conflicting_groups,
        "conflicting_rows_removed": int(conflicting_rows_removed),
        "final_row_count": len(df_clean),
        "feature_count": features_before,
        "classes": list(df_clean["final_label"].unique()),
        "class_counts": df_clean["final_label"].value_counts().to_dict(),
        "train_count": len(X_train),
        "val_count": len(X_val),
        "test_count": len(X_test),
        "leakage_checks": {
            "suspicious_identifiers": suspicious,
            "constant_columns": constant
        },
        "heartbleed_status": "unavailable / requires legitimate additional data",
        "heartbleed_count": 0,
        "strategy": "Option C: Conflicting feature groups removed completely (Memory Safe)."
    }
    
    os.makedirs(resolve_path(config["paths"]["reports_dir"]), exist_ok=True)
    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ids2018_preparation_report.json")), "w") as f:
        json.dump(report, f, indent=4)
        
    return report

def process_ciciot2023(config, mapping):
    processed_dir = config["paths"]["processed_ciciot2023"]
    if check_existing_files(processed_dir, ["train.parquet", "val.parquet", "test.parquet"]):
        print("CICIoT2023 already processed. Skipping.")
        with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ciciot2023_preparation_report.json")), "r") as f:
            return json.load(f)
            
    print("Processing CICIoT2023 memory-safely (Option B)...")
    raw_dir = resolve_path(config["paths"]["raw_ciciot2023_dir"])
    iot_map = mapping["CICIoT2023"]
    valid_classes = config["classes"]["ciciot2023"]
    os.makedirs(resolve_path(processed_dir), exist_ok=True)
    
    report = {
        "pipeline_version": config["version"],
        "timestamp": time.time(),
        "source_path": raw_dir,
        "output_path": resolve_path(processed_dir),
        "initial_rows": 0,
        "clean_rows": 0,
        "final_row_count": 0,
        "class_counts": {},
        "splits": {},
        "train_val_overlaps_removed": 0,
        "train_test_overlaps_removed": 0,
        "val_test_overlap_remaining": 0,
        "dropped_invalid_numeric": 0,
        "leakage_checks": {"suspicious_identifiers": [], "constant_columns": []},
        "heartbleed_status": "unavailable / requires legitimate additional data",
        "heartbleed_count": 0,
        "strategy": "Option B: Train boundary strict overlap removal (Memory Safe)."
    }
    
    def process_file_chunked(file_name, split_name, known_hashes=None, is_train=False):
        file_path = os.path.join(raw_dir, file_name)
        if not os.path.exists(file_path):
            print(f"Missing {file_path}")
            return None, set(), 0
            
        chunk_dfs = []
        split_hashes = set()
        overlaps_removed = 0
        seen_in_split = set()
        
        for chunk in pd.read_csv(file_path, chunksize=500000, low_memory=False):
            report["initial_rows"] += len(chunk)
            chunk["final_label"] = chunk["label"].map(iot_map)
            chunk = chunk[chunk["final_label"].isin(valid_classes)]
            chunk, dropped = handle_invalid_numeric(chunk)
            report["dropped_invalid_numeric"] += dropped
            
            chunk = downcast_dtypes(chunk)
            
            feat_cols = [c for c in chunk.columns if c not in ["label", "final_label"]]
            chunk["hash"] = pd.util.hash_pandas_object(chunk[feat_cols], index=False)
            
            # Deduplicate internally
            chunk = chunk[~chunk["hash"].isin(seen_in_split)]
            seen_in_split.update(chunk["hash"])
            
            # Cross-split overlap removal
            if known_hashes is not None:
                overlap = chunk["hash"].isin(known_hashes)
                overlaps_removed += overlap.sum()
                chunk = chunk[~overlap]
                
            split_hashes.update(chunk["hash"])
            chunk_dfs.append(chunk)
            gc.collect()
            
        df = pd.concat(chunk_dfs) if chunk_dfs else pd.DataFrame()
        return df, split_hashes, overlaps_removed
    
    print("  Processing Train...")
    train_df, train_hashes, _ = process_file_chunked("train.csv", "train", is_train=True)
    if train_df is None: return None
    
    print("  Processing Validation...")
    val_df, val_hashes, val_removed = process_file_chunked("validation.csv", "val", known_hashes=train_hashes)
    report["train_val_overlaps_removed"] = int(val_removed)
    
    print("  Processing Test...")
    test_df, test_hashes, test_removed = process_file_chunked("test.csv", "test", known_hashes=train_hashes)
    report["train_test_overlaps_removed"] = int(test_removed)
    
    report["val_test_overlap_remaining"] = len(val_hashes.intersection(test_hashes))
    
    final_dfs = {"train": train_df, "val": val_df, "test": test_df}
    for split_name, df in final_dfs.items():
        df = df.drop(columns=["hash"])
        report["final_row_count"] += len(df)
        report["splits"][split_name] = len(df)
        
        for k, v in df["final_label"].value_counts().to_dict().items():
            report["class_counts"][k] = report["class_counts"].get(k, 0) + v
            
        if split_name == "train":
            suspicious, constant = check_leakage(df, "final_label")
            report["leakage_checks"]["suspicious_identifiers"] = suspicious
            report["leakage_checks"]["constant_columns"] = constant
            report["feature_count"] = len(df.columns) - 2 # excluding label & final_label
            
        tmp_out = resolve_path(os.path.join(processed_dir, f"{split_name}.tmp.parquet"))
        final_out = resolve_path(os.path.join(processed_dir, f"{split_name}.parquet"))
        df.drop(columns=["label"]).to_parquet(tmp_out)
        os.rename(tmp_out, final_out)
        
    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ciciot2023_preparation_report.json")), "w") as f:
        json.dump(report, f, indent=4)
        
    return report

def main():
    update_env_checkpoint("data_preparation_started", True)
    config = load_config()
    mapping = load_label_mapping()
    
    os.makedirs(resolve_path(config["paths"]["reports_dir"]), exist_ok=True)
    
    ids_report = process_ids2018(config, mapping)
    iot_report = process_ciciot2023(config, mapping)
    
    dist = {}
    if ids_report: dist["IDS2018"] = ids_report["class_counts"]
    if iot_report: dist["CICIoT2023"] = iot_report["class_counts"]
        
    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "class_distribution_report.json")), "w") as f:
        json.dump(dist, f, indent=4)
        
    update_env_checkpoint("ids2018_preparation_status", "Success" if ids_report else "Skipped")
    update_env_checkpoint("ciciot2023_preparation_status", "Success" if iot_report else "Skipped")
    update_env_checkpoint("data_preparation_completed", True)
    
    print("Pipelines safely executed.")

if __name__ == "__main__":
    main()
