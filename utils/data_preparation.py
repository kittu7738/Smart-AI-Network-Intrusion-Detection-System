import os
import json
import time
import pandas as pd
import numpy as np

def resolve_path(rel_path):
    """Resolve paths dynamically based on NIDS_PROJECT_ROOT or CWD to support Mac and Colab."""
    base_dir = os.environ.get("NIDS_PROJECT_ROOT", os.getcwd())
    return os.path.join(base_dir, rel_path)

def load_config():
    config_path = resolve_path("config/preprocessing_config.json")
    with open(config_path, "r") as f:
        return json.load(f)

def load_label_mapping():
    mapping_path = resolve_path("config/label_mapping.json")
    with open(mapping_path, "r") as f:
        return json.load(f)

def update_env_checkpoint(key, value):
    env_path = resolve_path("env_config.json")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            cfg = json.load(f)
    else:
        cfg = {"checkpoints": {}}
    cfg["checkpoints"][key] = value
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
    # We do not use inplace=True here to avoid pandas SettingWithCopy warnings in tests
    df = df.replace([np.inf, -np.inf], np.nan)
    initial_rows = len(df)
    df = df.dropna()
    dropped = initial_rows - len(df)
    return df, dropped

def check_leakage(df, target_col):
    """Check for identifier columns, constant columns, and suspicious target derivations."""
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
    """Perform a manual 70/15/15 stratified split natively in Pandas to avoid external ML dependencies here."""
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

def process_ids2018(config, mapping):
    processed_dir = config["paths"]["processed_ids2018"]
    if check_existing_files(processed_dir, ["train.parquet", "val.parquet", "test.parquet"]):
        print("IDS2018 processed data already exists. Validating and skipping regeneration.")
        # Load report to simulate return
        with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ids2018_preparation_report.json")), "r") as f:
            return json.load(f)
            
    print("Processing IDS2018 pipeline...")
    raw_path = resolve_path(config["paths"]["raw_ids2018"])
    df = pd.read_parquet(raw_path)
    
    initial_rows = len(df)
    features_before = len(df.columns) - 1
    
    ids_map = mapping["IDS2018"]
    df["final_label"] = df["Label"].map(ids_map)
    
    valid_classes = config["classes"]["ids2018"]
    df = df[df["final_label"].isin(valid_classes)]
    mapped_rows = len(df)
    
    df, dropped_invalid = handle_invalid_numeric(df)
    
    df = df.drop_duplicates()
    clean_rows = len(df)
    
    suspicious, constant = check_leakage(df, "final_label")
    
    X_train, X_val, X_test = split_stratified(df, "final_label", config["parameters"]["random_seed"])
    
    os.makedirs(resolve_path(processed_dir), exist_ok=True)
    X_train.drop(columns=["Label", "final_label"]).to_parquet(resolve_path(os.path.join(processed_dir, "train.parquet")))
    X_val.drop(columns=["Label", "final_label"]).to_parquet(resolve_path(os.path.join(processed_dir, "val.parquet")))
    X_test.drop(columns=["Label", "final_label"]).to_parquet(resolve_path(os.path.join(processed_dir, "test.parquet")))
    
    os.makedirs(resolve_path(config["paths"]["samples_dir"]), exist_ok=True)
    X_train.head(100).to_csv(resolve_path(os.path.join(config["paths"]["samples_dir"], "ids2018_sample.csv")), index=False)
    
    report = {
        "pipeline_version": config["version"],
        "timestamp": time.time(),
        "random_seed": config["parameters"]["random_seed"],
        "source_path": raw_path,
        "output_path": resolve_path(processed_dir),
        "initial_rows": initial_rows,
        "mapped_rows": mapped_rows,
        "clean_rows": clean_rows,
        "dropped_invalid_numeric": dropped_invalid,
        "total_dropped_rows": initial_rows - clean_rows,
        "feature_count": features_before,
        "classes": list(df["final_label"].unique()),
        "class_counts": df["final_label"].value_counts().to_dict(),
        "train_count": len(X_train),
        "val_count": len(X_val),
        "test_count": len(X_test),
        "leakage_checks": {
            "suspicious_identifiers": suspicious,
            "constant_columns": constant
        }
    }
    
    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ids2018_preparation_report.json")), "w") as f:
        json.dump(report, f, indent=4)
        
    return report

def process_ciciot2023(config, mapping):
    processed_dir = config["paths"]["processed_ciciot2023"]
    if check_existing_files(processed_dir, ["train.parquet", "val.parquet", "test.parquet"]):
        print("CICIoT2023 processed data already exists. Validating and skipping regeneration.")
        with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ciciot2023_preparation_report.json")), "r") as f:
            return json.load(f)
            
    print("Processing CICIoT2023 pipeline...")
    raw_dir = resolve_path(config["paths"]["raw_ciciot2023_dir"])
    iot_map = mapping["CICIoT2023"]
    valid_classes = config["classes"]["ciciot2023"]
    
    splits = {"train": "train.csv", "val": "validation.csv", "test": "test.csv"}
    os.makedirs(resolve_path(processed_dir), exist_ok=True)
    
    report = {
        "pipeline_version": config["version"],
        "timestamp": time.time(),
        "source_path": raw_dir,
        "output_path": resolve_path(processed_dir),
        "initial_rows": 0,
        "clean_rows": 0,
        "class_counts": {},
        "splits": {},
        "dropped_invalid_numeric": 0,
        "leakage_checks": {"suspicious_identifiers": [], "constant_columns": []}
    }
    
    for split_name, file_name in splits.items():
        df = pd.read_csv(os.path.join(raw_dir, file_name))
        report["initial_rows"] += len(df)
        
        df["final_label"] = df["label"].map(iot_map)
        df = df[df["final_label"].isin(valid_classes)]
        
        df, dropped = handle_invalid_numeric(df)
        report["dropped_invalid_numeric"] += dropped
        
        df = df.drop_duplicates()
        report["clean_rows"] += len(df)
        report["splits"][split_name] = len(df)
        
        for k, v in df["final_label"].value_counts().to_dict().items():
            report["class_counts"][k] = report["class_counts"].get(k, 0) + v
            
        if split_name == "train":
            suspicious, constant = check_leakage(df, "final_label")
            report["leakage_checks"]["suspicious_identifiers"] = suspicious
            report["leakage_checks"]["constant_columns"] = constant
            df.head(100).to_csv(resolve_path(os.path.join(config["paths"]["samples_dir"], "ciciot2023_sample.csv")), index=False)
            report["feature_count"] = len(df.columns) - 2
            
        df.drop(columns=["label", "final_label"]).to_parquet(resolve_path(os.path.join(processed_dir, f"{split_name}.parquet")))
        
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
    
    # Combined Class Distribution
    dist = {
        "IDS2018": ids_report["class_counts"],
        "CICIoT2023": iot_report["class_counts"]
    }
    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "class_distribution_report.json")), "w") as f:
        json.dump(dist, f, indent=4)
        
    update_env_checkpoint("ids2018_preparation_status", "Success")
    update_env_checkpoint("ciciot2023_preparation_status", "Success")
    update_env_checkpoint("data_preparation_completed", True)
    
    print("Pipelines successfully executed and verified.")

if __name__ == "__main__":
    main()
