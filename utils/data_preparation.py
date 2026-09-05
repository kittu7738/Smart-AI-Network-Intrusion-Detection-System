import os
import json
import pandas as pd
import numpy as np
import gc
import time

BASE_DIR = "/Users/anjanprasadcherukuthota/Documents/Cybersecurity/projects/ids/saiids"
DATASETS_DIR = os.path.join(BASE_DIR, "Datasets")
CONFIG_PATH = os.path.join(BASE_DIR, "env_config.json")
MAPPING_PATH = os.path.join(BASE_DIR, "config/label_mapping.json")

# Outputs
PROCESSED_IDS = os.path.join(BASE_DIR, "data/processed/IDS2018")
PROCESSED_IOT = os.path.join(BASE_DIR, "data/processed/CICIoT2023")
SAMPLES_DIR = os.path.join(BASE_DIR, "data/samples")

def get_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {"checkpoints": {}}

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=4)

def check_leakage(df):
    suspicious = []
    constant_cols = []
    for c in df.columns:
        cl = c.lower()
        if "ip" in cl or "timestamp" in cl or "time" in cl or "id" in cl or "port" in cl:
            suspicious.append(c)
        if df[c].nunique() <= 1:
            constant_cols.append(c)
    return suspicious, constant_cols

def process_ids2018(mapping):
    print("Processing IDS2018...")
    file_path = os.path.join(DATASETS_DIR, "ids2018_combined_7attacks_benign.parquet")
    df = pd.read_parquet(file_path)
    
    initial_rows = len(df)
    features_before = len(df.columns) - 1
    
    # Mapping
    ids_map = mapping["IDS2018"]
    df["final_label"] = df["Label"].map(ids_map)
    
    # Filter
    valid_categories = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
    df = df[df["final_label"].isin(valid_categories)].copy()
    mapped_rows = len(df)
    
    # Clean
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Deduplicate
    df.drop_duplicates(inplace=True)
    clean_rows = len(df)
    
    # Leakage
    suspicious, constant = check_leakage(df.drop(columns=["Label", "final_label"]))
    
    print("Splitting IDS2018...")
    # Manual stratified split 70/15/15
    train_dfs = []
    val_dfs = []
    test_dfs = []
    
    for label in df['final_label'].unique():
        class_df = df[df['final_label'] == label]
        
        if len(class_df) < 3:
            print(f"Warning: Class {label} is too small to stratify safely.")
            # For this pipeline, we will just assign it to train
            train_dfs.append(class_df)
            continue
            
        train_class = class_df.sample(frac=0.7, random_state=42)
        rem = class_df.drop(train_class.index)
        val_class = rem.sample(frac=0.5, random_state=42)
        test_class = rem.drop(val_class.index)
        
        train_dfs.append(train_class)
        val_dfs.append(val_class)
        test_dfs.append(test_class)
        
    X_train = pd.concat(train_dfs).sample(frac=1, random_state=42)
    X_val = pd.concat(val_dfs).sample(frac=1, random_state=42)
    X_test = pd.concat(test_dfs).sample(frac=1, random_state=42)
    
    # y's for reports
    y = df['final_label']
    
    X_train_features = X_train.drop(columns=["Label", "final_label"])
    X_val_features = X_val.drop(columns=["Label", "final_label"])
    X_test_features = X_test.drop(columns=["Label", "final_label"])
    
    print("Saving IDS2018...")
    X_train_features.to_parquet(os.path.join(PROCESSED_IDS, "train.parquet"))
    X_val_features.to_parquet(os.path.join(PROCESSED_IDS, "val.parquet"))
    X_test_features.to_parquet(os.path.join(PROCESSED_IDS, "test.parquet"))
        
    # Sample
    X_train.head(100).to_csv(os.path.join(SAMPLES_DIR, "ids2018_sample.csv"), index=False)
    
    report = {
        "initial_rows": initial_rows,
        "mapped_rows": mapped_rows,
        "clean_rows": clean_rows,
        "dropped_rows": initial_rows - clean_rows,
        "feature_count": features_before,
        "classes": list(y.unique()),
        "class_counts": y.value_counts().to_dict(),
        "train_count": len(X_train),
        "val_count": len(X_val),
        "test_count": len(X_test),
        "suspicious_cols": suspicious,
        "constant_cols": constant
    }
    
    with open(os.path.join(BASE_DIR, "reports/ids2018_preparation_report.json"), "w") as f:
        json.dump(report, f, indent=4)
        
    del df, X_train, X_val, X_test, X_train_features, X_val_features, X_test_features, y
    gc.collect()
    return report

def process_ciciot2023(mapping):
    print("Processing CICIoT2023...")
    iot_map = mapping["CICIoT2023"]
    valid_categories = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack", "Spoofing", "Recon / Port Scan", "MITM"]
    
    splits = {"train": "train.csv", "val": "validation.csv", "test": "test.csv"}
    
    report = {"initial_rows": 0, "clean_rows": 0, "class_counts": {}, "splits": {}}
    suspicious = []
    constant = []
    feature_count = 0
    
    for split_name, file_name in splits.items():
        print(f"  {split_name}...")
        df = pd.read_csv(os.path.join(DATASETS_DIR, "CICIOT23", file_name))
        report["initial_rows"] += len(df)
        
        label_col = "label"
        df["final_label"] = df[label_col].map(iot_map)
        df = df[df["final_label"].isin(valid_categories)].copy()
        
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        df.drop_duplicates(inplace=True)
        
        report["clean_rows"] += len(df)
        report["splits"][split_name] = len(df)
        
        for k, v in df["final_label"].value_counts().to_dict().items():
            report["class_counts"][k] = report["class_counts"].get(k, 0) + v
            
        if split_name == "train":
            suspicious, constant = check_leakage(df.drop(columns=[label_col, "final_label"]))
            df.head(100).to_csv(os.path.join(SAMPLES_DIR, "ciciot2023_sample.csv"), index=False)
            feature_count = len(df.columns) - 2
            
        df.drop(columns=[label_col]).to_parquet(os.path.join(PROCESSED_IOT, f"{split_name}.parquet"))
        del df
        gc.collect()
        
    report["suspicious_cols"] = suspicious
    report["constant_cols"] = constant
    report["feature_count"] = feature_count
    
    with open(os.path.join(BASE_DIR, "reports/ciciot2023_preparation_report.json"), "w") as f:
        json.dump(report, f, indent=4)
        
    return report

def main():
    cfg = get_config()
    
    with open(MAPPING_PATH, "r") as f:
        mapping = json.load(f)
        
    start_time = time.time()
    
    ids_rep = process_ids2018(mapping)
    iot_rep = process_ciciot2023(mapping)
    
    cfg["checkpoints"]["data_preparation_completed"] = True
    cfg["preparation_metadata"] = {
        "timestamp": time.time(),
        "pipeline_version": "1.0",
        "random_seed": 42,
        "strategy": "Dropped NaNs/Infs, deduplicated, 70/15/15 stratify for IDS2018. Official splits kept for CICIoT2023."
    }
    save_config(cfg)
    
    quality = {
        "ids2018": {"constant_features": ids_rep["constant_cols"], "suspicious_identifiers": ids_rep["suspicious_cols"]},
        "ciciot2023": {"constant_features": iot_rep["constant_cols"], "suspicious_identifiers": iot_rep["suspicious_cols"]}
    }
    with open(os.path.join(BASE_DIR, "reports/data_quality_report.json"), "w") as f:
        json.dump(quality, f, indent=4)
        
    print(f"Preparation complete in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
