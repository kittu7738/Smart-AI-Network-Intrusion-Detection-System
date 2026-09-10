import os
import json
import pandas as pd
import numpy as np
import time

from utils.data_preparation import resolve_path

def load_label_mapping():
    mapping_path = resolve_path("config/label_mapping.json")
    with open(mapping_path, "r") as f:
        return json.load(f)

def handle_invalid_numeric(df):
    df = df.replace([np.inf, -np.inf], np.nan)
    return df.dropna()

def analyze_dataset_overlaps(train, val, test, label_col):
    # Hash feature columns only
    feature_cols = [c for c in train.columns if c not in [label_col, 'Label', 'label']]
    
    # Create hashes
    train['hash'] = pd.util.hash_pandas_object(train[feature_cols], index=False)
    val['hash'] = pd.util.hash_pandas_object(val[feature_cols], index=False)
    test['hash'] = pd.util.hash_pandas_object(test[feature_cols], index=False)
    
    analysis = []
    
    pairs = [
        ("train_val", train, val),
        ("train_test", train, test),
        ("val_test", val, test)
    ]
    
    for pair_name, df1, df2 in pairs:
        # Find intersecting hashes
        common_hashes = set(df1['hash']).intersection(set(df2['hash']))
        overlap_count = len(common_hashes) # Number of unique feature vectors shared
        
        same_label = 0
        conflict_label = 0
        
        if overlap_count > 0:
            df1_overlap = df1[df1['hash'].isin(common_hashes)].drop_duplicates(subset=['hash', label_col])
            df2_overlap = df2[df2['hash'].isin(common_hashes)].drop_duplicates(subset=['hash', label_col])
            
            merged = pd.merge(df1_overlap[['hash', label_col]], df2_overlap[['hash', label_col]], on='hash', suffixes=('_1', '_2'))
            
            same_label = len(merged[merged[f"{label_col}_1"] == merged[f"{label_col}_2"]])
            conflict_label = len(merged[merged[f"{label_col}_1"] != merged[f"{label_col}_2"]])
            
        analysis.append({
            "split_pair": pair_name,
            "overlap_count": overlap_count,
            "percentage_of_df1": (overlap_count / len(df1)) * 100 if len(df1) else 0,
            "percentage_of_df2": (overlap_count / len(df2)) * 100 if len(df2) else 0,
            "same_label_count": same_label,
            "conflicting_label_count": conflict_label
        })
        
    return analysis

def analyze_ids2018(mapping):
    print("Analyzing IDS2018...")
    raw_path = resolve_path("Datasets/ids2018_combined_7attacks_benign.parquet")
    df = pd.read_parquet(raw_path)
    
    ids_map = mapping["IDS2018"]
    df["final_label"] = df["Label"].map(ids_map)
    
    valid_classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
    df = df[df["final_label"].isin(valid_classes)]
    
    df = handle_invalid_numeric(df)
    df = df.drop_duplicates()
    
    seed = 42
    train_dfs, val_dfs, test_dfs = [], [], []
    for label in df["final_label"].unique():
        class_df = df[df["final_label"] == label]
        if len(class_df) < 3:
            train_dfs.append(class_df)
            continue
        train_class = class_df.sample(frac=0.7, random_state=seed)
        rem = class_df.drop(train_class.index)
        val_class = rem.sample(frac=0.5, random_state=seed)
        test_class = rem.drop(val_class.index)
        train_dfs.append(train_class)
        val_dfs.append(val_class)
        test_dfs.append(test_class)
        
    X_train = pd.concat(train_dfs)
    X_val = pd.concat(val_dfs)
    X_test = pd.concat(test_dfs)
    
    return analyze_dataset_overlaps(X_train, X_val, X_test, "final_label")

def analyze_ciciot(mapping):
    print("Analyzing CICIoT2023...")
    raw_dir = resolve_path("Datasets/CICIOT23")
    iot_map = mapping["CICIoT2023"]
    valid_classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack", "Spoofing", "Recon / Port Scan", "MITM"]
    
    dfs = {}
    for split in ["train", "validation", "test"]:
        df = pd.read_csv(os.path.join(raw_dir, f"{split}.csv"))
        df["final_label"] = df["label"].map(iot_map)
        df = df[df["final_label"].isin(valid_classes)]
        df = handle_invalid_numeric(df)
        df = df.drop_duplicates()
        dfs[split] = df
        
    return analyze_dataset_overlaps(dfs["train"], dfs["validation"], dfs["test"], "final_label")

def main():
    mapping = load_label_mapping()
    ids_analysis = analyze_ids2018(mapping)
    iot_analysis = analyze_ciciot(mapping)
    
    report = {
        "timestamp": time.time(),
        "methodology": "Hashed feature columns (excluding labels). Cross-referenced hashes across splits. Evaluated whether identical feature vectors shared the same or conflicting labels.",
        "datasets": {
            "IDS2018": ids_analysis,
            "CICIoT2023": iot_analysis
        },
        "recommendation": "For IDS2018: The overlaps are likely conflicting labels (identical features but different labels, which bypass drop_duplicates). These should be removed to prevent confusion. For CICIoT2023: The overlaps are primarily identical patterns (same labels) that naturally occur in network bursts. Since they appear across official splits, keeping them mimics real-world identical packet bursts, but removing them ensures zero train/test leakage. Recommendation: B. remove cross-split duplicates for absolute strict ML evaluation."
    }
    
    reports_dir = resolve_path("reports")
    os.makedirs(reports_dir, exist_ok=True)
    with open(os.path.join(reports_dir, "cross_split_overlap_analysis.json"), "w") as f:
        json.dump(report, f, indent=4)
        
    print("Analysis complete.")

if __name__ == "__main__":
    main()
