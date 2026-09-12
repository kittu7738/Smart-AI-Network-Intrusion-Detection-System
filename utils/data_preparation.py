import os
import sys
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
    if not rel_path:
        return rel_path

    if os.path.isabs(rel_path):
        return os.path.normpath(rel_path)

    norm_rel = os.path.normpath(rel_path).replace("\\", "/")

    data_root = os.environ.get("NIDS_DATA_ROOT")
    if data_root:
        data_root = data_root.strip().strip('"').strip("'")

    # Auto-detect standard Colab Google Drive mount if NIDS_DATA_ROOT is not explicitly set
    if not data_root:
        colab_default = "/content/drive/MyDrive/Smart-AI-NIDS"
        if os.path.isdir(colab_default):
            data_root = colab_default

    project_root = os.environ.get("NIDS_PROJECT_ROOT", os.getcwd())
    if project_root:
        project_root = project_root.strip().strip('"').strip("'")

    if data_root:
        # 1. Known repository config / code paths -> project_root
        repo_prefixes = ("config", "utils", "tests", "notebooks", "README.md", "app.py", "requirements.txt")
        if any(norm_rel == p or norm_rel.startswith(p + "/") for p in repo_prefixes):
            return os.path.normpath(os.path.join(project_root, norm_rel))

        # 2. Processed datasets & samples (checked before raw to avoid matching dataset name suffixes)
        if norm_rel.startswith("data/processed/"):
            return os.path.normpath(os.path.join(data_root, norm_rel[len("data/"):]))
        if norm_rel == "data/processed":
            return os.path.normpath(os.path.join(data_root, "processed"))
        if norm_rel.startswith("processed/"):
            return os.path.normpath(os.path.join(data_root, norm_rel))
        if norm_rel == "processed":
            return os.path.normpath(os.path.join(data_root, "processed"))

        if norm_rel.startswith("data/samples/"):
            return os.path.normpath(os.path.join(data_root, norm_rel[len("data/"):]))
        if norm_rel == "data/samples":
            return os.path.normpath(os.path.join(data_root, "samples"))

        # 3. Raw datasets
        # IDS2018 raw dataset
        if norm_rel in (
            "Datasets/ids2018_combined_7attacks_benign.parquet",
            "raw/IDS2018/ids2018_combined_7attacks_benign.parquet",
            "IDS2018/ids2018_combined_7attacks_benign.parquet"
        ) or norm_rel.endswith("/ids2018_combined_7attacks_benign.parquet") or norm_rel == "ids2018_combined_7attacks_benign.parquet":
            return os.path.normpath(os.path.join(data_root, "raw", "IDS2018", "ids2018_combined_7attacks_benign.parquet"))

        # CICIoT2023 raw dataset directory
        if norm_rel in ("Datasets/CICIOT23", "raw/CICIoT2023", "Datasets/CICIoT2023", "raw/CICIOT23"):
            return os.path.normpath(os.path.join(data_root, "raw", "CICIoT2023"))

        # Other raw datasets (e.g. raw/additional/...)
        if norm_rel.startswith("raw/"):
            return os.path.normpath(os.path.join(data_root, norm_rel))

        # 4. Known runtime output directories (Drive-backed)
        data_prefixes = ("checkpoints", "reports", "models", "colab_state", "backups")
        if any(norm_rel == p or norm_rel.startswith(p + "/") for p in data_prefixes):
            return os.path.normpath(os.path.join(data_root, norm_rel))

        # General fallback with data_root
        return os.path.normpath(os.path.join(data_root, norm_rel))

    return os.path.normpath(os.path.join(project_root, norm_rel))

def load_config():
    with open(resolve_path("config/preprocessing_config.json"), "r") as f:
        return json.load(f)

def load_label_mapping():
    with open(resolve_path("config/label_mapping.json"), "r") as f:
        return json.load(f)

def update_env_checkpoint(key, value):
    env_path = resolve_path("checkpoints/progress.json")
    cfg = {}
    if os.path.exists(env_path):
        try:
            with open(env_path, "r") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg = loaded
        except Exception:
            cfg = {}

    if not isinstance(cfg.get("checkpoints"), dict):
        cfg["checkpoints"] = {}

    cfg["checkpoints"][key] = value

    os.makedirs(os.path.dirname(env_path), exist_ok=True)
    temp_path = f"{env_path}.tmp"
    try:
        with open(temp_path, "w") as f:
            json.dump(cfg, f, indent=4)
        os.replace(temp_path, env_path)
    except Exception:
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
    """Downcast float64 to float32 to save RAM and normalize signed zero (-0.0 to 0.0)."""
    float64_cols = df.select_dtypes(include=['float64']).columns
    if len(float64_cols) > 0:
        df[float64_cols] = df[float64_cols].astype('float32')
    float32_cols = df.select_dtypes(include=['float32']).columns
    for c in float32_cols:
        df[c] = np.where(df[c] == 0.0, np.float32(0.0), df[c]).astype(np.float32)
    return df

def process_ids2018(config, mapping, force_rebuild=False):
    processed_dir = config["paths"]["processed_ids2018"]
    if not force_rebuild and check_existing_files(processed_dir, ["train.parquet", "val.parquet", "test.parquet"]):
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

    parquet_file = pq.ParquetFile(raw_path)
    if "Label" not in parquet_file.schema.names:
        raise ValueError(f"Label column missing from {raw_path}")

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

        # Downcast float64 to float32 BEFORE hashing so that precision truncation
        # matches the exact representation written to parquet
        df = downcast_dtypes(df)

        feat_cols = [c for c in df.columns if c not in ["Label", "label", "final_label"]]
        df['hash'] = pd.util.hash_pandas_object(df[feat_cols], index=False)

        # Track which labels each hash is associated with using fast vectorization
        unique_pairs = df[['hash', 'final_label']].drop_duplicates()
        for h, l in zip(unique_pairs['hash'], unique_pairs['final_label']):
            hash_to_labels[h].add(l)

        del df
        gc.collect()

    # Identify conflicting hashes
    conflicting_hashes = {h for h, labels in hash_to_labels.items() if len(labels) > 1}
    conflicting_groups = len(conflicting_hashes)
    del hash_to_labels
    gc.collect()

    # Pass 2: Extract valid rows, downcast, drop exact duplicates, and split
    print("  Pass 2: Extracting clean data and streaming to parquet (Memory Safe)...")
    seen_hashes = set()
    conflicting_rows_removed = 0
    clean_rows = 0
    features_before = 0

    os.makedirs(resolve_path(processed_dir), exist_ok=True)
    tmp_train = resolve_path(os.path.join(processed_dir, "train.tmp.parquet"))
    tmp_val = resolve_path(os.path.join(processed_dir, "val.tmp.parquet"))
    tmp_test = resolve_path(os.path.join(processed_dir, "test.tmp.parquet"))

    writer_train = None
    writer_train_schema = None
    writer_val = None
    writer_val_schema = None
    writer_test = None
    writer_test_schema = None

    suspicious, constant = [], []
    class_counts = defaultdict(int)
    train_count = 0
    val_count = 0
    test_count = 0
    classes = set()

    for i, batch in enumerate(parquet_file.iter_batches(batch_size=500000)):
        start_t = time.time()
        df = batch.to_pandas()
        df["final_label"] = df["Label"].map(ids_map)
        df = df[df["final_label"].isin(valid_classes)]
        df, _ = handle_invalid_numeric(df)

        # Downcast float64 to float32 BEFORE hashing so that precision truncation
        # matches the exact representation written to parquet
        df = downcast_dtypes(df)

        feat_cols = [c for c in df.columns if c not in ["Label", "label", "final_label"]]
        df['hash'] = pd.util.hash_pandas_object(df[feat_cols], index=False)

        # Option C: Drop all rows with conflicting hashes
        is_conflict = df['hash'].isin(conflicting_hashes)
        conflicting_rows_removed += is_conflict.sum()
        df = df[~is_conflict]

        # Deduplicate internally within the chunk first
        df = df.drop_duplicates(subset=['hash'])

        # Deduplicate globally across chunks
        is_dup = df['hash'].isin(seen_hashes)
        df = df[~is_dup]
        seen_hashes.update(df['hash'])

        df = df.drop(columns=["hash", "Label"])
        clean_rows += len(df)
        if len(df.columns) > features_before: features_before = len(df.columns) - 1

        if len(df) > 0:
            if clean_rows == len(df): # First chunk
                suspicious, constant = check_leakage(df, "final_label")

            X_train, X_val, X_test = split_stratified(df, "final_label", config["parameters"]["random_seed"])

            for k, v in df["final_label"].value_counts().to_dict().items():
                class_counts[k] += v
                classes.add(k)

            train_count += len(X_train)
            val_count += len(X_val)
            test_count += len(X_test)

            if len(X_train) > 0:
                table = pa.Table.from_pandas(X_train, preserve_index=False)
                if writer_train is None:
                    writer_train_schema = table.schema
                    writer_train = pq.ParquetWriter(tmp_train, writer_train_schema)
                else:
                    if table.schema != writer_train_schema:
                        try:
                            X_train = X_train[[field.name for field in writer_train_schema]]
                            table = pa.Table.from_pandas(X_train, preserve_index=False).cast(writer_train_schema)
                        except Exception as e:
                            raise ValueError(f"Schema mismatch! Writer schema: {writer_train_schema}, Chunk schema: {table.schema}") from e
                writer_train.write_table(table)

            if len(X_val) > 0:
                table = pa.Table.from_pandas(X_val, preserve_index=False)
                if writer_val is None:
                    writer_val_schema = table.schema
                    writer_val = pq.ParquetWriter(tmp_val, writer_val_schema)
                else:
                    if table.schema != writer_val_schema:
                        try:
                            X_val = X_val[[field.name for field in writer_val_schema]]
                            table = pa.Table.from_pandas(X_val, preserve_index=False).cast(writer_val_schema)
                        except Exception as e:
                            raise ValueError(f"Schema mismatch! Writer schema: {writer_val_schema}, Chunk schema: {table.schema}") from e
                writer_val.write_table(table)

            if len(X_test) > 0:
                table = pa.Table.from_pandas(X_test, preserve_index=False)
                if writer_test is None:
                    writer_test_schema = table.schema
                    writer_test = pq.ParquetWriter(tmp_test, writer_test_schema)
                else:
                    if table.schema != writer_test_schema:
                        try:
                            X_test = X_test[[field.name for field in writer_test_schema]]
                            table = pa.Table.from_pandas(X_test, preserve_index=False).cast(writer_test_schema)
                        except Exception as e:
                            raise ValueError(f"Schema mismatch! Writer schema: {writer_test_schema}, Chunk schema: {table.schema}") from e
                writer_test.write_table(table)

        print(f"    Pass 2 Chunk {i+1} processed in {time.time()-start_t:.1f}s. Total clean: {clean_rows}")
        gc.collect()

    if writer_train: writer_train.close()
    if writer_val: writer_val.close()
    if writer_test: writer_test.close()
    del seen_hashes, conflicting_hashes
    gc.collect()

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
        "final_row_count": clean_rows,
        "feature_count": features_before,
        "classes": list(classes),
        "class_counts": dict(class_counts),
        "train_count": train_count,
        "val_count": val_count,
        "test_count": test_count,
        "leakage_checks": {
            "suspicious_identifiers": suspicious,
            "constant_columns": constant
        },
        "strategy": "Option C: Conflicting feature groups removed completely (Memory Safe)."
    }

    os.makedirs(resolve_path(config["paths"]["reports_dir"]), exist_ok=True)
    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ids2018_preparation_report.json")), "w") as f:
        json.dump(report, f, indent=4)

    return report

def process_ciciot2023(config, mapping, force_rebuild=False):
    processed_dir = config["paths"]["processed_ciciot2023"]
    if not force_rebuild and check_existing_files(processed_dir, ["train.parquet", "val.parquet", "test.parquet"]):
        print("CICIoT2023 already processed. Skipping.")
        report_path = resolve_path(os.path.join(config["paths"]["reports_dir"], "ciciot2023_preparation_report.json"))
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                return json.load(f)
        return None

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
        "strategy": "Option B: Train boundary strict overlap removal (Memory Safe)."
    }

    def process_file_chunked(file_name, split_name, known_hashes=None, is_train=False):
        file_path = os.path.join(raw_dir, file_name)
        if not os.path.exists(file_path):
            print(f"Missing {file_path}")
            return None, set(), 0

        split_hashes = set()
        overlaps_removed = 0
        seen_in_split = set()

        tmp_out = resolve_path(os.path.join(processed_dir, f"{split_name}.tmp.parquet"))
        final_out = resolve_path(os.path.join(processed_dir, f"{split_name}.parquet"))
        writer = None
        writer_schema = None

        for i, chunk in enumerate(pd.read_csv(file_path, chunksize=500000, low_memory=False)):
            start_t = time.time()
            report["initial_rows"] += len(chunk)
            chunk["final_label"] = chunk["label"].map(iot_map)
            chunk = chunk[chunk["final_label"].isin(valid_classes)]
            chunk, dropped = handle_invalid_numeric(chunk)
            report["dropped_invalid_numeric"] += dropped

            chunk = downcast_dtypes(chunk)

            feat_cols = [c for c in chunk.columns if c not in ["label", "final_label"]]
            chunk["hash"] = pd.util.hash_pandas_object(chunk[feat_cols], index=False)

            # Deduplicate internally within the chunk first
            chunk = chunk.drop_duplicates(subset=['hash'])

            # Deduplicate across chunks within the same split
            chunk = chunk[~chunk["hash"].isin(seen_in_split)]
            seen_in_split.update(chunk["hash"])

            # Cross-split overlap removal
            if known_hashes is not None:
                overlap = chunk["hash"].isin(known_hashes)
                overlaps_removed += overlap.sum()
                chunk = chunk[~overlap]

            split_hashes.update(chunk["hash"])

            chunk = chunk.drop(columns=["hash", "label"])
            report["final_row_count"] += len(chunk)
            report["splits"][split_name] = report["splits"].get(split_name, 0) + len(chunk)

            for k, v in chunk["final_label"].value_counts().to_dict().items():
                report["class_counts"][k] = report["class_counts"].get(k, 0) + v

            if is_train and report["splits"][split_name] == len(chunk) and len(chunk) > 0:
                # First chunk of train
                suspicious, constant = check_leakage(chunk, "final_label")
                report["leakage_checks"]["suspicious_identifiers"] = suspicious
                report["leakage_checks"]["constant_columns"] = constant
                report["feature_count"] = len(chunk.columns) - 1 # excluding final_label

            if len(chunk) > 0:
                table = pa.Table.from_pandas(chunk, preserve_index=False)
                if writer is None:
                    writer_schema = table.schema
                    writer = pq.ParquetWriter(tmp_out, writer_schema)
                else:
                    if table.schema != writer_schema:
                        try:
                            chunk = chunk[[field.name for field in writer_schema]]
                            table = pa.Table.from_pandas(chunk, preserve_index=False).cast(writer_schema)
                        except Exception as e:
                            raise ValueError(f"Schema mismatch! Writer schema: {writer_schema}, Chunk schema: {table.schema}") from e
                writer.write_table(table)

            print(f"    {split_name} Chunk {i+1} processed in {time.time()-start_t:.1f}s. Clean rows: {len(chunk)}")
            gc.collect()

        if writer is not None: writer.close()
        if os.path.exists(tmp_out): os.rename(tmp_out, final_out)

        return True, split_hashes, overlaps_removed

    print("  Processing Train streaming to Parquet (Memory Safe)...")
    train_success, train_hashes, _ = process_file_chunked("train.csv", "train", is_train=True)
    if train_success is None: return None

    print("  Processing Validation streaming...")
    val_success, val_hashes, val_removed = process_file_chunked("validation.csv", "val", known_hashes=train_hashes)
    report["train_val_overlaps_removed"] = int(val_removed)

    print("  Processing Test streaming...")
    test_success, test_hashes, test_removed = process_file_chunked("test.csv", "test", known_hashes=train_hashes)
    report["train_test_overlaps_removed"] = int(test_removed)

    report["val_test_overlap_remaining"] = len(val_hashes.intersection(test_hashes))

    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "ciciot2023_preparation_report.json")), "w") as f:
        json.dump(report, f, indent=4)

    return report


def calculate_entropy(text):
    import math
    from collections import Counter
    if not text: return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

def extract_dns_features(df):
    """Extract statistical features from raw DNS query strings."""
    # query is at column 1 (0 is label)
    queries = df.iloc[:, 1].fillna("").astype(str)

    df["query_length"] = queries.str.len()
    df["num_dots"] = queries.str.count(r"\.")
    df["num_subdomains"] = df["num_dots"] + 1

    # Label lengths (labels are parts between dots)
    label_parts = queries.str.split(r"\.")
    df["max_label_length"] = label_parts.apply(lambda x: max((len(p) for p in x)) if x else 0)
    df["avg_label_length"] = label_parts.apply(lambda x: sum(len(p) for p in x)/len(x) if x and len(x)>0 else 0)

    # Char counts
    df["digit_count"] = queries.str.count(r"[0-9]")
    df["alpha_count"] = queries.str.count(r"[a-zA-Z]")
    df["special_character_count"] = queries.str.count(r"[^a-zA-Z0-9\.]")

    # Entropy
    df["entropy"] = queries.apply(calculate_entropy)

    # Drop the raw query
    df = df.drop(columns=[df.columns[1]])
    return df

def extract_arp_features(df):
    """Keep only defensible ARP/TCP/ICMP features."""
    defensible = [
        "frame_number", "frame_time_delta", "arp_opcode", "tcp_seq",
        "tcp_hdr_len", "data_len", "icmp_type", "tcp_flag_fin",
        "tcp_flag_syn", "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_ack", "final_label"
    ]
    # Filter to only columns that actually exist in the dataframe
    cols_to_keep = [c for c in defensible if c in df.columns]

    # Ensure no MAC addresses
    mac_cols = [c for c in df.columns if "mac" in c.lower()]
    cols_to_keep = [c for c in cols_to_keep if c not in mac_cols]

    return df[cols_to_keep]

def extract_5g_features(df):
    """Keep defensible 5G features, stripping raw IPs."""
    # Drop source and destination IPs if they exist
    ip_cols = [c for c in df.columns if "ip" in c.lower() and ("src" in c.lower() or "dst" in c.lower())]
    mac_cols = [c for c in df.columns if "mac" in c.lower()]
    bad_cols = ip_cols + mac_cols
    cols_to_keep = [c for c in df.columns if c not in bad_cols]
    return df[cols_to_keep]

def process_dataset_generic(config, mapping, dataset_name, raw_dir_key, processed_dir_key, file_splits, feature_extractor, map_key, force_rebuild=False):
    """A generic memory-safe processor for new datasets."""
    processed_dir = config["paths"][processed_dir_key]
    expected_outputs = [f"{split}.parquet" for split in file_splits.keys()]
    if not force_rebuild and check_existing_files(processed_dir, expected_outputs):
        print(f"{dataset_name} already processed. Skipping.")
        report_path = resolve_path(os.path.join(config["paths"]["reports_dir"], f"{dataset_name.lower()}_preparation_report.json"))
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                return json.load(f)
        return None

    print(f"Processing {dataset_name} memory-safely...")
    raw_dir = resolve_path(config["paths"][raw_dir_key])
    label_map = mapping[map_key]
    valid_classes = config["classes"].get(map_key.lower(), config["classes"].get(dataset_name.lower(), []))

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
        "dropped_invalid_numeric": 0,
        "leakage_checks": {"suspicious_identifiers": [], "constant_columns": []},
        "strategy": f"Source-specific extraction for {dataset_name}"
    }

    for split_name, file_list in file_splits.items():
        print(f"  Processing {split_name}...")
        tmp_out = resolve_path(os.path.join(processed_dir, f"{split_name}.tmp.parquet"))
        final_out = resolve_path(os.path.join(processed_dir, f"{split_name}.parquet"))
        writer = None
        writer_schema = None

        for file_name in file_list:
            file_path = os.path.join(raw_dir, file_name)
            if not os.path.exists(file_path):
                print(f"Missing {file_path}")
                continue

            # For DNS, no header
            header = None if dataset_name == "DNS_Tunneling" else "infer"

            for chunk_idx, chunk in enumerate(pd.read_csv(file_path, chunksize=250000, header=header, low_memory=False)):
                report["initial_rows"] += len(chunk)

                # Standardize label column name
                if dataset_name == "DNS_Tunneling":
                    chunk = chunk.rename(columns={0: "label"})

                label_col = None
                for candidate in ["label_name", "Label_Name", "Label", "label", 0, "0"]:
                    if candidate in chunk.columns:
                        label_col = candidate
                        break
                if label_col is None:
                    label_col = chunk.columns[0]

                # Standardize label mapping: string cast and strip
                chunk_labels = chunk[label_col].astype(str).str.strip()

                # Make label_map robust against int/string mismatches
                robust_map = {str(k).strip(): v for k, v in label_map.items()}

                # Map labels safely
                chunk["final_label"] = chunk_labels.map(robust_map)
                chunk = chunk[chunk["final_label"].isin(valid_classes)]

                # Extract features
                chunk = feature_extractor(chunk)

                # Numeric cleanup
                chunk, dropped = handle_invalid_numeric(chunk)
                report["dropped_invalid_numeric"] += dropped
                chunk = downcast_dtypes(chunk)

                # Drop original label columns to ensure no leakage
                for l_col in ["label", "Label", "label_name", "Label_Name"]:
                    if l_col in chunk.columns:
                        chunk = chunk.drop(columns=[l_col])

                report["final_row_count"] += len(chunk)
                report["splits"][split_name] = report["splits"].get(split_name, 0) + len(chunk)

                for k, v in chunk["final_label"].value_counts().to_dict().items():
                    report["class_counts"][k] = report["class_counts"].get(k, 0) + v

                if len(chunk) > 0:
                    # Leakage check on first chunk
                    if report["splits"][split_name] == len(chunk):
                        suspicious, constant = check_leakage(chunk, "final_label")
                        report["leakage_checks"]["suspicious_identifiers"].extend(suspicious)
                        report["leakage_checks"]["constant_columns"].extend(constant)
                        report["feature_count"] = len(chunk.columns) - 1

                    table = pa.Table.from_pandas(chunk, preserve_index=False)
                    if writer is None:
                        writer_schema = table.schema
                        writer = pq.ParquetWriter(tmp_out, writer_schema)
                    else:
                        if table.schema != writer_schema:
                            try:
                                chunk = chunk[[field.name for field in writer_schema]]
                                table = pa.Table.from_pandas(chunk, preserve_index=False).cast(writer_schema)
                            except Exception as e:
                                raise ValueError(f"Schema mismatch! Writer: {writer_schema}, Chunk: {table.schema}") from e
                    writer.write_table(table)
                gc.collect()

        if writer is not None: writer.close()

        if report["splits"][split_name] == 0:
            raise RuntimeError(f"Pipeline failure: {dataset_name} {split_name} resulted in 0 valid rows. Check label mapping or raw data.")

        if not os.path.exists(tmp_out):
            raise RuntimeError(f"Pipeline failure: tmp parquet not found for {dataset_name} {split_name} at {tmp_out}")

        os.rename(tmp_out, final_out)

        if not os.path.exists(final_out):
            raise RuntimeError(f"Pipeline failure: Final parquet not found at {final_out}")

    rep_dir = resolve_path(config["paths"]["reports_dir"])
    os.makedirs(rep_dir, exist_ok=True)
    with open(os.path.join(rep_dir, f"{dataset_name.lower()}_preparation_report.json"), "w") as f:
        json.dump(report, f, indent=4)

    return report

def process_arp(config, mapping, force_rebuild=False):
    file_splits = {"train": ["train.csv"], "test": ["test.csv"]}
    return process_dataset_generic(config, mapping, "ARP_Spoofing", "raw_arp_dir", "processed_arp", file_splits, extract_arp_features, "ARP", force_rebuild=force_rebuild)

def process_5g(config, mapping, force_rebuild=False):
    file_splits = {"train": ["data/Train_subset_1.csv", "data/Train_subset_2.csv"], "test": ["data/Test_Data.csv"]}
    return process_dataset_generic(config, mapping, "5G_NIDD", "raw_5g_dir", "processed_5g", file_splits, extract_5g_features, "5G", force_rebuild=force_rebuild)

def process_dns(config, mapping, force_rebuild=False):
    file_splits = {"train": ["training.csv"], "val": ["validating.csv"]}
    return process_dataset_generic(config, mapping, "DNS_Tunneling", "raw_dns_dir", "processed_dns", file_splits, extract_dns_features, "DNS", force_rebuild=force_rebuild)


def main():
    update_env_checkpoint("data_preparation_started", True)
    config = load_config()
    mapping = load_label_mapping()

    os.makedirs(resolve_path(config["paths"]["reports_dir"]), exist_ok=True)

    force_all = "--force-rebuild" in sys.argv or "--force-rebuild-all" in sys.argv
    force_ids2018 = (
        force_all or
        "--force-rebuild-ids2018" in sys.argv or
        os.environ.get("FORCE_REBUILD_IDS2018", "").lower() in ("1", "true", "yes")
    )
    force_ciciot = force_all or "--force-rebuild-ciciot2023" in sys.argv
    force_arp = force_all or "--force-rebuild-arp" in sys.argv
    force_5g = force_all or "--force-rebuild-5g" in sys.argv
    force_dns = force_all or "--force-rebuild-dns" in sys.argv

    ids_report = process_ids2018(config, mapping, force_rebuild=force_ids2018)
    iot_report = process_ciciot2023(config, mapping, force_rebuild=force_ciciot)
    arp_report = process_arp(config, mapping, force_rebuild=force_arp)
    nidd_report = process_5g(config, mapping, force_rebuild=force_5g)
    dns_report = process_dns(config, mapping, force_rebuild=force_dns)

    dist = {}
    if ids_report: dist["IDS2018"] = ids_report["class_counts"]
    if iot_report: dist["CICIoT2023"] = iot_report["class_counts"]
    if arp_report: dist["ARP_Spoofing"] = arp_report["class_counts"]
    if nidd_report: dist["5G_NIDD"] = nidd_report["class_counts"]
    if dns_report: dist["DNS_Tunneling"] = dns_report["class_counts"]

    with open(resolve_path(os.path.join(config["paths"]["reports_dir"], "class_distribution_report.json")), "w") as f:
        json.dump(dist, f, indent=4)

    update_env_checkpoint("ids2018_preparation_status", "Success" if ids_report else "Skipped")
    update_env_checkpoint("ciciot2023_preparation_status", "Success" if iot_report else "Skipped")
    update_env_checkpoint("data_preparation_completed", True)

    print("Pipelines safely executed.")

if __name__ == "__main__":
    main()
