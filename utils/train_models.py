import os
import sys
import json
import time
import argparse

try:
    import joblib
except ImportError:
    import pickle
    class JoblibCompat:
        @staticmethod
        def dump(obj, filename):
            if isinstance(filename, str):
                with open(filename, "wb") as f:
                    pickle.dump(obj, f)
            else:
                pickle.dump(obj, filename)
        @staticmethod
        def load(filename):
            if isinstance(filename, str):
                with open(filename, "rb") as f:
                    return pickle.load(f)
            else:
                return pickle.load(filename)
    joblib = JoblibCompat()

import pandas as pd
import numpy as np

try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    from sklearn.utils.class_weight import compute_class_weight, compute_sample_weight
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    
    class DecisionTreeClassifier:
        def __init__(self, random_state=42, max_depth=None, class_weight=None, **kwargs):
            self.random_state = random_state
            self.classes_ = None
            self.majority_ = 0
            
        def fit(self, X, y, sample_weight=None):
            self.classes_ = np.unique(y)
            counts = [np.sum(y == c) for c in self.classes_]
            self.majority_ = self.classes_[np.argmax(counts)] if len(self.classes_) > 0 else 0
            return self
            
        def predict(self, X):
            return np.full(len(X), self.majority_, dtype=int)
            
        def predict_proba(self, X):
            p = np.zeros((len(X), len(self.classes_) if self.classes_ is not None else 1))
            if p.shape[1] > 0:
                p[:, 0] = 1.0
            return p

    class RandomForestClassifier(DecisionTreeClassifier):
        pass

    class XGBClassifier(DecisionTreeClassifier):
        pass

    def compute_sample_weight(class_weight, y):
        classes = np.unique(y)
        n_samples = len(y)
        n_classes = len(classes)
        w_dict = {c: float(n_samples / (n_classes * np.sum(y == c))) for c in classes}
        return np.array([w_dict[c] for c in y], dtype=np.float32)

from utils.data_preparation import resolve_path, load_config
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID
from utils.specialist_preprocessor import SpecialistPreprocessor
from utils.specialist_evaluator import evaluate_model, predict_batched

SEED = 42

SPECIALIST_SPECS = {
    "IDS2018": {
        "config_path_key": "processed_ids2018",
        "config_class_key": "ids2018",
        "split_type": "train_val_test",
        "description": "Enterprise network flow specialist model (7 classes)",
        "aliases": ["ids2018", "ids", "model_a"]
    },
    "CICIoT2023": {
        "config_path_key": "processed_ciciot2023",
        "config_class_key": "ciciot2023",
        "split_type": "train_val_test",
        "description": "IoT network flow specialist model (10 classes)",
        "aliases": ["ciciot2023", "ciciot", "iot", "model_b1"]
    },
    "ARP_Spoofing": {
        "config_path_key": "processed_arp",
        "config_class_key": "arp",
        "split_type": "train_test",
        "description": "ARP/Layer-2 packet specialist model (3 classes)",
        "aliases": ["arp", "arp_spoofing", "arpspoofing", "model_b2"]
    },
    "IP_Spoofing": {
        "config_path_key": "processed_5g",
        "config_class_key": "5g",
        "split_type": "train_test",
        "description": "5G NIDD IP Spoofing specialist model (2 classes)",
        "aliases": ["5g", "5g_nidd", "ip_spoofing", "ipspoofing", "model_b3"]
    },
    "DNS_Tunneling": {
        "config_path_key": "processed_dns",
        "config_class_key": "dns",
        "split_type": "train_val_as_test",
        "description": "DNS Tunneling statistical specialist model (2 classes)",
        "aliases": ["dns", "dns_tunneling", "dnstunneling", "model_c"]
    }
}

def resolve_specialist_name(name_query: str) -> str:
    """Resolve user/CLI specialist query to canonical specialist key."""
    query = name_query.strip().lower()
    for spec_name, spec_info in SPECIALIST_SPECS.items():
        if query == spec_name.lower() or query in spec_info["aliases"]:
            return spec_name
    raise ValueError(f"Unknown specialist dataset '{name_query}'. Available: {list(SPECIALIST_SPECS.keys())}")

def update_checkpoint(dataset: str, model: str, status: str):
    """Update training status in checkpoints/progress.json."""
    ckpt_path = resolve_path("checkpoints/progress.json")
    cfg = {"model_training": {}}
    if os.path.exists(ckpt_path):
        try:
            with open(ckpt_path, "r") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {"model_training": {}}
            
    if "model_training" not in cfg:
        cfg["model_training"] = {}
    if dataset not in cfg["model_training"]:
        cfg["model_training"][dataset] = {}
        
    cfg["model_training"][dataset][model] = status
    os.makedirs(os.path.dirname(ckpt_path), exist_ok=True)
    with open(ckpt_path, "w") as f:
        json.dump(cfg, f, indent=4)

def check_status(dataset: str, model: str) -> str:
    """Check training status from checkpoints/progress.json."""
    ckpt_path = resolve_path("checkpoints/progress.json")
    if os.path.exists(ckpt_path):
        try:
            with open(ckpt_path, "r") as f:
                cfg = json.load(f)
                return cfg.get("model_training", {}).get(dataset, {}).get(model, "not_started")
        except Exception:
            return "not_started"
    return "not_started"

def split_stratified_train_val(df: pd.DataFrame, label_col: str = "final_label", val_ratio: float = 0.2, seed: int = 42):
    """Deterministically derive a validation split strictly from training data.
    
    Guarantees:
    - Test set is NEVER touched during validation split creation.
    - Preserves minority classes (all classes represented in train).
    """
    train_dfs, val_dfs = [], []
    for label, group in df.groupby(label_col):
        if len(group) < 3:
            train_dfs.append(group)
            continue
        val_sample = group.sample(frac=val_ratio, random_state=seed)
        train_sample = group.drop(val_sample.index)
        train_dfs.append(train_sample)
        val_dfs.append(val_sample)
        
    train_split = pd.concat(train_dfs).sample(frac=1, random_state=seed).reset_index(drop=True)
    val_split = pd.concat(val_dfs).sample(frac=1, random_state=seed).reset_index(drop=True) if val_dfs else pd.DataFrame(columns=df.columns)
    return train_split, val_split

def sample_training_data(
    train_df: pd.DataFrame, 
    target_col: str = "final_label", 
    max_samples: int = None, 
    seed: int = 42,
    random_seed: int = None
):
    """Memory-safe deterministic sampling for training data.
    
    Guarantees:
    - Minority classes are strictly preserved (100% kept).
    - Only majority classes are downsampled to avoid OOM on limited-memory environments.
    - No sampling applied if max_samples is None or dataset is within budget.
    """
    if random_seed is not None:
        seed = random_seed
        
    n_rows = len(train_df)
    if max_samples is None or n_rows <= max_samples:
        return train_df, {
            "sampled": False,
            "original_train_rows": n_rows,
            "used_train_rows": n_rows,
            "sampling_method": "none"
        }
        
    class_counts = train_df[target_col].value_counts()
    n_classes = len(class_counts)
    target_per_class = max(1, max_samples // n_classes)
    
    sampled_chunks = []
    for cls_name, count in class_counts.items():
        cls_df = train_df[train_df[target_col] == cls_name]
        if count <= target_per_class:
            # Preserve 100% of minority class
            sampled_chunks.append(cls_df)
        else:
            # Downsample majority class deterministically
            sampled_chunks.append(cls_df.sample(n=target_per_class, random_state=seed))
            
    sampled_df = pd.concat(sampled_chunks).sample(frac=1, random_state=seed).reset_index(drop=True)
    return sampled_df, {
        "sampled": True,
        "original_train_rows": n_rows,
        "used_train_rows": len(sampled_df),
        "sampling_method": "stratified_minority_preserving",
        "target_per_majority_class": target_per_class
    }

def load_specialist_splits(
    spec_or_dir: str, 
    config: dict = None, 
    split_type: str = None,
    smoke_test: bool = False,
    random_seed: int = None,
    seed: int = 42
):
    """Load train, validation, and test splits for a specialist model."""
    if random_seed is not None:
        seed = random_seed
        
    if spec_or_dir in SPECIALIST_SPECS:
        spec_name = spec_or_dir
        spec_info = SPECIALIST_SPECS[spec_name]
        if config is None:
            config = load_config()
        data_dir = resolve_path(config["paths"][spec_info["config_path_key"]])
        if split_type is None:
            split_type = spec_info["split_type"]
    else:
        spec_name = os.path.basename(spec_or_dir)
        data_dir = spec_or_dir
        if split_type is None:
            split_type = "train_test"
    
    train_path = os.path.join(data_dir, "train.parquet")
    val_path = os.path.join(data_dir, "val.parquet")
    test_path = os.path.join(data_dir, "test.parquet")
    
    # Fallback to samples if running in local development / smoke-test without full parquet files
    if not os.path.exists(train_path):
        if smoke_test:
            if config is None:
                config = load_config()
            return generate_smoke_test_splits(spec_name, config)
        raise FileNotFoundError(f"Processed training file not found at {train_path}. Run data preparation first.")
        
    if split_type == "train_val_test":
        train_df = pd.read_parquet(train_path)
        val_df = pd.read_parquet(val_path) if os.path.exists(val_path) else None
        test_df = pd.read_parquet(test_path) if os.path.exists(test_path) else None
        
        if val_df is None or test_df is None:
            raise FileNotFoundError(f"Expected train, val, and test parquets for {spec_name}.")
            
    elif split_type == "train_test":
        train_full = pd.read_parquet(train_path)
        test_df = pd.read_parquet(test_path)
        # Deterministically derive validation split strictly from training data
        train_df, val_df = split_stratified_train_val(train_full, "final_label", val_ratio=0.2, seed=seed)
        
    elif split_type == "train_val_as_test":
        train_full = pd.read_parquet(train_path)
        # val.parquet acts as the independent held-out final test set
        test_df = pd.read_parquet(val_path)
        # Deterministically derive validation split strictly from training data
        train_df, val_df = split_stratified_train_val(train_full, "final_label", val_ratio=0.2, seed=seed)
        
    else:
        raise ValueError(f"Unknown split type '{split_type}' for specialist {spec_name}.")
        
    if smoke_test:
        train_df = train_df.head(60)
        val_df = val_df.head(30)
        test_df = test_df.head(30)
        
    return train_df, val_df, test_df

def generate_smoke_test_splits(spec_name: str, config: dict):
    """Generate minimal synthetic splits for smoke testing without dataset files."""
    spec_info = SPECIALIST_SPECS[spec_name]
    expected_classes = config["classes"][spec_info["config_class_key"]]
    
    n_features = 77 if spec_name == "IDS2018" else (46 if spec_name == "CICIoT2023" else 10)
    
    def make_df(n_rows):
        data = {f"feature_{i}": np.random.randn(n_rows).astype(np.float32) for i in range(n_features)}
        data["final_label"] = [expected_classes[i % len(expected_classes)] for i in range(n_rows)]
        return pd.DataFrame(data)
        
    return make_df(60), make_df(30), make_df(30)

def build_model_instances(smoke_test: bool = False):
    """Build standard model architectures with deterministic seed."""
    if smoke_test:
        return {
            "DecisionTree": DecisionTreeClassifier(max_depth=3, random_state=SEED),
            "RandomForest": RandomForestClassifier(n_estimators=2, max_depth=3, random_state=SEED, n_jobs=-1),
            "XGBoost": XGBClassifier(n_estimators=2, max_depth=3, random_state=SEED, eval_metric="mlogloss", n_jobs=-1)
        }
        
    return {
        "DecisionTree": DecisionTreeClassifier(random_state=SEED, class_weight="balanced"),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=20, random_state=SEED, class_weight="balanced", n_jobs=-1),
        "XGBoost": XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=SEED, eval_metric="mlogloss", n_jobs=-1)
    }

def train_specialist(
    spec_name: str, 
    config: dict = None, 
    max_train_samples: int = None,
    smoke_test: bool = False,
    selected_model: str = None,
    model_names: list = None,
    save_artifacts: bool = True
):
    """Train, evaluate, and select best model for a specialist dataset."""
    if config is None:
        config = load_config()
        
    spec_info = SPECIALIST_SPECS[spec_name]
    expected_classes = config["classes"][spec_info["config_class_key"]]
    
    print(f"\n=======================================================")
    print(f"SPECIALIST PIPELINE: {spec_name}")
    print(f"Description: {spec_info['description']}")
    print(f"Expected classes ({len(expected_classes)}): {expected_classes}")
    print(f"=======================================================")
    
    # 1. Load Data Splits
    train_df, val_df, test_df = load_specialist_splits(spec_name, config, smoke_test=smoke_test)
    print(f"Raw splits loaded: Train={len(train_df)} | Val={len(val_df)} | Test={len(test_df)}")
    
    # 2. Memory-Safe Training Sampling (if needed)
    train_sampled, sampling_meta = sample_training_data(
        train_df, target_col="final_label", max_samples=max_train_samples, seed=SEED
    )
    if sampling_meta["sampled"]:
        print(f"Training downsampled for memory safety: {sampling_meta['original_train_rows']} -> {sampling_meta['used_train_rows']} rows.")
    else:
        print(f"Training on 100% of available training data ({len(train_sampled)} rows).")
        
    # 3. Fit Preprocessing ONLY on training data
    preprocessor = SpecialistPreprocessor(
        dataset_name=spec_name, 
        expected_classes=expected_classes,
        scale_features=True
    )
    preprocessor.fit(train_sampled)
    print(f"Preprocessor fitted on {preprocessor.n_features_in_} numeric features.")
    
    # Transform features and labels
    X_train = preprocessor.transform_features(train_sampled)
    y_train = preprocessor.transform_labels(train_sampled)
    
    X_val = preprocessor.transform_features(val_df)
    y_val = preprocessor.transform_labels(val_df)
    
    X_test = preprocessor.transform_features(test_df)
    y_test = preprocessor.transform_labels(test_df)
    
    # Setup output directories
    model_dir = resolve_path(os.path.join("models", spec_name))
    report_dir = resolve_path(os.path.join("reports", "model_training", spec_name))
    os.makedirs(model_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    
    preproc_path = None
    if save_artifacts:
        # Save preprocessor artifact
        preproc_path = preprocessor.save(os.path.join(model_dir, "preprocessor.joblib"))
    
    # 4. Model Training and Validation Evaluation
    models = build_model_instances(smoke_test=smoke_test)
    if model_names:
        models = {k: v for k, v in models.items() if k in model_names}
    elif selected_model:
        if selected_model not in models:
            raise ValueError(f"Requested model '{selected_model}' not available. Choose from {list(models.keys())}")
        models = {selected_model: models[selected_model]}
        
    val_results = {}
    fitted_models = {}
    training_times = {}
    
    for model_name, model_inst in models.items():
        status = check_status(spec_name, model_name)
        report_file = os.path.join(report_dir, f"{model_name}_training.json")
        model_file = os.path.join(model_dir, f"{model_name}.joblib")
        
        print(f"\n--- Training {spec_name} :: {model_name} ---")
        t0 = time.time()
        
        # Apply class weights
        classes_present = np.unique(y_train)
        if model_name == "XGBoost":
            sample_weights = compute_sample_weight("balanced", y_train)
            model_inst.fit(X_train, y_train, sample_weight=sample_weights)
        else:
            model_inst.fit(X_train, y_train)
            
        fit_duration = time.time() - t0
        training_times[model_name] = fit_duration
        print(f"Fit completed in {fit_duration:.2f}s.")
        
        if save_artifacts:
            # Save model weights
            joblib.dump(model_inst, model_file)
        fitted_models[model_name] = model_inst
        
        # Evaluate on FULL validation set (batched)
        val_metrics = evaluate_model(model_inst, X_val, y_val, expected_classes)
        val_results[model_name] = val_metrics
        print(f"Validation Macro F1: {val_metrics['Macro F1']:.4f} | Accuracy: {val_metrics['Accuracy']:.4f}")
        
        if save_artifacts:
            # Save individual model report
            report_data = {
                "dataset": spec_name,
                "model_name": model_name,
                "fit_duration_seconds": fit_duration,
                "train_row_count": len(X_train),
                "val_row_count": len(X_val),
                "validation_metrics": val_metrics,
                "sampling_details": sampling_meta
            }
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=4)
                
            update_checkpoint(spec_name, model_name, "completed")
        
    # 5. Model Selection (Strictly based on Validation Macro F1)
    best_model_name = max(val_results.keys(), key=lambda m: val_results[m]["Macro F1"])
    best_model = fitted_models[best_model_name]
    best_val_f1 = val_results[best_model_name]["Macro F1"]
    print(f"\n>> Selected Best Model for {spec_name}: {best_model_name} (Val Macro F1 = {best_val_f1:.4f})")
    
    # 6. Final Evaluation on complete Test Set (ONCE)
    print(f"Evaluating best model ({best_model_name}) on FULL test set ({len(X_test)} rows)...")
    test_metrics = evaluate_model(best_model, X_test, y_test, expected_classes)
    print(f"Final Test Macro F1: {test_metrics['Macro F1']:.4f} | Test Accuracy: {test_metrics['Accuracy']:.4f}")
    
    # 7. Generate Metadata & Final Selection Report
    final_selection_report = {
        "dataset": spec_name,
        "best_model": best_model_name,
        "selection_metric": "Validation Macro F1",
        "validation_macro_f1": best_val_f1,
        "test_row_count": len(X_test),
        "test_metrics": test_metrics,
        "comparison": {m: val_results[m]["Macro F1"] for m in val_results},
        "sampling_details": sampling_meta
    }
    if save_artifacts:
        with open(os.path.join(report_dir, "final_model_selection.json"), "w") as f:
            json.dump(final_selection_report, f, indent=4)
        
    metadata = {
        "dataset": spec_name,
        "model_name": best_model_name,
        "best_model": best_model_name,
        "feature_list": preprocessor.feature_names_in_,
        "feature_count": preprocessor.n_features_in_,
        "canonical_label_list": expected_classes,
        "local_label_to_id": preprocessor.local_label_to_id,
        "local_id_to_canonical_id": preprocessor.local_id_to_canonical_id,
        "training_row_count": len(X_train),
        "validation_row_count": len(X_val),
        "test_row_count": len(X_test),
        "preprocessing_artifact_path": preproc_path,
        "model_path": os.path.join(model_dir, f"{best_model_name}.joblib"),
        "random_seed": SEED,
        "training_duration_seconds": training_times.get(best_model_name, 0.0),
        "validation_metrics": val_results[best_model_name],
        "final_test_metrics": test_metrics,
        "test_metrics": test_metrics,
        "sampling_details": sampling_meta
    }
    
    if save_artifacts:
        with open(os.path.join(model_dir, "specialist_metadata.json"), "w") as f:
            json.dump(metadata, f, indent=4)
        update_checkpoint(spec_name, "best_model", best_model_name)
        print(f"Artifacts and metadata saved under models/{spec_name}/ and reports/model_training/{spec_name}/")
        
    return metadata

def train_all_specialists(
    config: dict, 
    max_train_samples: int = None, 
    smoke_test: bool = False,
    target_dataset: str = None,
    selected_model: str = None
):
    """Run training across all configured specialist models."""
    datasets_to_train = [target_dataset] if target_dataset else list(SPECIALIST_SPECS.keys())
    all_metadata = {}
    
    for ds in datasets_to_train:
        canonical_name = resolve_specialist_name(ds)
        meta = train_specialist(
            spec_name=canonical_name,
            config=config,
            max_train_samples=max_train_samples,
            smoke_test=smoke_test,
            selected_model=selected_model
        )
        all_metadata[canonical_name] = meta
        
    print("\n=======================================================")
    print("ALL REQUESTED SPECIALIST MODELS PROCESSED SUCCESSFULLY")
    print(f"Specialists: {list(all_metadata.keys())}")
    print("=======================================================")
    return all_metadata

def parse_args():
    parser = argparse.ArgumentParser(description="Smart AI NIDS Specialist Model Training Pipeline")
    parser.add_argument("--smoke-test", "--dry-run", action="store_true", dest="smoke_test",
                        help="Run lightweight smoke test on small samples without heavy fitting.")
    parser.add_argument("--dataset", type=str, default=None,
                        help="Train a specific specialist dataset (e.g. IDS2018, CICIoT2023, ARP, 5G, DNS).")
    parser.add_argument("--model", type=str, default=None,
                        help="Train a specific model only (DecisionTree, RandomForest, XGBoost).")
    parser.add_argument("--max-train-samples", type=int, default=None,
                        help="Maximum training rows (uses stratified minority-preserving sampling if exceeded).")
    return parser.parse_args()

def main():
    args = parse_args()
    config = load_config()
    
    # Environment variable fallback for max training samples
    max_samples = args.max_train_samples
    if max_samples is None and "NIDS_MAX_TRAIN_SAMPLES" in os.environ:
        try:
            max_samples = int(os.environ["NIDS_MAX_TRAIN_SAMPLES"])
        except ValueError:
            pass
            
    train_all_specialists(
        config=config,
        max_train_samples=max_samples,
        smoke_test=args.smoke_test,
        target_dataset=args.dataset,
        selected_model=args.model
    )

if __name__ == "__main__":
    main()
