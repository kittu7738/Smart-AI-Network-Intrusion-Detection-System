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
            class CompatUnpickler(pickle.Unpickler):
                def find_class(self, module, name):
                    if module == "__main__":
                        cls_map = {
                            "DecisionTreeClassifier": globals().get("DecisionTreeClassifier"),
                            "RandomForestClassifier": globals().get("RandomForestClassifier"),
                            "ExtraTreesClassifier": globals().get("ExtraTreesClassifier"),
                            "HistGradientBoostingClassifier": globals().get("HistGradientBoostingClassifier"),
                            "XGBClassifier": globals().get("XGBClassifier"),
                        }
                        if name in cls_map and cls_map[name] is not None:
                            return cls_map[name]
                    return super().find_class(module, name)

            if isinstance(filename, str):
                with open(filename, "rb") as f:
                    return CompatUnpickler(f).load()
            else:
                return CompatUnpickler(filename).load()
    joblib = JoblibCompat()

import pandas as pd
import numpy as np

try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier
    from xgboost import XGBClassifier
    from sklearn.utils.class_weight import compute_class_weight, compute_sample_weight
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

    class DecisionTreeClassifier:
        def __init__(self, random_state=42, max_depth=None, class_weight=None, **kwargs):
            self.random_state = random_state
            self.max_depth = max_depth
            self.class_weight = class_weight
            for k, v in kwargs.items():
                setattr(self, k, v)
            self.classes_ = None
            self.majority_ = 0

        def fit(self, X, y, sample_weight=None):
            self.classes_ = np.unique(y)
            counts = [np.sum(y == c) for c in self.classes_]
            self.majority_ = self.classes_[np.argmax(counts)] if len(self.classes_) > 0 else 0
            self.n_features_in_ = X.shape[1] if hasattr(X, "shape") and len(X.shape) > 1 else None
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

    class ExtraTreesClassifier(DecisionTreeClassifier):
        pass

    class HistGradientBoostingClassifier(DecisionTreeClassifier):
        pass

    class XGBClassifier(DecisionTreeClassifier):
        pass

    def compute_sample_weight(class_weight, y):
        classes = np.unique(y)
        n_samples = len(y)
        n_classes = len(classes)
        w_dict = {c: float(n_samples / (n_classes * np.sum(y == c))) for c in classes}
        return np.array([w_dict[c] for c in y], dtype=np.float32)

import gc
from utils.data_preparation import resolve_path, load_config
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID
from utils.specialist_preprocessor import SpecialistPreprocessor
from utils.specialist_evaluator import evaluate_model, evaluate_dataset_streamed, predict_batched
from utils.model_registry import OPTIMIZATION_CANDIDATE_CONFIGS, get_candidate_model
from utils.class_weighting import compute_specialist_sample_weights

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

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

MODEL_ALIASES = {
    "decisiontree": "DecisionTree",
    "decision_tree": "DecisionTree",
    "dt": "DecisionTree",
    "tree": "DecisionTree",
    "randomforest": "RandomForest",
    "random_forest": "RandomForest",
    "rf": "RandomForest",
    "forest": "RandomForest",
    "xgboost": "XGBoost",
    "xgb": "XGBoost",
    "histgradientboosting": "HistGradientBoosting",
    "hist_gradient_boosting": "HistGradientBoosting",
    "hgb": "HistGradientBoosting",
    "extratrees": "ExtraTrees",
    "extra_trees": "ExtraTrees",
    "et": "ExtraTrees",
    # Progressive optimizer candidate aliases
    "decisiontree_tuned": "DecisionTree_Tuned",
    "decision_tree_tuned": "DecisionTree_Tuned",
    "dt_tuned": "DecisionTree_Tuned",
    "candidate_decisiontree_tuned": "DecisionTree_Tuned",
    "candidate_decision_tree_tuned": "DecisionTree_Tuned",
    "decisiontree_baseline": "DecisionTree_Baseline",
    "candidate_decisiontree_baseline": "DecisionTree_Baseline",
    "randomforest_tuned": "RandomForest_Tuned",
    "rf_tuned": "RandomForest_Tuned",
    "candidate_randomforest_tuned": "RandomForest_Tuned",
    "xgboost_tuned": "XGBoost_Tuned",
    "xgb_tuned": "XGBoost_Tuned",
    "candidate_xgboost_tuned": "XGBoost_Tuned",
    "candidate_histgradientboosting": "HistGradientBoosting",
    "candidate_extratrees": "ExtraTrees",
}

def normalize_model_name(model_name: str) -> str:
    """Normalize model query to standard capitalized name."""
    if not model_name:
        return model_name
    query = model_name.strip().lower()
    if query in MODEL_ALIASES:
        return MODEL_ALIASES[query]
    if query.startswith("candidate_"):
        sub_query = query[len("candidate_"):]
        if sub_query in MODEL_ALIASES:
            return MODEL_ALIASES[sub_query]
    for cand in OPTIMIZATION_CANDIDATE_CONFIGS.keys():
        if query == cand.lower() or query == f"candidate_{cand}".lower():
            return cand
    return model_name.strip()

def resolve_model_path(model_dir: str, model_name: str) -> str:
    """Resolve model artifact path, checking exact match and candidate_ prefixes."""
    # 1. Exact match: {model_name}.joblib
    p = os.path.join(model_dir, f"{model_name}.joblib")
    if os.path.exists(p):
        return p
    # 2. Candidate prefix: candidate_{model_name}.joblib
    p = os.path.join(model_dir, f"candidate_{model_name}.joblib")
    if os.path.exists(p):
        return p
    # 3. Strip candidate_ prefix if passed: {model_name[10:]}.joblib
    if model_name.startswith("candidate_"):
        stripped = model_name[len("candidate_"):]
        p = os.path.join(model_dir, f"{stripped}.joblib")
        if os.path.exists(p):
            return p
    # Default fallback to standard path
    return os.path.join(model_dir, f"{model_name}.joblib")

def load_stored_threshold_multipliers(spec_name: str, opt_dir: str = None) -> dict:
    """Load reproducible validation threshold multipliers if stored by optimizer."""
    if opt_dir is None:
        opt_dir = resolve_path(os.path.join("reports", "model_training", spec_name, "optimization"))

    # 1. Check best_optimized_model.json
    best_file = os.path.join(opt_dir, "best_optimized_model.json")
    if os.path.exists(best_file):
        try:
            with open(best_file, "r") as f:
                data = json.load(f)
            if "threshold_multipliers" in data and isinstance(data["threshold_multipliers"], dict):
                return data["threshold_multipliers"]
        except Exception:
            pass

    # 2. Check threshold_tuning.json
    thresh_file = os.path.join(opt_dir, "threshold_tuning.json")
    if os.path.exists(thresh_file):
        try:
            with open(thresh_file, "r") as f:
                data = json.load(f)
            if "optimized" in data and "multipliers" in data["optimized"]:
                return data["optimized"]["multipliers"]
        except Exception:
            pass

    return None

def resolve_specialist_name(name_query: str) -> str:
    """Resolve user/CLI specialist query to canonical specialist key."""
    query = name_query.strip().lower()
    for spec_name, spec_info in SPECIALIST_SPECS.items():
        if query == spec_name.lower() or query in spec_info["aliases"]:
            return spec_name
    raise ValueError(f"Unknown specialist dataset '{name_query}'. Available: {list(SPECIALIST_SPECS.keys())}")

def update_checkpoint(dataset: str, model: str, status: str):
    """Update training status in checkpoints/progress.json.

    Robust against corrupted, non-dict, or legacy boolean schema in progress.json.
    """
    ckpt_path = resolve_path("checkpoints/progress.json")
    cfg = {}
    if os.path.exists(ckpt_path):
        try:
            with open(ckpt_path, "r") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg = loaded
        except Exception:
            cfg = {}

    if not isinstance(cfg.get("checkpoints"), dict):
        cfg["checkpoints"] = {}

    # Guarantee model_training is always a dictionary
    if not isinstance(cfg.get("model_training"), dict):
        cfg["model_training"] = {}

    # Guarantee dataset entry is always a dictionary
    if not isinstance(cfg["model_training"].get(dataset), dict):
        prev = cfg["model_training"].get(dataset)
        cfg["model_training"][dataset] = {}
        if isinstance(prev, str):
            cfg["model_training"][dataset]["status"] = prev

    cfg["model_training"][dataset][model] = status
    cfg["checkpoints"][f"{dataset.lower()}_model_training_status"] = status

    os.makedirs(os.path.dirname(ckpt_path), exist_ok=True)
    temp_path = f"{ckpt_path}.tmp"
    try:
        with open(temp_path, "w") as f:
            json.dump(cfg, f, indent=4)
        os.replace(temp_path, ckpt_path)
    except Exception:
        with open(ckpt_path, "w") as f:
            json.dump(cfg, f, indent=4)

def check_status(dataset: str, model: str) -> str:
    """Check training status from checkpoints/progress.json."""
    ckpt_path = resolve_path("checkpoints/progress.json")
    if os.path.exists(ckpt_path):
        try:
            with open(ckpt_path, "r") as f:
                cfg = json.load(f)
                if isinstance(cfg, dict):
                    mt = cfg.get("model_training")
                    if isinstance(mt, dict):
                        ds_info = mt.get(dataset)
                        if isinstance(ds_info, dict):
                            return str(ds_info.get(model, "not_started"))
        except Exception:
            return "not_started"
    return "not_started"

def should_invalidate_checkpoint(cached_train_rows: int, n_train_raw: int) -> bool:
    """Determine whether a cached training report / preprocessor is stale and must be invalidated.

    Invalidates if:
    1. Cached rows are from a micro-stub (<= 10 rows) and available data is larger (> 10 rows).
    2. Cached rows are from a subsample (< 1000 rows) and available data has >= 1000 rows.
    3. Cached rows are significantly smaller (< 50% of available data) for datasets > 100 rows.
    4. Legacy condition: cached_train_rows < 1000 and n_train_raw > 5000.
    """
    if n_train_raw is None or n_train_raw <= 0:
        return False
    if cached_train_rows <= 10 and n_train_raw > 10:
        return True
    if cached_train_rows < 1000 and (n_train_raw >= 1000 or n_train_raw > 5000):
        return True
    if n_train_raw > 100 and cached_train_rows < (n_train_raw * 0.5):
        return True
    return False

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

    sampled_indices = []
    for cls_name, count in class_counts.items():
        cls_idx = train_df.index[train_df[target_col] == cls_name]
        if count <= target_per_class:
            # Preserve 100% of minority class
            sampled_indices.extend(cls_idx)
        else:
            # Downsample majority class deterministically
            sampled_indices.extend(cls_idx.to_series().sample(n=target_per_class, random_state=seed))

    sampled_df = train_df.loc[sampled_indices].sample(frac=1, random_state=seed).reset_index(drop=True)
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
    seed: int = 42,
    lazy_val_test: bool = False
):
    """Load train, validation, and test splits for a specialist model.

    If lazy_val_test is True, validation and test sets are returned as Parquet file paths
    (or derived DataFrames if calculated in-memory) to avoid loading 1.8M unused rows into RAM.
    """
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
        if smoke_test:
            val_df = pd.read_parquet(val_path).head(30) if os.path.exists(val_path) else None
            test_df = pd.read_parquet(test_path).head(30) if os.path.exists(test_path) else None
            return train_df.head(60), val_df, test_df
        if lazy_val_test:
            return train_df, val_path, test_path

        val_df = pd.read_parquet(val_path) if os.path.exists(val_path) else None
        test_df = pd.read_parquet(test_path) if os.path.exists(test_path) else None
        if val_df is None or test_df is None:
            raise FileNotFoundError(f"Expected train, val, and test parquets for {spec_name}.")
        return train_df, val_df, test_df

    elif split_type == "train_test":
        train_full = pd.read_parquet(train_path)
        # Deterministically derive validation split strictly from training data
        train_df, val_df = split_stratified_train_val(train_full, "final_label", val_ratio=0.2, seed=seed)
        del train_full

        if smoke_test:
            test_df = pd.read_parquet(test_path).head(30) if os.path.exists(test_path) else None
            return train_df.head(60), val_df.head(30), test_df
        if lazy_val_test:
            return train_df, val_df, test_path

        test_df = pd.read_parquet(test_path)
        return train_df, val_df, test_df

    elif split_type == "train_val_as_test":
        train_full = pd.read_parquet(train_path)
        # Deterministically derive validation split strictly from training data
        train_df, val_df = split_stratified_train_val(train_full, "final_label", val_ratio=0.2, seed=seed)
        del train_full

        if smoke_test:
            test_df = pd.read_parquet(val_path).head(30) if os.path.exists(val_path) else None
            return train_df.head(60), val_df.head(30), test_df
        if lazy_val_test:
            # val.parquet acts as the independent held-out final test set
            return train_df, val_df, val_path

        test_df = pd.read_parquet(val_path)
        return train_df, val_df, test_df

    else:
        raise ValueError(f"Unknown split type '{split_type}' for specialist {spec_name}.")

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

def get_model_instance(model_name: str, smoke_test: bool = False):
    """Instantiate a single candidate model with memory-safe conservative configuration for Colab CPU/RAM."""
    if smoke_test:
        if model_name == "DecisionTree":
            return DecisionTreeClassifier(max_depth=3, random_state=SEED)
        elif model_name == "RandomForest":
            return RandomForestClassifier(n_estimators=2, max_depth=3, random_state=SEED, n_jobs=1)
        elif model_name == "XGBoost":
            return XGBClassifier(n_estimators=2, max_depth=3, random_state=SEED, eval_metric="mlogloss", n_jobs=1)
        elif model_name == "HistGradientBoosting":
            return HistGradientBoostingClassifier(max_iter=3, max_leaf_nodes=7, random_state=SEED)
        elif model_name == "ExtraTrees":
            return ExtraTreesClassifier(n_estimators=2, max_depth=3, random_state=SEED, n_jobs=1)
        else:
            raise ValueError(f"Unknown model name: {model_name}")

    if model_name == "DecisionTree":
        # Lightweight baseline: max_depth=15 prevents uncontrolled combinatorial leaf growth
        return DecisionTreeClassifier(
            max_depth=15,
            min_samples_leaf=5,
            random_state=SEED,
            class_weight="balanced"
        )
    elif model_name == "RandomForest":
        # Conservative RF configuration for Colab CPU/RAM:
        # 30 trees with max_depth=12, max_samples=0.25 (bootstrap subsample fraction), n_jobs=1 to avoid process duplication
        return RandomForestClassifier(
            n_estimators=30,
            max_depth=12,
            min_samples_leaf=10,
            max_samples=0.25,
            random_state=SEED,
            class_weight="balanced",
            n_jobs=1
        )
    elif model_name == "XGBoost":
        # Conservative XGBoost configuration for Colab CPU/RAM:
        # tree_method="hist" uses fast, low-memory histogram binning (256 bins) instead of greedy exact splitting.
        # n_jobs=2 utilizes Colab's 2 vCPUs safely without oversubscribing.
        return XGBClassifier(
            n_estimators=50,
            max_depth=6,
            learning_rate=0.1,
            tree_method="hist",
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=SEED,
            eval_metric="mlogloss",
            n_jobs=2
        )
    elif model_name == "HistGradientBoosting":
        return HistGradientBoostingClassifier(
            max_iter=150,
            max_leaf_nodes=63,
            min_samples_leaf=20,
            learning_rate=0.08,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=10,
            random_state=SEED
        )
    elif model_name == "ExtraTrees":
        return ExtraTreesClassifier(
            n_estimators=60,
            max_depth=20,
            min_samples_leaf=3,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=2,
            random_state=SEED
        )
    else:
        raise ValueError(f"Unknown model name: {model_name}")

def build_model_instances(smoke_test: bool = False):
    """Build standard model architectures with deterministic seed."""
    return {
        m: get_model_instance(m, smoke_test=smoke_test)
        for m in ["DecisionTree", "RandomForest", "XGBoost"]
    }

def train_specialist(
    spec_name: str,
    config: dict = None,
    max_train_samples: int = None,
    smoke_test: bool = False,
    selected_model: str = None,
    model_names: list = None,
    save_artifacts: bool = True,
    force_retrain: bool = False,
    evaluate_only: bool = False,
    use_optimized: bool = False,
    sync_preprocessor: bool = False,
    model_dir: str = None,
    report_dir: str = None
):
    """Train, evaluate, and select best model for a specialist dataset with strict memory safety."""
    if config is None:
        config = load_config()

    spec_info = SPECIALIST_SPECS[spec_name]
    expected_classes = config["classes"][spec_info["config_class_key"]]

    print(f"\n=======================================================", flush=True)
    print(f"SPECIALIST PIPELINE: {spec_name}", flush=True)
    print(f"Description: {spec_info['description']}", flush=True)
    print(f"Expected classes ({len(expected_classes)}): {expected_classes}", flush=True)
    print(f"=======================================================", flush=True)

    if model_dir is None:
        if smoke_test and not evaluate_only:
            model_dir = resolve_path(os.path.join("scratch", "smoke_test", "models", spec_name))
        else:
            model_dir = resolve_path(os.path.join("models", spec_name))
    else:
        model_dir = resolve_path(model_dir)

    if report_dir is None:
        if smoke_test and not evaluate_only:
            report_dir = resolve_path(os.path.join("scratch", "smoke_test", "reports", spec_name))
        else:
            report_dir = resolve_path(os.path.join("reports", "model_training", spec_name))
    else:
        report_dir = resolve_path(report_dir)

    if save_artifacts:
        os.makedirs(model_dir, exist_ok=True)
        os.makedirs(report_dir, exist_ok=True)

    is_default_dirs = (
        model_dir == resolve_path(os.path.join("models", spec_name)) and
        report_dir == resolve_path(os.path.join("reports", "model_training", spec_name))
    )
    if smoke_test and is_default_dirs:
        save_artifacts = False
    should_update_checkpoints = bool(save_artifacts and is_default_dirs and (not smoke_test))

    cand_preproc_file = os.path.join(model_dir, "candidate_preprocessor.joblib")
    std_preproc_file = os.path.join(model_dir, "preprocessor.joblib")
    if (use_optimized or (selected_model and "tuned" in selected_model.lower())) and os.path.exists(cand_preproc_file):
        preproc_path = cand_preproc_file
    else:
        preproc_path = std_preproc_file
    val_results = {}
    training_times = {}
    in_memory_models = {}
    threshold_multipliers = None

    if evaluate_only:
        print(f"\n[Evaluate-Only Mode] Evaluating saved models for {spec_name}...", flush=True)

        # Locate raw training parquet to verify / sync preprocessor statistics
        train_parquet_path = None
        if spec_name in SPECIALIST_SPECS:
            p_key = SPECIALIST_SPECS[spec_name]["config_path_key"]
            spec_dir = resolve_path(config["paths"][p_key])
            cand_path = os.path.join(spec_dir, "train.parquet")
            if os.path.exists(cand_path):
                train_parquet_path = cand_path

        # 1. Load / Validate Preprocessor
        preprocessor = None
        if os.path.exists(preproc_path) and not sync_preprocessor:
            try:
                preprocessor = SpecialistPreprocessor.load(preproc_path)
                valid_contract, contract_reason = preprocessor.validate_contract(
                    expected_classes=expected_classes, require_scaled=True, strict_order=True
                )
                if not valid_contract and not smoke_test:
                    print(f"[Notice] Loaded preprocessor at {preproc_path} failed contract validation ({contract_reason}). Discarding to re-fit from training data.", flush=True)
                    preprocessor = None
                else:
                    # Check training row count parity for full-data models
                    if train_parquet_path and not smoke_test:
                        n_train_rows = None
                        try:
                            import pyarrow.parquet as pq
                            n_train_rows = pq.read_metadata(train_parquet_path).num_rows
                        except Exception:
                            pass
                        prep_rows = getattr(preprocessor, "training_row_count_", 0)
                        if should_invalidate_checkpoint(prep_rows, n_train_rows):
                            print(f"[Preprocessor Sync] Loaded preprocessor was fitted on mock/stale rows ({prep_rows}), but train.parquet contains {n_train_rows} rows. Re-fitting from training data...", flush=True)
                            preprocessor = None
                        else:
                            print(f"Loaded existing preprocessor from {preproc_path} with {preprocessor.n_features_in_} features ({prep_rows} train rows).", flush=True)
                    else:
                        print(f"Loaded existing preprocessor from {preproc_path} with {preprocessor.n_features_in_} features.", flush=True)
            except Exception as e:
                print(f"[Warning] Failed to load preprocessor from {preproc_path}: {e}. Will attempt re-fit.", flush=True)
                preprocessor = None
        elif sync_preprocessor:
            print(f"[Preprocessor Sync] --sync-preprocessor requested. Forcing re-fit from training data...", flush=True)
            preprocessor = None

        if preprocessor is None:
            if train_parquet_path and not smoke_test:
                print(f"[Preprocessor Sync] Fitting clean SpecialistPreprocessor on full training dataset: {train_parquet_path}...", flush=True)
                full_train_df = pd.read_parquet(train_parquet_path)
                preprocessor = SpecialistPreprocessor(
                    dataset_name=spec_name,
                    expected_classes=expected_classes,
                    scale_features=True
                )
                preprocessor.fit(full_train_df)
                if save_artifacts:
                    preprocessor.save(preproc_path)
                del full_train_df
                gc.collect()
                print(f"[Preprocessor Sync] Saved full-dataset preprocessor to {preproc_path} ({preprocessor.n_features_in_} features, {preprocessor.training_row_count_} rows).", flush=True)
            elif smoke_test:
                print(f"Smoke-test: preprocessor not found at {preproc_path}, generating mock...", flush=True)
                train_df, _, _ = load_specialist_splits(spec_name, config, smoke_test=True)
                preprocessor = SpecialistPreprocessor(dataset_name=spec_name, expected_classes=expected_classes, scale_features=True)
                preprocessor.fit(train_df)
                if save_artifacts:
                    preprocessor.save(preproc_path)
                del train_df
                gc.collect()
            else:
                raise FileNotFoundError(f"Preprocessor not found at {preproc_path}. Run training first before evaluate-only.")

        # 2. Load validation and test sources
        _, val_source, test_source = load_specialist_splits(
            spec_name, config, smoke_test=smoke_test, lazy_val_test=True
        )

        # 3. Determine candidate models
        standard_candidates = ["DecisionTree", "RandomForest", "XGBoost"]
        all_candidates = list(standard_candidates)
        if spec_name in ["IDS2018", "CICIoT2023"] or use_optimized:
            for opt_c in OPTIMIZATION_CANDIDATE_CONFIGS.keys():
                if opt_c not in all_candidates:
                    all_candidates.append(opt_c)

        if model_names:
            candidate_names = [normalize_model_name(m) for m in all_candidates if normalize_model_name(m) in [normalize_model_name(x) for x in model_names]]
        elif selected_model:
            norm_model = normalize_model_name(selected_model)
            if use_optimized:
                # If --optimized was passed with a base algorithm name, map to tuned finalist
                if f"{norm_model}_Tuned" in OPTIMIZATION_CANDIDATE_CONFIGS:
                    norm_model = f"{norm_model}_Tuned"
                elif norm_model.lower() == "xgboost":
                    norm_model = "XGBoost_Tuned"
                elif norm_model.lower() == "decisiontree":
                    norm_model = "DecisionTree_Tuned"
                elif norm_model.lower() == "randomforest":
                    norm_model = "RandomForest_Tuned"
            if norm_model not in all_candidates:
                raise ValueError(f"Requested model '{selected_model}' not available. Choose from {all_candidates}")
            active_opt_dir = os.path.join(report_dir, "optimization") if report_dir else None
            if not (active_opt_dir and os.path.exists(active_opt_dir)):
                active_opt_dir = resolve_path(os.path.join("reports", "model_training", spec_name, "optimization"))

            candidate_names = [norm_model]
            if (spec_name in ["IDS2018", "CICIoT2023"] or use_optimized) and (norm_model in OPTIMIZATION_CANDIDATE_CONFIGS or use_optimized):
                threshold_multipliers = load_stored_threshold_multipliers(spec_name, opt_dir=active_opt_dir)
        else:
            # Check if progressive optimizer finalist model is recorded
            optimized_finalist = None
            active_opt_dir = os.path.join(report_dir, "optimization") if report_dir else None
            if not (active_opt_dir and os.path.exists(active_opt_dir)):
                active_opt_dir = resolve_path(os.path.join("reports", "model_training", spec_name, "optimization"))

            if spec_name in ["IDS2018", "CICIoT2023"] or use_optimized:
                opt_best_path = os.path.join(active_opt_dir, "best_optimized_model.json")
                if os.path.exists(opt_best_path):
                    try:
                        with open(opt_best_path, "r") as f:
                            opt_best_data = json.load(f)
                        cand_m = opt_best_data.get("model")
                        if cand_m:
                            norm_cand_m = normalize_model_name(cand_m)
                            cand_path = resolve_model_path(model_dir, norm_cand_m)
                            if os.path.exists(cand_path):
                                optimized_finalist = norm_cand_m
                    except Exception:
                        pass
                if not optimized_finalist and use_optimized:
                    # If flag --optimized was passed, try default finalist for specialist
                    default_cand = "XGBoost_Tuned" if spec_name == "CICIoT2023" else "DecisionTree_Tuned"
                    if os.path.exists(resolve_model_path(model_dir, default_cand)):
                        optimized_finalist = default_cand

            if optimized_finalist:
                candidate_names = [optimized_finalist]
                threshold_multipliers = load_stored_threshold_multipliers(spec_name, opt_dir=active_opt_dir)
                print(f"[Optimized Evaluation] Loading progressive optimizer finalist model: {optimized_finalist} from {resolve_model_path(model_dir, optimized_finalist)}", flush=True)
                if threshold_multipliers:
                    print(f"[Threshold Calibration] Applying validation-tuned probability multipliers: {threshold_multipliers}", flush=True)
            else:
                candidate_names = [m for m in standard_candidates if os.path.exists(resolve_model_path(model_dir, m))]
                if not candidate_names:
                    if smoke_test:
                        candidate_names = ["DecisionTree"]
                    else:
                        raise FileNotFoundError(f"No saved models found in {model_dir} for evaluation.")

        train_row_count = 0
        sampling_meta = {"sampled": False, "original_train_rows": 0, "used_train_rows": 0, "sampling_method": "none"}

        for model_name in candidate_names:
            report_file = os.path.join(report_dir, f"{model_name}_training.json")
            model_file = resolve_model_path(model_dir, model_name)

            if not os.path.exists(model_file):
                if smoke_test:
                    print(f"Smoke-test: fitting mock {model_name} for evaluation test...", flush=True)
                    model_inst = get_candidate_model(model_name, smoke_test=True) if model_name in OPTIMIZATION_CANDIDATE_CONFIGS else get_model_instance(model_name, smoke_test=True)
                    train_df, _, _ = load_specialist_splits(spec_name, config, smoke_test=True)
                    X_tr = preprocessor.transform_features(train_df)
                    y_tr = preprocessor.transform_labels(train_df)
                    model_inst.fit(X_tr, y_tr)
                    if save_artifacts:
                        joblib.dump(model_inst, model_file)
                    else:
                        in_memory_models[model_name] = model_inst
                    del train_df, X_tr, y_tr
                    gc.collect()
                else:
                    print(f"Warning: Model file {model_file} not found. Skipping {model_name}.", flush=True)
                    continue
            else:
                try:
                    model_inst = joblib.load(model_file)
                except Exception as e:
                    print(f"Warning: Failed to load model file {model_file}: {e}. Skipping {model_name}.", flush=True)
                    continue

            print(f"\n--- Evaluating {spec_name} :: {model_name} on validation split ---", flush=True)
            # Step 1: Evaluate baseline (uncalibrated)
            val_metrics_base = evaluate_dataset_streamed(
                model_inst, val_source, preprocessor, expected_classes, batch_size=100000,
                threshold_multipliers=None
            )
            print(f"Validation Baseline (Uncalibrated) Macro F1: {val_metrics_base['Macro F1']:.4f} | Accuracy: {val_metrics_base['Accuracy']:.4f}", flush=True)

            if threshold_multipliers:
                # Step 2: Evaluate with calibrated thresholds
                val_metrics_cal = evaluate_dataset_streamed(
                    model_inst, val_source, preprocessor, expected_classes, batch_size=100000,
                    threshold_multipliers=threshold_multipliers
                )
                print(f"Validation Calibrated Macro F1: {val_metrics_cal['Macro F1']:.4f} | Accuracy: {val_metrics_cal['Accuracy']:.4f}", flush=True)
                val_metrics = val_metrics_cal
                val_metrics["uncalibrated_baseline"] = {
                    "Macro F1": float(val_metrics_base.get("Macro F1", 0.0)),
                    "Accuracy": float(val_metrics_base.get("Accuracy", 0.0)),
                    "Macro Precision": float(val_metrics_base.get("Macro Precision", 0.0)),
                    "Macro Recall": float(val_metrics_base.get("Macro Recall", 0.0))
                }
            else:
                val_metrics = val_metrics_base

            val_results[model_name] = val_metrics

            fit_duration = 0.0
            if os.path.exists(report_file):
                try:
                    with open(report_file, "r") as f:
                        old_rep = json.load(f)
                        train_row_count = old_rep.get("train_row_count", train_row_count)
                        fit_duration = old_rep.get("fit_duration_seconds", fit_duration)
                        sampling_meta = old_rep.get("sampling_details", sampling_meta)
                except Exception:
                    pass
            training_times[model_name] = fit_duration

            if save_artifacts:
                report_data = {
                    "dataset": spec_name,
                    "model_name": model_name,
                    "model_path": model_file,
                    "fit_duration_seconds": fit_duration,
                    "train_row_count": train_row_count,
                    "validation_metrics": val_metrics,
                    "sampling_details": sampling_meta
                }
                if threshold_multipliers:
                    report_data["threshold_multipliers"] = threshold_multipliers
                with open(report_file, "w") as f:
                    json.dump(report_data, f, indent=4)
                if should_update_checkpoints:
                    update_checkpoint(spec_name, model_name, "completed")

            if save_artifacts:
                del model_inst
                gc.collect()
            else:
                in_memory_models[model_name] = model_inst

    else:
        # Standard Training Workflow
        # 1. Load Data Splits (lazy validation and test references avoid loading 1.8M unused rows into RAM)
        train_df, val_source, test_source = load_specialist_splits(
            spec_name, config, smoke_test=smoke_test, lazy_val_test=True
        )
        n_train_raw = len(train_df)
        val_repr = len(val_source) if isinstance(val_source, pd.DataFrame) else "disk (streamed)"
        test_repr = len(test_source) if isinstance(test_source, pd.DataFrame) else "disk (streamed)"
        print(f"Raw splits initialized: Train={n_train_raw} | Val={val_repr} | Test={test_repr}", flush=True)

        # 2. Memory-Safe Training Sampling (if needed)
        train_sampled, sampling_meta = sample_training_data(
            train_df, target_col="final_label", max_samples=max_train_samples, seed=SEED
        )
        del train_df
        gc.collect()

        if sampling_meta["sampled"]:
            print(f"Training downsampled for memory safety: {sampling_meta['original_train_rows']} -> {sampling_meta['used_train_rows']} rows.", flush=True)
        else:
            print(f"Training on 100% of available training data ({len(train_sampled)} rows).", flush=True)

        # 3. Fit Preprocessor strictly on training data
        preprocessor = SpecialistPreprocessor(
            dataset_name=spec_name,
            expected_classes=expected_classes,
            scale_features=True
        )
        preprocessor.fit(train_sampled)
        print(f"Preprocessor fitted on {preprocessor.n_features_in_} numeric features.", flush=True)

        if save_artifacts:
            preprocessor.save(preproc_path)

        # Materialize ONLY the training matrix in float32
        X_train = preprocessor.transform_features(train_sampled)
        y_train = preprocessor.transform_labels(train_sampled)
        train_row_count = len(X_train)

        # Free raw sampled training dataframe immediately
        del train_sampled
        gc.collect()
        print(f"Training matrix materialized in float32: shape={X_train.shape} ({X_train.nbytes / 1e6:.1f} MB).", flush=True)

        # Determine candidate models to run
        standard_candidates = ["DecisionTree", "RandomForest", "XGBoost"]
        all_candidates = list(standard_candidates)
        if spec_name in ["IDS2018", "CICIoT2023"]:
            for opt_c in OPTIMIZATION_CANDIDATE_CONFIGS.keys():
                if opt_c not in all_candidates:
                    all_candidates.append(opt_c)

        if model_names:
            candidate_names = [normalize_model_name(m) for m in all_candidates if normalize_model_name(m) in [normalize_model_name(x) for x in model_names]]
        elif selected_model:
            norm_model = normalize_model_name(selected_model)
            if norm_model not in all_candidates:
                raise ValueError(f"Requested model '{selected_model}' not available. Choose from {all_candidates}")
            candidate_names = [norm_model]
        else:
            candidate_names = list(standard_candidates)

        # Compute sample weights once if XGBoost is in candidate list
        xgb_sample_weights = None
        if "XGBoost" in candidate_names:
            xgb_sample_weights = compute_sample_weight("balanced", y_train)

        # 4. Sequential Model Training & Validation Evaluation
        for model_name in candidate_names:
            report_file = os.path.join(report_dir, f"{model_name}_training.json")
            model_file = resolve_model_path(model_dir, model_name)
            status = check_status(spec_name, model_name)

            # Checkpoint / resume: skip completed models if valid artifacts already exist (unless force_retrain=True)
            if not force_retrain and not smoke_test and save_artifacts and status == "completed" and os.path.exists(report_file) and os.path.exists(model_file):
                cached_train_rows = 0
                try:
                    with open(report_file, "r") as f:
                        r = json.load(f)
                        cached_train_rows = r.get("train_row_count", 0)
                except Exception:
                    pass

                if should_invalidate_checkpoint(cached_train_rows, n_train_raw):
                    print(f"\n[Checkpoint] Invalidation: cached report {report_file} has only {cached_train_rows} rows (available: {n_train_raw}). Re-training {model_name}...", flush=True)
                else:
                    print(f"\n[Checkpoint] Skipping {spec_name} :: {model_name} (already completed).", flush=True)
                    try:
                        val_results[model_name] = r["validation_metrics"]
                        training_times[model_name] = r.get("fit_duration_seconds", 0.0)
                        continue
                    except Exception as e:
                        print(f"Failed to read cached report for {model_name} ({e}). Re-training...", flush=True)

            print(f"\n--- Training {spec_name} :: {model_name} ---", flush=True)
            if should_update_checkpoints:
                update_checkpoint(spec_name, model_name, "running")

            # Instantiate ONLY the single model instance
            model_inst = get_candidate_model(model_name, smoke_test=smoke_test) if model_name in OPTIMIZATION_CANDIDATE_CONFIGS else get_model_instance(model_name, smoke_test=smoke_test)

            sample_w = None
            if model_name in OPTIMIZATION_CANDIDATE_CONFIGS:
                cand_cfg = OPTIMIZATION_CANDIDATE_CONFIGS[model_name]
                if cand_cfg.get("supports_sample_weight"):
                    w_strat = cand_cfg.get("default_weighting", "unweighted")
                    sample_w = compute_specialist_sample_weights(y_train, strategy=w_strat)
            elif model_name == "XGBoost":
                sample_w = xgb_sample_weights

            t0 = time.time()
            try:
                if sample_w is not None and model_name != "HistGradientBoosting":
                    model_inst.fit(X_train, y_train, sample_weight=sample_w)
                elif sample_w is not None and model_name == "HistGradientBoosting":
                    try:
                        model_inst.fit(X_train, y_train, sample_weight=sample_w)
                    except (TypeError, ValueError):
                        model_inst.fit(X_train, y_train)
                else:
                    model_inst.fit(X_train, y_train)
                fit_duration = time.time() - t0
                training_times[model_name] = fit_duration
                print(f"Fit completed in {fit_duration:.2f}s.", flush=True)

                if save_artifacts:
                    joblib.dump(model_inst, model_file)
                else:
                    in_memory_models[model_name] = model_inst

                # Batched validation evaluation (streams chunks, memory-safe)
                val_metrics = evaluate_dataset_streamed(
                    model_inst, val_source, preprocessor, expected_classes, batch_size=100000
                )
                val_results[model_name] = val_metrics
                print(f"Validation Macro F1: {val_metrics['Macro F1']:.4f} | Accuracy: {val_metrics['Accuracy']:.4f}", flush=True)

                if save_artifacts:
                    report_data = {
                        "dataset": spec_name,
                        "model_name": model_name,
                        "fit_duration_seconds": fit_duration,
                        "train_row_count": train_row_count,
                        "validation_metrics": val_metrics,
                        "sampling_details": sampling_meta
                    }
                    with open(report_file, "w") as f:
                        json.dump(report_data, f, indent=4)
                    if should_update_checkpoints:
                        update_checkpoint(spec_name, model_name, "completed")

            except Exception as e:
                if should_update_checkpoints:
                    update_checkpoint(spec_name, model_name, "failed")
                print(f"ERROR fitting {model_name}: {e}", flush=True)
                raise e

            finally:
                if save_artifacts:
                    del model_inst
                    gc.collect()

        # Free training data completely before test evaluation phase
        del X_train, y_train, xgb_sample_weights
        gc.collect()

    # 6. Model Selection (Strictly based on Validation Macro F1)
    if not val_results:
        raise RuntimeError(f"No candidate models were successfully trained or evaluated for {spec_name}.")

    best_model_name = max(val_results.keys(), key=lambda m: val_results[m]["Macro F1"])
    best_val_f1 = val_results[best_model_name]["Macro F1"]
    print(f"\n>> Selected Best Model for {spec_name}: {best_model_name} (Val Macro F1 = {best_val_f1:.4f})", flush=True)

    # 7. Final Evaluation on Complete Test Set (ONCE)
    # Strictly enforce validation reproduction before test evaluation for optimized candidates
    if evaluate_only and not smoke_test and (use_optimized or best_model_name in OPTIMIZATION_CANDIDATE_CONFIGS or "tuned" in best_model_name.lower()):
        val_acc = val_results[best_model_name].get("Accuracy", 0.0)
        val_f1 = val_results[best_model_name].get("Macro F1", 0.0)
        uncal_acc = val_results[best_model_name].get("uncalibrated_baseline", {}).get("Accuracy", val_acc)
        uncal_f1 = val_results[best_model_name].get("uncalibrated_baseline", {}).get("Macro F1", val_f1)
        gate_failed = False
        threshold_desc = ""
        if spec_name == "IDS2018":
            gate_failed = (uncal_acc < 0.95 or uncal_f1 < 0.80)
            threshold_desc = "expected >= 0.95 Acc, >= 0.80 Macro F1"
        elif spec_name == "CICIoT2023":
            if best_model_name in ["XGBoost_Tuned", "candidate_XGBoost_Tuned"] or use_optimized or "tuned" in best_model_name.lower():
                gate_failed = (uncal_acc < 0.985 or uncal_f1 < 0.75)
                threshold_desc = "expected >= 0.985 Acc, >= 0.750 Macro F1 for XGBoost_Tuned"
                if threshold_multipliers and val_f1 < 0.78:
                    gate_failed = True
                    threshold_desc += f", and >= 0.780 Calibrated Macro F1 (got {val_f1:.4f})"
            else:
                gate_failed = (uncal_acc < 0.95 or uncal_f1 < 0.69)
                threshold_desc = "expected >= 0.95 Acc, >= 0.69 Macro F1"

        if gate_failed:
            raise RuntimeError(
                f"[Evaluation Gatekeeper] Validation reproduction check FAILED for {spec_name} :: {best_model_name}: "
                f"Validation Accuracy={uncal_acc:.4f}, Macro F1={uncal_f1:.4f} ({threshold_desc}). "
                f"Held-out test evaluation strictly blocked to prevent test split contamination."
            )

    print(f"Loading best model ({best_model_name}) for final test evaluation...", flush=True)
    best_model_path = resolve_model_path(model_dir, best_model_name)
    if save_artifacts and os.path.exists(best_model_path):
        best_model = joblib.load(best_model_path)
    elif best_model_name in in_memory_models:
        best_model = in_memory_models[best_model_name]
    else:
        best_model = joblib.load(best_model_path)

    test_metrics = evaluate_dataset_streamed(
        best_model, test_source, preprocessor, expected_classes, batch_size=100000,
        threshold_multipliers=threshold_multipliers
    )
    # Fix: derive exact test_row_count from total evaluated samples, not summing averages
    test_row_count = int(test_metrics.get("total_samples", sum(test_metrics["Per Class"][c]["support"] for c in expected_classes if c in test_metrics["Per Class"])))
    print(f"Final Test Evaluation ({test_row_count} rows): Macro F1: {test_metrics['Macro F1']:.4f} | Accuracy: {test_metrics['Accuracy']:.4f}", flush=True)

    # Free best model
    del best_model
    in_memory_models.clear()
    gc.collect()

    # Fix: derive exact val_row_count from total evaluated samples, not summing averages
    val_row_count = int(val_results[best_model_name].get("total_samples", sum(val_results[best_model_name]["Per Class"][c]["support"] for c in expected_classes if c in val_results[best_model_name]["Per Class"])))

    # 8. Generate Metadata & Final Selection Report
    final_selection_report = {
        "dataset": spec_name,
        "best_model": best_model_name,
        "model_path": best_model_path,
        "selection_metric": "Validation Macro F1",
        "validation_macro_f1": best_val_f1,
        "test_row_count": test_row_count,
        "test_metrics": test_metrics,
        "comparison": {m: val_results[m]["Macro F1"] for m in val_results},
        "sampling_details": sampling_meta
    }
    if threshold_multipliers:
        final_selection_report["threshold_multipliers"] = threshold_multipliers

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
        "training_row_count": train_row_count,
        "validation_row_count": val_row_count,
        "test_row_count": test_row_count,
        "preprocessing_artifact_path": preproc_path,
        "model_path": best_model_path,
        "random_seed": SEED,
        "training_duration_seconds": training_times.get(best_model_name, 0.0),
        "validation_metrics": val_results[best_model_name],
        "final_test_metrics": test_metrics,
        "test_metrics": test_metrics,
        "sampling_details": sampling_meta
    }
    if threshold_multipliers:
        metadata["threshold_multipliers"] = threshold_multipliers

    if save_artifacts:
        with open(os.path.join(model_dir, "specialist_metadata.json"), "w") as f:
            json.dump(metadata, f, indent=4)
        if should_update_checkpoints:
            update_checkpoint(spec_name, "best_model", best_model_name)
            update_checkpoint(spec_name, "status", "completed")
        print(f"Artifacts and metadata saved under {model_dir}/ and {report_dir}/", flush=True)

    return metadata

def train_all_specialists(
    config: dict,
    max_train_samples: int = None,
    smoke_test: bool = False,
    target_dataset: str = None,
    selected_model: str = None,
    force_retrain: bool = False,
    evaluate_only: bool = False,
    use_optimized: bool = False,
    sync_preprocessor: bool = False,
    save_artifacts: bool = True,
    model_dir: str = None,
    report_dir: str = None
):
    """Run training across all configured specialist models."""
    if target_dataset:
        raw_items = [item.strip() for item in target_dataset.split(",") if item.strip()]
        datasets_to_train = [resolve_specialist_name(item) for item in raw_items]
    else:
        datasets_to_train = list(SPECIALIST_SPECS.keys())

    all_metadata = {}

    for canonical_name in datasets_to_train:
        meta = train_specialist(
            spec_name=canonical_name,
            config=config,
            max_train_samples=max_train_samples,
            smoke_test=smoke_test,
            selected_model=selected_model,
            force_retrain=force_retrain,
            evaluate_only=evaluate_only,
            use_optimized=use_optimized,
            sync_preprocessor=sync_preprocessor,
            save_artifacts=save_artifacts,
            model_dir=model_dir,
            report_dir=report_dir
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
                        help="Train specific specialist dataset(s), comma-separated (e.g. IDS2018, CICIoT2023, ARP, 5G, DNS).")
    parser.add_argument("--model", type=str, default=None,
                        help="Train a specific model only (DecisionTree, RandomForest, XGBoost, HistGradientBoosting, ExtraTrees, dt, rf, xgb, hgb, et).")
    parser.add_argument("--max-train-samples", type=int, default=None,
                        help="Maximum training rows (uses stratified minority-preserving sampling if exceeded).")
    parser.add_argument("--force", "--force-retrain", action="store_true", dest="force_retrain",
                        help="Force retraining models even if checkpoints indicate completion.")
    parser.add_argument("--evaluate-only", "--eval-only", action="store_true", dest="evaluate_only",
                        help="Evaluate existing trained models and regenerate reports without retraining.")
    parser.add_argument("--optimized", action="store_true", dest="use_optimized",
                        help="Evaluate the progressive optimizer's saved finalist model for IDS2018 or CICIoT2023.")
    parser.add_argument("--sync-preprocessor", action="store_true", dest="sync_preprocessor",
                        help="Force re-fitting SpecialistPreprocessor on full train.parquet to guarantee exact preprocessing contract.")
    parser.add_argument("--optimize", action="store_true", dest="optimize",
                        help="Run validation-only optimization suite for IDS2018 specialist.")
    parser.add_argument("--screening-samples", type=int, default=None,
                        help="Stage A screening sample size for optimization (default 500,000).")
    parser.add_argument("--top-k", type=int, default=2,
                        help="Number of Stage A finalists to train on full dataset in Stage B.")
    parser.add_argument("--stage-a-only", "--skip-stage-b", action="store_true", dest="stage_a_only",
                        help="Run Stage A screening only.")
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

    if args.optimize:
        norm_spec = resolve_specialist_name(args.dataset) if args.dataset else "IDS2018"
        if norm_spec == "CICIoT2023":
            from utils.optimize_ciciot2023 import run_ciciot2023_optimization
            run_ciciot2023_optimization(
                config=config,
                smoke_test=args.smoke_test,
                screening_samples=args.screening_samples or max_samples,
                top_k=args.top_k,
                stage_a_only=args.stage_a_only,
                force=args.force_retrain
            )
        elif norm_spec == "IDS2018":
            from utils.optimize_ids2018 import run_ids2018_optimization
            run_ids2018_optimization(
                config=config,
                smoke_test=args.smoke_test,
                screening_samples=args.screening_samples or max_samples,
                top_k=args.top_k,
                stage_a_only=args.stage_a_only,
                force=args.force_retrain
            )
        else:
            raise ValueError(f"Progressive optimization is not implemented for specialist '{norm_spec}'. Available: ['IDS2018', 'CICIoT2023']")
        return

    train_all_specialists(
        config=config,
        max_train_samples=max_samples,
        smoke_test=args.smoke_test,
        target_dataset=args.dataset,
        selected_model=args.model,
        force_retrain=args.force_retrain,
        evaluate_only=args.evaluate_only,
        use_optimized=args.use_optimized,
        sync_preprocessor=args.sync_preprocessor
    )

if __name__ == "__main__":
    main()
