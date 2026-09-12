import os
import numpy as np
import pandas as pd
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID, ID_TO_CLASS

__all__ = [
    "SPECIALIST_CLASSES",
    "evaluate_dataset_streamed",
    "evaluate_model",
    "predict_batched",
    "predict_proba_batched",
    "evaluate_predictions",
]

SPECIALIST_CLASSES = {
    "IDS2018": [
        "Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"
    ],
    "CICIoT2023": [
        "Benign", "DDoS", "DoS", "Botnet", "Infiltration",
        "Brute Force", "Web Attack", "DNS Spoofing", "Recon / Port Scan", "MITM"
    ],
    "ARP_Spoofing": ["Benign", "ARP Spoofing", "DoS"],
    "IP_Spoofing": ["Benign", "IP Spoofing"],
    "DNS_Tunneling": ["Benign", "DNS Tunneling"],
}

def predict_batched(model, X: np.ndarray, batch_size: int = 100000) -> np.ndarray:
    """Perform memory-safe batched model prediction.

    Prevents allocating massive intermediate arrays when predicting
    on million-row validation or test sets.
    """
    n_samples = len(X)
    if n_samples <= batch_size:
        return np.asarray(model.predict(X))

    predictions = []
    for start_idx in range(0, n_samples, batch_size):
        end_idx = min(start_idx + batch_size, n_samples)
        batch_pred = np.asarray(model.predict(X[start_idx:end_idx]))
        predictions.append(batch_pred)

    return np.concatenate(predictions)

def predict_proba_batched(model, X: np.ndarray, batch_size: int = 100000) -> np.ndarray:
    """Perform memory-safe batched model probability prediction."""
    if not hasattr(model, "predict_proba"):
        return None
    n_samples = len(X)
    if n_samples <= batch_size:
        return np.asarray(model.predict_proba(X))

    probas = []
    for start_idx in range(0, n_samples, batch_size):
        end_idx = min(start_idx + batch_size, n_samples)
        batch_proba = np.asarray(model.predict_proba(X[start_idx:end_idx]))
        probas.append(batch_proba)

    return np.vstack(probas)

def evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray, class_names: list) -> dict:
    """Compute comprehensive evaluation metrics for specialist models.

    Guarantees:
    - y_true and y_pred use identical class indices [0 .. len(class_names)-1].
    - Confusion matrix row i is true class_names[i], column j is pred class_names[j].
    - Per-class metrics strictly derive from the corresponding row/col of the confusion matrix.
    - Total support equals exact total samples evaluated.
    """
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    n_classes = len(class_names)
    total_samples = len(y_true)

    acc = float(np.mean(y_true == y_pred)) if total_samples > 0 else 0.0

    per_class = {}
    precisions = []
    recalls = []
    f1s = []
    supports = []

    cm = np.zeros((n_classes, n_classes), dtype=int)

    for i in range(n_classes):
        for j in range(n_classes):
            cm[i, j] = int(np.sum((y_true == i) & (y_pred == j)))

    for k in range(n_classes):
        tp = int(cm[k, k])
        fp = int(np.sum(cm[:, k]) - tp)
        fn = int(np.sum(cm[k, :]) - tp)
        support = int(np.sum(cm[k, :]))

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)
        supports.append(support)

        name = class_names[k] if k < len(class_names) else str(k)
        per_class[name] = {
            "precision": prec,
            "recall": rec,
            "f1-score": f1,
            "support": support
        }

    macro_p = float(np.mean(precisions)) if precisions else 0.0
    macro_r = float(np.mean(recalls)) if recalls else 0.0
    macro_f1 = float(np.mean(f1s)) if f1s else 0.0

    tot_support = sum(supports)
    if tot_support > 0:
        weighted_p = float(sum(p * s for p, s in zip(precisions, supports)) / tot_support)
        weighted_r = float(sum(r * s for r, s in zip(recalls, supports)) / tot_support)
        weighted_f1 = float(sum(f * s for f, s in zip(f1s, supports)) / tot_support)
    else:
        weighted_p = macro_p
        weighted_r = macro_r
        weighted_f1 = macro_f1

    per_class["accuracy"] = acc
    per_class["macro avg"] = {
        "precision": macro_p,
        "recall": macro_r,
        "f1-score": macro_f1,
        "support": tot_support
    }
    per_class["weighted avg"] = {
        "precision": weighted_p,
        "recall": weighted_r,
        "f1-score": weighted_f1,
        "support": tot_support
    }

    # Named confusion matrix dictionary to make indexing unambiguous
    cm_dict = {}
    for i, true_name in enumerate(class_names):
        cm_dict[true_name] = {}
        for j, pred_name in enumerate(class_names):
            cm_dict[true_name][pred_name] = int(cm[i, j])

    return {
        "Accuracy": acc,
        "Macro Precision": macro_p,
        "Macro Recall": macro_r,
        "Macro F1": macro_f1,
        "Weighted F1": weighted_f1,
        "Per Class": per_class,
        "Confusion Matrix": cm.tolist(),
        "confusion_matrix_dict": cm_dict,
        "confusion_matrix_labels": list(class_names),
        "class_order": list(class_names),
        "total_samples": int(tot_support)
    }

def evaluate_dataset_streamed(
    model,
    data_source,
    preprocessor,
    expected_classes: list = None,
    batch_size: int = 100000,
    **kwargs
) -> dict:
    """Evaluate a fitted model on a dataset source without materializing all features in memory.

    Enforces explicit canonical class ordering to prevent label permutation bugs.
    """
    if expected_classes is None:
        expected_classes = kwargs.get("class_names")

    # Resolve target class ordering explicitly
    if expected_classes is not None:
        target_class_order = list(expected_classes)
    elif hasattr(preprocessor, "dataset_name") and preprocessor.dataset_name in SPECIALIST_CLASSES:
        target_class_order = list(SPECIALIST_CLASSES[preprocessor.dataset_name])
    elif hasattr(preprocessor, "expected_classes") and preprocessor.expected_classes is not None:
        target_class_order = list(preprocessor.expected_classes)
    elif hasattr(preprocessor, "classes_") and preprocessor.classes_ is not None:
        target_class_order = list(preprocessor.classes_)
    else:
        raise ValueError("Target class order must be provided to evaluate_dataset_streamed.")

    # Build remap vector: preprocessor local ID -> target_class_order index
    if hasattr(preprocessor, "id_to_local_label") and preprocessor.id_to_local_label:
        max_id = max(preprocessor.id_to_local_label.keys())
        remap_vec = np.zeros(max_id + 1, dtype=np.int64)
        for local_id, name in preprocessor.id_to_local_label.items():
            if name in target_class_order:
                remap_vec[local_id] = target_class_order.index(name)
            else:
                remap_vec[local_id] = local_id

        def map_to_target(y_arr):
            y_arr = np.asarray(y_arr, dtype=np.int64)
            return remap_vec[y_arr]
    else:
        def map_to_target(y_arr):
            return np.asarray(y_arr, dtype=np.int64)

    all_y_true = []
    all_y_pred = []

    if isinstance(data_source, (str, os.PathLike)):
        file_path = str(data_source)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Evaluation data source Parquet file not found: {file_path}")

        try:
            import pyarrow.parquet as pq
            parquet_file = pq.ParquetFile(file_path)
            for batch in parquet_file.iter_batches(batch_size=batch_size):
                batch_df = batch.to_pandas()
                X_batch = preprocessor.transform_features(batch_df)
                y_batch = preprocessor.transform_labels(batch_df)
                y_pred_batch = model.predict(X_batch)
                all_y_true.append(map_to_target(y_batch))
                all_y_pred.append(map_to_target(y_pred_batch))
                del batch_df, X_batch, y_batch, y_pred_batch
        except ImportError:
            # Safe fallback if pyarrow iter_batches is not supported
            full_df = pd.read_parquet(file_path)
            return evaluate_dataset_streamed(
                model=model,
                data_source=full_df,
                preprocessor=preprocessor,
                expected_classes=target_class_order,
                batch_size=batch_size
            )

    elif isinstance(data_source, pd.DataFrame):
        n_rows = len(data_source)
        for start_idx in range(0, n_rows, batch_size):
            end_idx = min(start_idx + batch_size, n_rows)
            chunk = data_source.iloc[start_idx:end_idx]
            X_batch = preprocessor.transform_features(chunk)
            y_batch = preprocessor.transform_labels(chunk)
            y_pred_batch = model.predict(X_batch)
            all_y_true.append(map_to_target(y_batch))
            all_y_pred.append(map_to_target(y_pred_batch))
            del chunk, X_batch, y_batch, y_pred_batch

    else:
        raise TypeError(f"Unsupported data_source type for evaluation: {type(data_source)}")

    if not all_y_true:
        metrics = evaluate_predictions(np.array([], dtype=np.int64), np.array([], dtype=np.int64), target_class_order)
    else:
        y_true = np.concatenate(all_y_true)
        y_pred = np.concatenate(all_y_pred)
        metrics = evaluate_predictions(y_true, y_pred, target_class_order)

    # Expose canonical class taxonomy mapping (0 to 12)
    metrics["canonical_mapping"] = {
        cls_name: int(CLASS_TO_ID[cls_name])
        for cls_name in target_class_order
        if cls_name in CLASS_TO_ID
    }

    return metrics

def evaluate_model(
    model,
    X,
    y_true,
    class_names: list = None,
    batch_size: int = 100000,
    **kwargs
) -> dict:
    """Evaluate a fitted model on given features and true labels using batched inference.

    Supports both:
    1. Pre-transformed arrays (X: np.ndarray, y_true: np.ndarray)
    2. Streamed data sources (X: str/PathLike or DataFrame, y_true: SpecialistPreprocessor)
    """
    if class_names is None:
        class_names = kwargs.get("expected_classes")

    if isinstance(X, (str, os.PathLike, object)) and hasattr(y_true, "transform_features"):
        return evaluate_dataset_streamed(
            model=model,
            data_source=X,
            preprocessor=y_true,
            expected_classes=class_names,
            batch_size=batch_size
        )
    y_pred = predict_batched(model, X, batch_size=batch_size)
    return evaluate_predictions(y_true, y_pred, class_names)
