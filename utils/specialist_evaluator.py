import numpy as np

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
    
    Uses scikit-learn if available, or equivalent pure NumPy computation.
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
    
    return {
        "Accuracy": acc,
        "Macro Precision": macro_p,
        "Macro Recall": macro_r,
        "Macro F1": macro_f1,
        "Weighted F1": weighted_f1,
        "Per Class": per_class,
        "Confusion Matrix": cm.tolist()
    }

def evaluate_model(model, X: np.ndarray, y_true: np.ndarray, class_names: list, batch_size: int = 100000) -> dict:
    """Evaluate a fitted model on given features and true labels using batched inference."""
    y_pred = predict_batched(model, X, batch_size=batch_size)
    return evaluate_predictions(y_true, y_pred, class_names)
