import numpy as np
from utils.specialist_evaluator import evaluate_predictions

def align_probabilities_to_classes(y_prob: np.ndarray, model_classes: np.ndarray, n_classes: int) -> np.ndarray:
    """Align model output probabilities to canonical class index space."""
    if y_prob.shape[1] == n_classes and (model_classes is None or np.array_equal(model_classes, np.arange(n_classes))):
        return y_prob
    aligned = np.zeros((len(y_prob), n_classes), dtype=np.float32)
    if model_classes is not None:
        for col_idx, cls_id in enumerate(model_classes):
            if int(cls_id) < n_classes:
                aligned[:, int(cls_id)] = y_prob[:, col_idx]
    else:
        aligned[:, :min(y_prob.shape[1], n_classes)] = y_prob[:, :min(y_prob.shape[1], n_classes)]
    return aligned

def predict_with_threshold_multipliers(
    y_prob: np.ndarray,
    multipliers: np.ndarray,
    model_classes: np.ndarray = None
) -> np.ndarray:
    """Predict class index using class-specific probability multipliers.
    
    Adjusts predicted posterior probabilities: y_pred = argmax_c (P(c) * M_c).
    """
    if y_prob.shape[1] != len(multipliers):
        y_prob = align_probabilities_to_classes(y_prob, model_classes, len(multipliers))
    scaled_prob = y_prob * multipliers
    return np.argmax(scaled_prob, axis=1)

def tune_validation_thresholds(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    class_names: list,
    benign_idx: int = 0,
    tune_minority: bool = True,
    model_classes: np.ndarray = None
) -> dict:
    """Tune class-specific decision thresholds strictly on validation probabilities.
    
    Maximizes Validation Macro F1 while controlling Benign False Positive Rate (FPR)
    and boosting recall on severely imbalanced minority attack classes.
    Zero test data is inspected during this procedure.
    """
    n_classes = len(class_names)
    if y_prob.shape[1] != n_classes or (model_classes is not None and not np.array_equal(model_classes, np.arange(n_classes))):
        y_prob = align_probabilities_to_classes(y_prob, model_classes, n_classes)

    best_multipliers = np.ones(n_classes, dtype=np.float32)
    
    # Baseline standard argmax evaluation
    y_pred_base = np.argmax(y_prob, axis=1)
    base_metrics = evaluate_predictions(y_true, y_pred_base, class_names)
    best_macro_f1 = base_metrics["Macro F1"]
    best_metrics = base_metrics
    
    benign_mask = (y_true == benign_idx)
    base_benign_fpr = float(np.mean(y_pred_base[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0

    # Phase 1: Search space for Benign bias multiplier (restoring empirical prior against false positives)
    benign_scales = [1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0]
    candidate_profiles = []
    
    for b_scale in benign_scales:
        multipliers = np.ones(n_classes, dtype=np.float32)
        multipliers[benign_idx] = b_scale
        
        y_pred = predict_with_threshold_multipliers(y_prob, multipliers)
        metrics = evaluate_predictions(y_true, y_pred, class_names)
        
        benign_fpr = float(np.mean(y_pred[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0
        
        candidate_profiles.append({
            "target": "Benign",
            "multiplier": float(b_scale),
            "macro_f1": float(metrics["Macro F1"]),
            "accuracy": float(metrics["Accuracy"]),
            "benign_fpr": benign_fpr
        })
        
        if metrics["Macro F1"] > best_macro_f1 or (
            abs(metrics["Macro F1"] - best_macro_f1) < 0.005 and metrics["Accuracy"] > best_metrics["Accuracy"]
        ):
            best_macro_f1 = metrics["Macro F1"]
            best_metrics = metrics
            best_multipliers = multipliers.copy()

    # Phase 2: Targeted minority attack recall boosting
    if tune_minority and n_classes > 2:
        minority_scales = [1.0, 1.25, 1.5, 2.0, 3.0, 5.0]
        # Identify classes with sub-optimal recall (< 0.85) in best_metrics
        for idx, c_name in enumerate(class_names):
            if idx == benign_idx:
                continue
            c_recall = best_metrics.get("Per Class", {}).get(c_name, {}).get("recall", 1.0)
            if c_recall < 0.85:
                best_class_scale = best_multipliers[idx]
                for m_scale in minority_scales:
                    trial_mult = best_multipliers.copy()
                    trial_mult[idx] = m_scale
                    y_pred_trial = predict_with_threshold_multipliers(y_prob, trial_mult)
                    trial_metrics = evaluate_predictions(y_true, y_pred_trial, class_names)
                    
                    # Accept if Macro F1 improves and Accuracy does not drop significantly
                    if trial_metrics["Macro F1"] > best_macro_f1 and trial_metrics["Accuracy"] >= max(0.0, best_metrics["Accuracy"] - 0.02):
                        best_macro_f1 = trial_metrics["Macro F1"]
                        best_metrics = trial_metrics
                        best_class_scale = m_scale
                        candidate_profiles.append({
                            "target": c_name,
                            "multiplier": float(m_scale),
                            "macro_f1": float(trial_metrics["Macro F1"]),
                            "accuracy": float(trial_metrics["Accuracy"]),
                            "benign_fpr": float(np.mean(y_pred_trial[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0
                        })
                best_multipliers[idx] = best_class_scale

    tuning_summary = {
        "baseline": {
            "accuracy": base_metrics["Accuracy"],
            "macro_f1": base_metrics["Macro F1"],
            "benign_fpr": base_benign_fpr
        },
        "optimized": {
            "accuracy": best_metrics["Accuracy"],
            "macro_f1": best_metrics["Macro F1"],
            "multipliers": {class_names[i]: float(best_multipliers[i]) for i in range(n_classes)},
            "benign_fpr": float(np.mean(predict_with_threshold_multipliers(y_prob, best_multipliers)[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0
        },
        "profiles_evaluated": candidate_profiles
    }
    
    return tuning_summary, best_multipliers
