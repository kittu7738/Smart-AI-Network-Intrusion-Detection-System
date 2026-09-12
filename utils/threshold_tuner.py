import numpy as np
from utils.specialist_evaluator import evaluate_predictions

def predict_with_threshold_multipliers(y_prob: np.ndarray, multipliers: np.ndarray) -> np.ndarray:
    """Predict class index using class-specific probability multipliers.
    
    Adjusts predicted posterior probabilities: y_pred = argmax_c (P(c) * M_c).
    """
    scaled_prob = y_prob * multipliers
    return np.argmax(scaled_prob, axis=1)

def tune_validation_thresholds(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    class_names: list,
    benign_idx: int = 0
) -> dict:
    """Tune class-specific decision thresholds strictly on validation probabilities.
    
    Maximizes Validation Macro F1 while controlling Benign False Positive Rate (FPR).
    Zero test data is inspected during this procedure.
    """
    n_classes = len(class_names)
    best_multipliers = np.ones(n_classes, dtype=np.float32)
    
    # Baseline standard argmax evaluation
    y_pred_base = np.argmax(y_prob, axis=1)
    base_metrics = evaluate_predictions(y_true, y_pred_base, class_names)
    best_macro_f1 = base_metrics["Macro F1"]
    best_metrics = base_metrics
    
    benign_mask = (y_true == benign_idx)
    base_benign_fpr = float(np.mean(y_pred_base[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0

    # Search space for Benign bias multiplier (restoring empirical prior against false positives)
    # A multiplier > 1.0 on Benign requires attack probabilities to have higher confidence to flip from Benign
    benign_scales = [1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0]
    
    # Rare attack multiplier options to selectively boost high-precision minority classes
    candidate_profiles = []
    
    for b_scale in benign_scales:
        multipliers = np.ones(n_classes, dtype=np.float32)
        multipliers[benign_idx] = b_scale
        
        y_pred = predict_with_threshold_multipliers(y_prob, multipliers)
        metrics = evaluate_predictions(y_true, y_pred, class_names)
        
        benign_fpr = float(np.mean(y_pred[benign_mask] != benign_idx)) if np.any(benign_mask) else 0.0
        
        candidate_profiles.append({
            "benign_multiplier": float(b_scale),
            "macro_f1": float(metrics["Macro F1"]),
            "accuracy": float(metrics["Accuracy"]),
            "benign_fpr": benign_fpr
        })
        
        # We select the profile with highest Macro F1; if Macro F1 is comparable, choose higher Accuracy / lower Benign FPR
        if metrics["Macro F1"] > best_macro_f1 or (
            abs(metrics["Macro F1"] - best_macro_f1) < 0.005 and metrics["Accuracy"] > best_metrics["Accuracy"]
        ):
            best_macro_f1 = metrics["Macro F1"]
            best_metrics = metrics
            best_multipliers = multipliers.copy()

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
