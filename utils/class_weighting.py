import numpy as np

def compute_specialist_class_weights(
    y: np.ndarray,
    strategy: str = "sqrt_balanced",
    max_weight: float = 25.0,
    beta: float = 0.999
) -> dict:
    """Compute per-class weights for imbalanced tabular network flow datasets.
    
    Strategies:
    - 'unweighted': Natural empirical frequency prior (w_c = 1.0).
    - 'balanced': Standard inverse class frequency N / (K * N_c).
    - 'sqrt_balanced': Square-root dampening sqrt(N / (K * N_c)), preventing
      extreme penalty ratios (e.g. 5500:1) that trigger massive false positive spikes.
    - 'capped_balanced': Standard inverse frequency capped at max_weight.
    - 'effective_samples': Class-balanced weights based on effective number of samples:
      (1 - beta) / (1 - beta^N_c).
    """
    classes, counts = np.unique(y, return_counts=True)
    n_samples = len(y)
    n_classes = len(classes)
    
    if strategy == "unweighted" or strategy is None:
        return {int(c): 1.0 for c in classes}
        
    elif strategy == "balanced":
        w_raw = {int(c): float(n_samples / (n_classes * cnt)) for c, cnt in zip(classes, counts)}
        return w_raw
        
    elif strategy == "sqrt_balanced":
        # Sqrt dampening: softens severe penalties while maintaining minority preference
        raw_inv = {int(c): np.sqrt(n_samples / (n_classes * cnt)) for c, cnt in zip(classes, counts)}
        # Normalize so mean weight is 1.0
        mean_w = np.mean(list(raw_inv.values()))
        return {c: float(w / mean_w) for c, w in raw_inv.items()}
        
    elif strategy == "capped_balanced":
        # Standard balanced capped at max_weight
        w_dict = {}
        for c, cnt in zip(classes, counts):
            raw = float(n_samples / (n_classes * cnt))
            w_dict[int(c)] = float(min(raw, max_weight))
        return w_dict
        
    elif strategy == "effective_samples":
        # Effective number of samples: Cui et al., CVPR 2019
        eff_weights = {}
        for c, cnt in zip(classes, counts):
            eff_num = 1.0 - (beta ** cnt)
            eff_weights[int(c)] = (1.0 - beta) / max(eff_num, 1e-8)
        mean_eff = np.mean(list(eff_weights.values()))
        return {c: float(w / mean_eff) for c, w in eff_weights.items()}
        
    else:
        raise ValueError(f"Unknown class weighting strategy: {strategy}")

def compute_specialist_sample_weights(
    y: np.ndarray,
    strategy: str = "sqrt_balanced",
    max_weight: float = 25.0
) -> np.ndarray:
    """Compute per-sample weight vector for model fitting."""
    w_dict = compute_specialist_class_weights(y, strategy=strategy, max_weight=max_weight)
    weights = np.array([w_dict[int(label)] for label in y], dtype=np.float32)
    return weights
