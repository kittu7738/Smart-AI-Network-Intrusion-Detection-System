import numpy as np

try:
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier
    from xgboost import XGBClassifier
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
            return self

        def predict(self, X):
            return np.full(len(X), self.majority_, dtype=int)

        def predict_proba(self, X):
            p = np.zeros((len(X), len(self.classes_) if self.classes_ is not None else 1), dtype=np.float32)
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

SEED = 42

OPTIMIZATION_CANDIDATE_CONFIGS = {
    # 1. Advanced Histogram Gradient Boosting (Fast, 256-bin histogram, early stopping)
    "HistGradientBoosting": {
        "class": HistGradientBoostingClassifier,
        "params": {
            "max_iter": 60,
            "max_leaf_nodes": 31,
            "min_samples_leaf": 50,
            "learning_rate": 0.1,
            "early_stopping": True,
            "validation_fraction": 0.1,
            "n_iter_no_change": 5,
            "random_state": SEED
        },
        "smoke_params": {
            "max_iter": 3,
            "max_leaf_nodes": 7,
            "min_samples_leaf": 2,
            "random_state": SEED
        },
        "supports_sample_weight": True,
        "default_weighting": "sqrt_balanced",
        "description": "Scikit-Learn native 256-bin histogram gradient boosting with early stopping (max_iter=60)"
    },
    
    # 2. Tuned XGBoost with histogram binning
    "XGBoost_Tuned": {
        "class": XGBClassifier,
        "params": {
            "n_estimators": 80,
            "max_depth": 7,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "tree_method": "hist",
            "eval_metric": "mlogloss",
            "n_jobs": 2,
            "random_state": SEED
        },
        "smoke_params": {
            "n_estimators": 3,
            "max_depth": 3,
            "eval_metric": "mlogloss",
            "n_jobs": 1,
            "random_state": SEED
        },
        "supports_sample_weight": True,
        "default_weighting": "sqrt_balanced",
        "description": "Fast histogram XGBoost (depth=7, 80 trees) with feature and row subsampling"
    },

    # 3. Tuned XGBoost Unweighted (Natural Prior)
    "XGBoost_Unweighted": {
        "class": XGBClassifier,
        "params": {
            "n_estimators": 80,
            "max_depth": 7,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "tree_method": "hist",
            "eval_metric": "mlogloss",
            "n_jobs": 2,
            "random_state": SEED
        },
        "smoke_params": {
            "n_estimators": 3,
            "max_depth": 3,
            "eval_metric": "mlogloss",
            "n_jobs": 1,
            "random_state": SEED
        },
        "supports_sample_weight": False,
        "default_weighting": "unweighted",
        "description": "XGBoost on empirical traffic frequencies to prevent Benign false positives"
    },
    
    # 4. ExtraTrees Classifier
    "ExtraTrees": {
        "class": ExtraTreesClassifier,
        "params": {
            "n_estimators": 40,
            "max_depth": 18,
            "min_samples_leaf": 5,
            "max_features": "sqrt",
            "n_jobs": 2,
            "random_state": SEED
        },
        "smoke_params": {
            "n_estimators": 3,
            "max_depth": 3,
            "n_jobs": 1,
            "random_state": SEED
        },
        "supports_sample_weight": True,
        "default_weighting": "sqrt_balanced",
        "description": "Extremely Randomized Trees with randomized thresholds (40 trees, depth=18)"
    },
    
    # 5. Tuned Random Forest
    "RandomForest_Tuned": {
        "class": RandomForestClassifier,
        "params": {
            "n_estimators": 40,
            "max_depth": 18,
            "min_samples_leaf": 5,
            "max_samples": 0.4,
            "max_features": "sqrt",
            "n_jobs": 2,
            "random_state": SEED
        },
        "smoke_params": {
            "n_estimators": 3,
            "max_depth": 3,
            "n_jobs": 1,
            "random_state": SEED
        },
        "supports_sample_weight": True,
        "default_weighting": "sqrt_balanced",
        "description": "Tuned Random Forest (depth=18, 40 trees, 40% subsampling) with moderate weights"
    },

    # 6. Tuned Decision Tree
    "DecisionTree_Tuned": {
        "class": DecisionTreeClassifier,
        "params": {
            "max_depth": 18,
            "min_samples_leaf": 5,
            "random_state": SEED
        },
        "smoke_params": {
            "max_depth": 3,
            "random_state": SEED
        },
        "supports_sample_weight": True,
        "default_weighting": "sqrt_balanced",
        "description": "Tuned single Decision Tree (depth=18) with sqrt class balancing"
    },

    # Baselines for direct comparison
    "DecisionTree_Baseline": {
        "class": DecisionTreeClassifier,
        "params": {
            "max_depth": 15,
            "min_samples_leaf": 5,
            "class_weight": "balanced",
            "random_state": SEED
        },
        "smoke_params": {
            "max_depth": 3,
            "random_state": SEED
        },
        "supports_sample_weight": False,
        "default_weighting": "none",
        "description": "Current production baseline: DecisionTree (depth=15, balanced weights)"
    },

    "RandomForest_Baseline": {
        "class": RandomForestClassifier,
        "params": {
            "n_estimators": 30,
            "max_depth": 12,
            "min_samples_leaf": 10,
            "max_samples": 0.25,
            "class_weight": "balanced",
            "n_jobs": 1,
            "random_state": SEED
        },
        "smoke_params": {
            "n_estimators": 2,
            "max_depth": 3,
            "n_jobs": 1,
            "random_state": SEED
        },
        "supports_sample_weight": False,
        "default_weighting": "none",
        "description": "Current production baseline: RandomForest (depth=12, 30 trees, balanced weights)"
    },

    "XGBoost_Baseline": {
        "class": XGBClassifier,
        "params": {
            "n_estimators": 50,
            "max_depth": 6,
            "learning_rate": 0.1,
            "tree_method": "hist",
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "eval_metric": "mlogloss",
            "n_jobs": 2,
            "random_state": SEED
        },
        "smoke_params": {
            "n_estimators": 2,
            "max_depth": 3,
            "eval_metric": "mlogloss",
            "n_jobs": 1,
            "random_state": SEED
        },
        "supports_sample_weight": True,
        "default_weighting": "balanced",
        "description": "Current production baseline: XGBoost (depth=6, 50 trees, balanced weights)"
    }
}

def get_candidate_model(name: str, smoke_test: bool = False, custom_params: dict = None):
    """Instantiate a configured candidate model."""
    if name not in OPTIMIZATION_CANDIDATE_CONFIGS:
        raise ValueError(f"Unknown optimization candidate '{name}'. Available: {list(OPTIMIZATION_CANDIDATE_CONFIGS.keys())}")
    
    cfg = OPTIMIZATION_CANDIDATE_CONFIGS[name]
    cls = cfg["class"]
    params = cfg["smoke_params"].copy() if smoke_test else cfg["params"].copy()
    
    if custom_params:
        params.update(custom_params)
        
    return cls(**params)
