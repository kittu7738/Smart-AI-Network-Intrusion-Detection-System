import os
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
import numpy as np
import pandas as pd
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID, ID_TO_CLASS

class SpecialistPreprocessor:
    """Preprocessor for individual specialist IDS models.
    
    Guarantees:
    1. Fitted ONLY on training data.
    2. 'final_label' is the target and never enters the feature space.
    3. Identifiers such as MAC addresses, IP addresses, raw DNS strings are strictly excluded.
    4. Numeric feature schema and ordering are strictly preserved.
    5. Specialist-local labels map unambiguously to global canonical IDs 0-12.
    """
    
    EXCLUDED_COLUMNS = {
        "final_label", "Label", "label", "label_name", "Label_Name", 
        "hash", "__index_level_0__"
    }

    def __init__(self, dataset_name: str, expected_classes: list = None, scale_features: bool = True, scale: bool = None):
        if scale is not None:
            scale_features = scale
        self.dataset_name = dataset_name
        self.scale_features = scale_features
        self.expected_classes = list(expected_classes) if expected_classes is not None else None
        
        self.local_label_to_id = {}
        self.id_to_local_label = {}
        self.local_id_to_canonical_id = {}
        
        if self.expected_classes is not None:
            self._init_classes(self.expected_classes)
        
        self.feature_names_in_ = None
        self.n_features_in_ = None
        self.medians_ = None
        self.means_ = None
        self.stds_ = None
        self.is_fitted = False

    def _init_classes(self, classes: list):
        self.expected_classes = sorted(list(set(classes)))
        for c in self.expected_classes:
            if c not in CLASS_NAMES:
                raise ValueError(f"Class '{c}' for dataset '{self.dataset_name}' is not in the canonical 13-class taxonomy.")
            if "mac spoofing" in c.lower():
                raise ValueError("MAC Spoofing is permanently excluded from the taxonomy.")
        
        self.classes_ = self.expected_classes
        self.local_label_to_id = {cls_name: idx for idx, cls_name in enumerate(self.expected_classes)}
        self.id_to_local_label = {idx: cls_name for idx, cls_name in enumerate(self.expected_classes)}
        self.local_id_to_canonical_id = {
            idx: CLASS_TO_ID[cls_name] for idx, cls_name in enumerate(self.expected_classes)
        }
        self.class_to_local_id_ = self.local_label_to_id
        self.local_id_to_canonical_ = self.local_id_to_canonical_id

    def identify_feature_columns(self, df: pd.DataFrame) -> list:
        """Explicitly identify valid numeric feature columns, rejecting targets and raw identifiers."""
        features = []
        for col in df.columns:
            if col in self.EXCLUDED_COLUMNS:
                continue
            col_lower = str(col).lower()
            # Reject raw MAC addresses or MAC Spoofing fields
            if "mac" in col_lower:
                continue
            # Reject raw IP addresses
            if "ip" in col_lower and ("src" in col_lower or "dst" in col_lower):
                continue
            # Ensure numeric dtype
            if not pd.api.types.is_numeric_dtype(df[col]):
                continue
            features.append(col)
        return features

    def fit(self, train_df: pd.DataFrame):
        """Fit preprocessing transformers strictly on training data."""
        if self.expected_classes is None:
            if "final_label" in train_df.columns:
                self._init_classes(train_df["final_label"].dropna().unique().tolist())
            else:
                raise ValueError("Cannot infer classes: expected_classes is None and 'final_label' not in DataFrame.")
                
        self.feature_names_in_ = self.identify_feature_columns(train_df)
        self.n_features_in_ = len(self.feature_names_in_)
        
        if self.n_features_in_ == 0:
            raise ValueError(f"No valid numeric feature columns identified for {self.dataset_name}.")
            
        X = train_df[self.feature_names_in_].to_numpy(dtype=np.float64, copy=True)
        # Replace Inf with NaN
        X[np.isinf(X)] = np.nan
        
        # Median imputation (computed solely on train data)
        self.medians_ = np.nanmedian(X, axis=0)
        self.medians_ = np.nan_to_num(self.medians_, nan=0.0)
        
        # Impute
        nan_mask = np.isnan(X)
        X_imp = np.where(nan_mask, self.medians_, X)
        
        if self.scale_features:
            self.means_ = np.mean(X_imp, axis=0)
            self.stds_ = np.std(X_imp, axis=0)
            self.stds_[self.stds_ == 0.0] = 1.0
            self.stds_ = np.nan_to_num(self.stds_, nan=1.0)
        else:
            self.means_ = None
            self.stds_ = None
            
        self.is_fitted = True
        return self

    def transform_features(self, df: pd.DataFrame) -> np.ndarray:
        """Apply fitted preprocessing to features of train, validation, or test sets."""
        if not self.is_fitted:
            raise RuntimeError("SpecialistPreprocessor must be fitted before transforming features.")
            
        missing_features = [f for f in self.feature_names_in_ if f not in df.columns]
        if missing_features:
            raise ValueError(f"DataFrame is missing features learned during fit: {missing_features}")
            
        X = df[self.feature_names_in_].to_numpy(dtype=np.float64, copy=True)
        X[np.isinf(X)] = np.nan
        
        # Apply train medians
        nan_mask = np.isnan(X)
        X_imp = np.where(nan_mask, self.medians_, X)
        
        if self.scale_features and self.means_ is not None:
            X_scaled = (X_imp - self.means_) / self.stds_
            return X_scaled.astype(np.float32)
        return X_imp.astype(np.float32)

    def transform_labels(self, df_or_series) -> np.ndarray:
        """Convert string target labels to local integer IDs."""
        if isinstance(df_or_series, pd.DataFrame):
            if "final_label" not in df_or_series.columns:
                raise ValueError("DataFrame missing target column 'final_label'.")
            labels = df_or_series["final_label"]
        else:
            labels = df_or_series
            
        unknown_labels = set(labels.dropna().unique()) - set(self.local_label_to_id.keys())
        if unknown_labels:
            raise ValueError(f"Found unknown labels for {self.dataset_name}: {unknown_labels}")
            
        y = labels.map(self.local_label_to_id).to_numpy(dtype=np.int64)
        return y

    def fit_transform(self, train_df: pd.DataFrame):
        """Fit and transform training dataframe."""
        self.fit(train_df)
        X = self.transform_features(train_df)
        if "final_label" in train_df.columns:
            y = self.transform_labels(train_df)
            return X, y
        return X

    def transform(self, df: pd.DataFrame):
        """Transform dataframe features (and labels if final_label present)."""
        X = self.transform_features(df)
        if "final_label" in df.columns:
            y = self.transform_labels(df)
            return X, y
        return X

    def local_to_canonical_ids(self, y_local: np.ndarray) -> np.ndarray:
        """Map local specialist predictions/IDs to global canonical 0-12 IDs."""
        return np.array([self.local_id_to_canonical_id[int(val)] for val in y_local], dtype=np.int64)

    def local_to_class_names(self, y_local: np.ndarray) -> list:
        """Map local IDs back to canonical class name strings."""
        return [self.id_to_local_label[int(val)] for val in y_local]

    def save(self, filepath: str) -> str:
        """Save fitted preprocessor artifact."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        joblib.dump(self, filepath)
        return filepath

    @staticmethod
    def load(filepath: str) -> "SpecialistPreprocessor":
        """Load saved preprocessor artifact."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Preprocessor artifact not found at {filepath}")
        return joblib.load(filepath)
