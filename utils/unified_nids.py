import os
import json
import numpy as np
import pandas as pd

from utils.taxonomy import (
    CLASS_NAMES,
    CLASS_TO_ID,
    ID_TO_CLASS,
    NUM_CLASSES,
    SPECIALIST_SUB_TAXONOMIES,
    SPECIALIST_LOCAL_TO_CANONICAL,
    SPECIALIST_FEATURE_INDICATORS,
    project_local_to_canonical_probabilities,
    detect_specialist_from_features,
)
from utils.specialist_preprocessor import SpecialistPreprocessor, joblib
from utils.data_preparation import resolve_path, extract_dns_features
from utils.train_models import (
    SPECIALIST_SPECS,
    resolve_specialist_name,
    resolve_model_path,
    load_stored_threshold_multipliers,
)


class UnifiedNIDS:
    """Unified 13-Class Network Intrusion Detection System Inference Engine.

    Coordinates all 5 specialist models and provides end-to-end inference,
    automated schema routing, and normalization into the frozen 13-class taxonomy.

    Guarantees:
    1. Output space is strictly 13 canonical classes (IDs 0 to 12).
    2. Posterior probability vectors always have dimension 13 and sum to 1.0.
    3. Probabilities for classes outside a specialist's sub-taxonomy are strictly 0.0.
    4. MAC Spoofing is permanently excluded and rejected on arrival.
    5. In-memory model caching ensures low-latency serving without repeated disk reads.
    """

    SPECIALIST_NAMES = [
        "IDS2018",
        "CICIoT2023",
        "ARP_Spoofing",
        "IP_Spoofing",
        "DNS_Tunneling"
    ]

    def __init__(self, models_dir: str = None, eager_load: bool = False):
        if models_dir is None:
            self.models_dir = resolve_path("models")
        else:
            self.models_dir = resolve_path(models_dir)

        self._specialists = {}
        if eager_load:
            self.load_all_available_specialists()

    def is_specialist_loaded(self, specialist_name: str) -> bool:
        """Check if a specialist model and preprocessor are already loaded in memory."""
        norm_name = resolve_specialist_name(specialist_name)
        return norm_name in self._specialists

    def register_specialist(
        self,
        specialist_name: str,
        model,
        preprocessor: SpecialistPreprocessor,
        threshold_multipliers: dict = None,
        model_name: str = None,
        model_path: str = None,
    ):
        """Register an in-memory specialist model and preprocessor directly.

        Useful for unit tests, custom deployments, or mock testing.
        """
        norm_name = resolve_specialist_name(specialist_name)
        if norm_name not in self.SPECIALIST_NAMES:
            raise ValueError(f"Unknown specialist '{specialist_name}'. Available: {self.SPECIALIST_NAMES}")

        # Check MAC spoofing exclusion
        if hasattr(preprocessor, "expected_classes"):
            for c in preprocessor.expected_classes:
                if "mac spoofing" in str(c).lower():
                    raise ValueError("MAC Spoofing is permanently excluded from the taxonomy.")

        self._specialists[norm_name] = {
            "model": model,
            "preprocessor": preprocessor,
            "threshold_multipliers": threshold_multipliers,
            "model_name": model_name or getattr(model, "__class__", type(model)).__name__,
            "model_path": model_path or "in-memory",
            "expected_classes": list(preprocessor.expected_classes) if hasattr(preprocessor, "expected_classes") else list(SPECIALIST_SUB_TAXONOMIES[norm_name])
        }

    def load_specialist(self, specialist_name: str, force_reload: bool = False):
        """Load a specialist's production model and preprocessor from disk into memory."""
        norm_name = resolve_specialist_name(specialist_name)
        if norm_name in self._specialists and not force_reload:
            return self._specialists[norm_name]

        spec_dir = os.path.join(self.models_dir, norm_name)
        if not os.path.exists(spec_dir):
            raise FileNotFoundError(f"Specialist directory not found: {spec_dir}")

        # 1. Load Preprocessor (candidate preprocessor takes precedence for tuned models)
        cand_preproc = os.path.join(spec_dir, "candidate_preprocessor.joblib")
        std_preproc = os.path.join(spec_dir, "preprocessor.joblib")

        if os.path.exists(cand_preproc):
            preproc_path = cand_preproc
        elif os.path.exists(std_preproc):
            preproc_path = std_preproc
        else:
            raise FileNotFoundError(f"Preprocessor artifact not found in {spec_dir} (checked candidate and standard)")

        preprocessor = SpecialistPreprocessor.load(preproc_path)

        # 2. Determine best model
        # Check specialist_metadata.json
        meta_path = os.path.join(spec_dir, "specialist_metadata.json")
        best_model_name = None
        threshold_multipliers = None

        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                best_model_name = meta.get("best_model") or meta.get("model_name")
                threshold_multipliers = meta.get("threshold_multipliers")
            except Exception:
                pass

        # Check optimization directory for tuned finalist
        report_opt_dir = resolve_path(os.path.join("reports", "model_training", norm_name, "optimization"))
        if not threshold_multipliers:
            threshold_multipliers = load_stored_threshold_multipliers(norm_name, opt_dir=report_opt_dir)

        if os.path.exists(os.path.join(report_opt_dir, "best_optimized_model.json")):
            try:
                with open(os.path.join(report_opt_dir, "best_optimized_model.json"), "r") as f:
                    opt_data = json.load(f)
                if opt_data.get("model"):
                    best_model_name = opt_data["model"]
            except Exception:
                pass

        # Default fallbacks if metadata not found
        if not best_model_name:
            if norm_name == "IDS2018":
                best_model_name = "candidate_DecisionTree_Tuned" if os.path.exists(os.path.join(spec_dir, "candidate_DecisionTree_Tuned.joblib")) else "DecisionTree"
            elif norm_name == "CICIoT2023":
                best_model_name = "candidate_XGBoost_Tuned" if os.path.exists(os.path.join(spec_dir, "candidate_XGBoost_Tuned.joblib")) else "XGBoost"
            elif norm_name == "DNS_Tunneling":
                best_model_name = "RandomForest" if os.path.exists(os.path.join(spec_dir, "RandomForest.joblib")) else "DecisionTree"
            else:
                best_model_name = "DecisionTree"

        model_path = resolve_model_path(spec_dir, best_model_name)
        if not os.path.exists(model_path):
            # Try alternate standard candidates
            for alt in ["DecisionTree", "RandomForest", "XGBoost"]:
                alt_p = resolve_model_path(spec_dir, alt)
                if os.path.exists(alt_p):
                    model_path = alt_p
                    best_model_name = alt
                    break

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model artifact not found for {norm_name} at {model_path}")

        model = joblib.load(model_path)

        self.register_specialist(
            specialist_name=norm_name,
            model=model,
            preprocessor=preprocessor,
            threshold_multipliers=threshold_multipliers,
            model_name=best_model_name,
            model_path=model_path
        )
        return self._specialists[norm_name]

    def load_all_available_specialists(self):
        """Load all specialists present in models_dir."""
        for name in self.SPECIALIST_NAMES:
            spec_dir = os.path.join(self.models_dir, name)
            if os.path.exists(spec_dir):
                try:
                    self.load_specialist(name)
                except Exception:
                    pass

    def route_traffic(self, df_or_cols, explicit_specialist: str = None) -> str:
        """Route incoming traffic to the appropriate specialist.

        Accepts either a pandas DataFrame/Series, a list of column names, or a dictionary.
        Enforces strict rejection of MAC Spoofing and incompatible schemas.
        """
        if isinstance(df_or_cols, pd.DataFrame):
            columns = list(df_or_cols.columns)
        elif isinstance(df_or_cols, pd.Series):
            columns = list(df_or_cols.index)
        elif isinstance(df_or_cols, dict):
            columns = list(df_or_cols.keys())
        elif isinstance(df_or_cols, (list, tuple, set)):
            columns = list(df_or_cols)
        else:
            raise TypeError(f"Unsupported input type for routing: {type(df_or_cols)}")

        # MAC Spoofing rejection check
        for col in columns:
            col_str = str(col).lower()
            if "mac" in col_str:
                raise ValueError("MAC Spoofing is permanently excluded from the taxonomy.")

        if explicit_specialist and str(explicit_specialist).lower() != "auto":
            target = resolve_specialist_name(explicit_specialist)
            return target

        # Automated schema fingerprinting
        target = detect_specialist_from_features(columns)
        return target

    def predict(self, data, specialist: str = "auto") -> dict:
        """Run unified inference on a single instance or batch of instances.

        Parameters:
            data: dict (single sample), list of dicts, pd.Series, or pd.DataFrame
            specialist: specialist name or "auto" for automated schema routing

        Returns:
            dict for single instance:
                {
                    "specialist": str,
                    "canonical_id": int (0-12),
                    "class_name": str,
                    "confidence": float,
                    "probabilities": list[float] (len=13)
                }
            or list of dicts for multiple instances.
        """
        is_single = False
        if isinstance(data, dict):
            is_single = True
            df = pd.DataFrame([data])
        elif isinstance(data, pd.Series):
            is_single = True
            df = pd.DataFrame([data.to_dict()])
        elif isinstance(data, list):
            if len(data) == 0:
                raise ValueError("Input data list is empty.")
            if isinstance(data[0], dict):
                df = pd.DataFrame(data)
            else:
                raise TypeError(f"Unsupported element in data list: {type(data[0])}")
        elif isinstance(data, pd.DataFrame):
            if len(data) == 0:
                raise ValueError("Input DataFrame is empty.")
            df = data.copy()
            if len(df) == 1:
                is_single = True
        else:
            raise TypeError(f"Unsupported data type for predict: {type(data)}")

        # 1. Determine specialist routing
        target_specialist = self.route_traffic(df, explicit_specialist=specialist)

        # 2. Ensure specialist is loaded
        if not self.is_specialist_loaded(target_specialist):
            self.load_specialist(target_specialist)

        spec_bundle = self._specialists[target_specialist]
        model = spec_bundle["model"]
        preprocessor = spec_bundle["preprocessor"]
        threshold_mult = spec_bundle["threshold_multipliers"]

        # 3. Domain-specific feature extraction if raw columns provided
        if target_specialist == "DNS_Tunneling":
            if "query" in df.columns and "query_length" not in df.columns:
                df = extract_dns_features(df)

        # 4. Feature preprocessing
        X = preprocessor.transform_features(df)

        # 5. Model Inference & Probability Calibration
        n_samples = len(X)
        if hasattr(model, "predict_proba"):
            local_probs = model.predict_proba(X)
            # Handle potential 1D output
            if local_probs.ndim == 1:
                local_probs = local_probs.reshape(1, -1)

            # Apply threshold multipliers if available
            if threshold_mult and hasattr(preprocessor, "id_to_local_label"):
                mult_vec = np.ones(local_probs.shape[1], dtype=np.float32)
                for local_id, cls_name in preprocessor.id_to_local_label.items():
                    if local_id < len(mult_vec) and cls_name in threshold_mult:
                        mult_vec[local_id] = float(threshold_mult[cls_name])
                scaled_probs = local_probs * mult_vec
                row_sums = np.sum(scaled_probs, axis=1, keepdims=True)
                row_sums[row_sums == 0.0] = 1.0
                local_probs = scaled_probs / row_sums

            local_pred_ids = np.argmax(local_probs, axis=1)
            confidences = np.max(local_probs, axis=1)

            # Project into canonical 13-class vector
            if hasattr(preprocessor, "project_probabilities_to_canonical"):
                canonical_probs = preprocessor.project_probabilities_to_canonical(local_probs, num_canonical_classes=NUM_CLASSES)
            else:
                canonical_probs = project_local_to_canonical_probabilities(
                    local_probs, specialist_name=target_specialist, num_canonical_classes=NUM_CLASSES
                )
        else:
            local_pred_ids = np.asarray(model.predict(X), dtype=int)
            confidences = np.ones(n_samples, dtype=np.float32)
            # One-hot encode canonical probabilities
            canonical_probs = np.zeros((n_samples, NUM_CLASSES), dtype=np.float32)
            for idx, loc_id in enumerate(local_pred_ids):
                canon_id = preprocessor.local_id_to_canonical_id.get(int(loc_id), 0)
                canonical_probs[idx, canon_id] = 1.0

        # 6. Map local IDs to canonical class IDs and names
        canonical_ids = np.array([
            preprocessor.local_id_to_canonical_id[int(loc_id)]
            for loc_id in local_pred_ids
        ], dtype=np.int64)
        class_names = [CLASS_NAMES[cid] for cid in canonical_ids]

        # 7. Construct output records
        results = []
        for i in range(n_samples):
            rec = {
                "specialist": target_specialist,
                "canonical_id": int(canonical_ids[i]),
                "class_name": str(class_names[i]),
                "confidence": float(confidences[i]),
                "probabilities": canonical_probs[i].tolist(),
            }
            results.append(rec)

        if is_single and len(results) == 1:
            return results[0]
        return results

    def predict_batch(self, df: pd.DataFrame, specialist: str = "auto") -> dict:
        """Run batch inference on a DataFrame and return arrays for fast vectorization."""
        records = self.predict(df, specialist=specialist)
        if isinstance(records, dict):
            records = [records]

        canonical_ids = np.array([r["canonical_id"] for r in records], dtype=np.int64)
        class_names = [r["class_name"] for r in records]
        confidences = np.array([r["confidence"] for r in records], dtype=np.float32)
        probabilities = np.array([r["probabilities"] for r in records], dtype=np.float32)
        specialist_used = records[0]["specialist"] if records else specialist

        return {
            "specialist": specialist_used,
            "canonical_ids": canonical_ids,
            "class_names": class_names,
            "confidences": confidences,
            "probabilities": probabilities,
        }
