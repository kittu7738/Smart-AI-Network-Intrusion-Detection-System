import os
import json
import unittest
import numpy as np
import pandas as pd

from utils.class_weighting import (
    compute_specialist_class_weights,
    compute_specialist_sample_weights
)
from utils.model_registry import (
    OPTIMIZATION_CANDIDATE_CONFIGS,
    get_candidate_model
)
from utils.feature_engineering import (
    analyze_features_on_training_data,
    compute_engineered_flow_features,
    apply_feature_representation
)
from utils.threshold_tuner import (
    tune_validation_thresholds,
    predict_with_threshold_multipliers
)
from utils.optimize_ids2018 import run_ids2018_optimization
from utils.train_models import normalize_model_name, get_model_instance

class TestIDS2018Optimization(unittest.TestCase):

    def test_class_weighting_strategies(self):
        """Verify unweighted, balanced, sqrt_balanced, capped_balanced, and effective_samples weighting."""
        # Highly imbalanced labels: 1000 Benign (class 0), 10 Infiltration (class 4), 1 Web Attack (class 6)
        y = np.array([0] * 1000 + [4] * 10 + [6] * 1)
        
        # 1. Unweighted
        w_un = compute_specialist_class_weights(y, strategy="unweighted")
        self.assertEqual(w_un[0], 1.0)
        self.assertEqual(w_un[4], 1.0)
        self.assertEqual(w_un[6], 1.0)

        # 2. Balanced (raw inverse frequency)
        w_bal = compute_specialist_class_weights(y, strategy="balanced")
        # Class 6 should have ~1000x the weight of Class 0
        self.assertGreater(w_bal[6] / w_bal[0], 900.0)

        # 3. Sqrt Balanced (dampened)
        w_sqrt = compute_specialist_class_weights(y, strategy="sqrt_balanced")
        # Ratio should be sqrt(1000) ~ 31.6, vastly dampening the penalty spike
        ratio_sqrt = w_sqrt[6] / w_sqrt[0]
        self.assertLess(ratio_sqrt, 50.0)
        self.assertGreater(ratio_sqrt, 20.0)

        # 4. Capped Balanced
        w_cap = compute_specialist_class_weights(y, strategy="capped_balanced", max_weight=15.0)
        self.assertLessEqual(w_cap[6], 15.0)
        self.assertLessEqual(w_cap[4], 15.0)

        # 5. Sample weights array
        s_weights = compute_specialist_sample_weights(y, strategy="sqrt_balanced")
        self.assertEqual(len(s_weights), len(y))
        self.assertEqual(s_weights.dtype, np.float32)

    def test_candidate_models_instantiation(self):
        """All optimization candidate models must instantiate in standard and smoke modes."""
        candidates = [
            "HistGradientBoosting",
            "XGBoost_Tuned",
            "XGBoost_Unweighted",
            "ExtraTrees",
            "RandomForest_Tuned",
            "DecisionTree_Tuned",
            "DecisionTree_Baseline",
            "RandomForest_Baseline",
            "XGBoost_Baseline"
        ]
        for cand in candidates:
            # Standard mode
            model = get_candidate_model(cand, smoke_test=False)
            self.assertIsNotNone(model)
            # Smoke test mode
            smoke_model = get_candidate_model(cand, smoke_test=True)
            self.assertIsNotNone(smoke_model)

        # Verify alias normalization in train_models
        self.assertEqual(normalize_model_name("hgb"), "HistGradientBoosting")
        self.assertEqual(normalize_model_name("et"), "ExtraTrees")
        hgb_inst = get_model_instance("HistGradientBoosting", smoke_test=True)
        self.assertIsNotNone(hgb_inst)
        et_inst = get_model_instance("ExtraTrees", smoke_test=True)
        self.assertIsNotNone(et_inst)

    def test_feature_analysis_and_engineering(self):
        """Feature analysis must identify constant columns, and engineered features must be leakage-free."""
        df_train = pd.DataFrame({
            "Total Fwd Packets": [10, 20, 30],
            "Total Backward Packets": [5, 10, 15],
            "Fwd Packets Length Total": [100.0, 200.0, 300.0],
            "Bwd Packets Length Total": [50.0, 100.0, 150.0],
            "Fwd Header Length": [40, 80, 120],
            "Flow IAT Max": [1000.0, 2000.0, 3000.0],
            "Flow IAT Min": [100.0, 200.0, 300.0],
            "Bwd PSH Flags": [0, 0, 0], # Constant zero
            "final_label": ["Benign", "DoS", "DDoS"]
        })
        feature_cols = [c for c in df_train.columns if c != "final_label"]
        analysis = analyze_features_on_training_data(df_train, feature_cols)

        self.assertIn("Bwd PSH Flags", analysis["constant_features"])
        self.assertEqual(analysis["total_features"], len(feature_cols))

        # Test leakage-free feature engineering
        df_eng = compute_engineered_flow_features(df_train)
        self.assertIn("fwd_bwd_pkt_ratio", df_eng.columns)
        self.assertIn("bytes_per_fwd_pkt", df_eng.columns)
        self.assertIn("hdr_payload_ratio_fwd", df_eng.columns)
        self.assertIn("flow_iat_spread", df_eng.columns)
        # Verify row-wise values
        self.assertAlmostEqual(df_eng["fwd_bwd_pkt_ratio"].iloc[0], 10 / 6.0)
        self.assertAlmostEqual(df_eng["bytes_per_fwd_pkt"].iloc[0], 100.0 / 11.0)

        # Test curated representation drops constant features
        df_curated = apply_feature_representation(df_train, representation="curated_subset")
        self.assertNotIn("Bwd PSH Flags", df_curated.columns)

    def test_threshold_tuner_validation_only(self):
        """Threshold tuning must calibrate class decisions on validation probabilities to improve metrics."""
        classes = ["Benign", "Infiltration"]
        # Simulated scenario: 100 Benign samples, 20 Infiltration samples
        # Model gives borderline 0.51 probability to Infiltration for 30 Benign samples (false positives)
        np.random.seed(42)
        y_true = np.array([0] * 100 + [1] * 20)
        # Benign probabilities: 70 are confident Benign, 30 have P(Infil)=0.52 (borderline false positive)
        prob_benign = np.vstack([
            np.column_stack([np.full(70, 0.9), np.full(70, 0.1)]),
            np.column_stack([np.full(30, 0.48), np.full(30, 0.52)])
        ])
        # Infiltration probabilities: 20 samples with P(Infil)=0.85
        prob_infil = np.column_stack([np.full(20, 0.15), np.full(20, 0.85)])
        y_prob = np.vstack([prob_benign, prob_infil])

        # Baseline argmax has 30 false positives on Benign
        y_base = np.argmax(y_prob, axis=1)
        base_fp = np.sum((y_true == 0) & (y_base == 1))
        self.assertEqual(base_fp, 30)

        # Tune thresholds
        summary, best_mults = tune_validation_thresholds(y_true, y_prob, classes, benign_idx=0)
        
        # Optimized multipliers must reduce false positives on Benign
        y_opt = predict_with_threshold_multipliers(y_prob, best_mults)
        opt_fp = np.sum((y_true == 0) & (y_opt == 1))
        self.assertLess(opt_fp, base_fp)
        self.assertGreaterEqual(summary["optimized"]["macro_f1"], summary["baseline"]["macro_f1"])

    def test_smoke_optimization_pipeline(self):
        """End-to-end smoke test of IDS2018 optimization orchestrator."""
        from utils.data_preparation import load_config
        config = load_config()

        # Run smoke optimization with small candidate subset for fast execution
        summary = run_ids2018_optimization(
            config=config,
            smoke_test=True,
            candidate_list=["DecisionTree_Tuned", "DecisionTree_Baseline"],
            feature_representations=["all_77", "curated_subset"],
            tune_thresholds_flag=True,
            save_artifacts=True
        )

        self.assertIn("selected_best_model", summary)
        self.assertIn("best_validation_metrics", summary)
        self.assertIn("all_candidates_comparison", summary)
        self.assertIn("recommendations", summary)

        # Verify reports exist and are valid JSON
        opt_report_path = "reports/model_training/IDS2018/optimization/validation_candidates_comparison.json"
        self.assertTrue(os.path.exists(opt_report_path))
        with open(opt_report_path, "r") as f:
            data = json.load(f)
        self.assertEqual(data["dataset"], "IDS2018")

        # Verify no MAC Spoofing in any output
        data_str = json.dumps(data).lower()
        self.assertNotIn("mac spoofing", data_str)

if __name__ == "__main__":
    unittest.main()
