import os
import sys
import json
import tempfile
import unittest
import numpy as np
import pandas as pd
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID
from utils.specialist_preprocessor import SpecialistPreprocessor
from utils.specialist_evaluator import (
    evaluate_predictions, evaluate_model, evaluate_dataset_streamed, predict_batched
)
from utils.train_models import (
    SPECIALIST_SPECS,
    resolve_specialist_name,
    load_specialist_splits,
    sample_training_data,
    train_specialist,
    get_model_instance,
    DecisionTreeClassifier
)

class TestSpecialistTraining(unittest.TestCase):

    def test_specialist_specs_configuration(self):
        """All 5 specialist datasets must be configured with aliases and valid taxonomy classes."""
        expected_specialists = ["IDS2018", "CICIoT2023", "ARP_Spoofing", "IP_Spoofing", "DNS_Tunneling"]
        for spec in expected_specialists:
            self.assertIn(spec, SPECIALIST_SPECS)
            info = SPECIALIST_SPECS[spec]
            self.assertIn("config_path_key", info)
            self.assertIn("config_class_key", info)
            self.assertIn("split_type", info)
            self.assertIn("description", info)
            self.assertIn("aliases", info)

        # Resolvable aliases
        self.assertEqual(resolve_specialist_name("ids2018"), "IDS2018")
        self.assertEqual(resolve_specialist_name("ciciot"), "CICIoT2023")
        self.assertEqual(resolve_specialist_name("arp"), "ARP_Spoofing")
        self.assertEqual(resolve_specialist_name("5g"), "IP_Spoofing")
        self.assertEqual(resolve_specialist_name("dns"), "DNS_Tunneling")

        with self.assertRaises(ValueError):
            resolve_specialist_name("unknown_specialist")

    def test_preprocessor_excludes_labels_and_identifiers(self):
        """Preprocessor must exclude final_label, raw labels, MAC, and IP columns from feature names."""
        df_train = pd.DataFrame({
            "flow_duration": [10.0, 20.0, 30.0],
            "packet_count": [5, 10, 15],
            "src_mac": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "00:11:22:33:44:55"],
            "dst_ip": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
            "Label": ["Benign", "DDoS", "Benign"],
            "final_label": ["Benign", "DDoS", "Benign"]
        })
        preprocessor = SpecialistPreprocessor(dataset_name="TestSpec")
        X, y = preprocessor.fit_transform(df_train)

        self.assertNotIn("final_label", preprocessor.feature_names_in_)
        self.assertNotIn("Label", preprocessor.feature_names_in_)
        self.assertNotIn("src_mac", preprocessor.feature_names_in_)
        self.assertNotIn("dst_ip", preprocessor.feature_names_in_)
        self.assertListEqual(preprocessor.feature_names_in_, ["flow_duration", "packet_count"])
        self.assertEqual(X.shape[1], 2)
        self.assertEqual(len(y), 3)

    def test_preprocessor_no_data_leakage(self):
        """Preprocessor fit statistics (median, scaler) must come strictly from train."""
        df_train = pd.DataFrame({
            "feature_a": [10.0, 20.0, np.nan, 30.0],
            "final_label": ["Benign", "DoS", "Benign", "DoS"]
        })
        df_test = pd.DataFrame({
            "feature_a": [np.nan, 100.0],
            "final_label": ["Benign", "DoS"]
        })
        preprocessor = SpecialistPreprocessor(dataset_name="TestSpec", scale=False)
        X_train, _ = preprocessor.fit_transform(df_train)
        X_test, _ = preprocessor.transform(df_test)

        # Median of [10.0, 20.0, 30.0] is 20.0
        # In test set, NaN must be imputed with train median (20.0), NOT influenced by 100.0
        self.assertEqual(X_test[0, 0], 20.0)

    def test_local_to_canonical_mapping(self):
        """Local prediction class IDs must correctly map to canonical 13-class taxonomy IDs."""
        classes = ["Benign", "ARP Spoofing", "DoS"]
        df_train = pd.DataFrame({
            "feat": [1.0, 2.0, 3.0],
            "final_label": classes
        })
        preprocessor = SpecialistPreprocessor(dataset_name="ARP_Spoofing")
        preprocessor.fit(df_train)

        # Verify local class mapping
        self.assertEqual(preprocessor.classes_, ["ARP Spoofing", "Benign", "DoS"])
        local_ids = np.array([0, 1, 2]) # corresponding to ["ARP Spoofing", "Benign", "DoS"]
        canonical_ids = preprocessor.local_to_canonical_ids(local_ids)

        self.assertEqual(canonical_ids[0], CLASS_TO_ID["ARP Spoofing"]) # 9
        self.assertEqual(canonical_ids[1], CLASS_TO_ID["Benign"])       # 0
        self.assertEqual(canonical_ids[2], CLASS_TO_ID["DoS"])          # 2

    def test_load_specialist_splits_deterministic_derivation(self):
        """Test derivation of validation split for 2-way splits (ARP / IP Spoofing)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create synthetic train and test files
            train_df = pd.DataFrame({
                "feat1": np.random.randn(100),
                "final_label": ["Benign"] * 50 + ["ARP Spoofing"] * 50
            })
            test_df = pd.DataFrame({
                "feat1": np.random.randn(30),
                "final_label": ["Benign"] * 15 + ["ARP Spoofing"] * 15
            })
            train_df.to_parquet(os.path.join(tmpdir, "train.parquet"), index=False)
            test_df.to_parquet(os.path.join(tmpdir, "test.parquet"), index=False)

            # Load splits
            train, val, test = load_specialist_splits(tmpdir, split_type="train_test", random_seed=42)

            # Test split should be completely untouched
            self.assertEqual(len(test), 30)
            self.assertTrue(np.allclose(test["feat1"].values, test_df["feat1"].values))

            # Train and Val should be derived from train_df (80/20)
            self.assertEqual(len(train), 80)
            self.assertEqual(len(val), 20)
            self.assertEqual(len(train) + len(val), 100)

            # Distribution should be stratified
            self.assertEqual((val["final_label"] == "Benign").sum(), 10)
            self.assertEqual((val["final_label"] == "ARP Spoofing").sum(), 10)

    def test_sampling_minority_preservation(self):
        """sample_training_data must preserve rare minority classes when downsampling."""
        # 1000 rows: 950 Benign, 40 DoS, 10 Botnet
        df = pd.DataFrame({
            "feat": np.random.randn(1000),
            "final_label": ["Benign"] * 950 + ["DoS"] * 40 + ["Botnet"] * 10
        })
        sampled, meta = sample_training_data(df, max_samples=100, random_seed=42)

        self.assertLessEqual(len(sampled), 100)
        self.assertTrue(meta["sampled"])
        # Minority class Botnet (10 instances) should be preserved
        botnet_count = (sampled["final_label"] == "Botnet").sum()
        self.assertGreaterEqual(botnet_count, 1)

    def test_batched_evaluation(self):
        """predict_batched and evaluate_predictions must correctly evaluate batches."""
        X_test = np.random.randn(250, 4)
        y_test = np.array([0] * 150 + [1] * 100)

        model = DecisionTreeClassifier(random_state=42)
        model.fit(X_test, y_test)

        preds = predict_batched(model, X_test, batch_size=50)
        self.assertEqual(len(preds), 250)

        metrics = evaluate_predictions(y_test, preds, class_names=["Benign", "DoS"])
        self.assertIn("Accuracy", metrics)
        self.assertIn("Macro F1", metrics)
        self.assertIn("Per Class", metrics)
        self.assertIn("Confusion Matrix", metrics)

    def test_smoke_test_execution(self):
        """train_specialist smoke test should run cleanly without errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_name = "ARP_Spoofing"
            results = train_specialist(
                spec_name,
                model_names=["DecisionTree"],
                max_train_samples=200,
                smoke_test=True,
                save_artifacts=False
            )
            self.assertIn("best_model", results)
            self.assertEqual(results["best_model"], "DecisionTree")
            self.assertIn("test_metrics", results)
            self.assertIn("Macro F1", results["test_metrics"])

    def test_conservative_model_configurations(self):
        """Model configurations must be conservative to prevent OS kill on Colab CPU/RAM."""
        dt = get_model_instance("DecisionTree", smoke_test=False)
        rf = get_model_instance("RandomForest", smoke_test=False)
        xgb = get_model_instance("XGBoost", smoke_test=False)

        # DecisionTree max_depth bounded
        self.assertTrue(hasattr(dt, "max_depth"))
        self.assertLessEqual(getattr(dt, "max_depth", 15), 15)

        # RandomForest conservative estimators and subsampling
        self.assertLessEqual(getattr(rf, "n_estimators", 30), 50)
        self.assertLessEqual(getattr(rf, "max_depth", 12), 15)
        self.assertLessEqual(getattr(rf, "n_jobs", 1), 2)
        if hasattr(rf, "max_samples"):
            self.assertIsNotNone(rf.max_samples)
            self.assertLessEqual(rf.max_samples, 0.5)

        # XGBoost conservative histogram method and jobs
        self.assertLessEqual(getattr(xgb, "n_estimators", 50), 60)
        self.assertLessEqual(getattr(xgb, "max_depth", 6), 8)
        self.assertLessEqual(getattr(xgb, "n_jobs", 2), 2)
        if hasattr(xgb, "tree_method"):
            self.assertEqual(xgb.tree_method, "hist")

    def test_preprocessor_float32_output(self):
        """Preprocessor must produce float32 feature matrices and int32 labels to halve memory."""
        df = pd.DataFrame({
            "f1": [1.0, 2.0, 3.0, 4.0],
            "f2": [10.0, 20.0, np.nan, 40.0],
            "final_label": ["Benign", "DDoS", "Benign", "DDoS"]
        })
        prep = SpecialistPreprocessor(dataset_name="TestSpec")
        X, y = prep.fit_transform(df)

        self.assertEqual(X.dtype, np.float32)
        self.assertEqual(y.dtype, np.int32)
        self.assertFalse(np.isnan(X).any())

    def test_streamed_dataset_evaluation(self):
        """evaluate_dataset_streamed must evaluate data in memory-safe batches without full duplication."""
        df = pd.DataFrame({
            "f1": np.random.randn(100).astype(np.float32),
            "final_label": ["Benign"] * 50 + ["DDoS"] * 50
        })
        prep = SpecialistPreprocessor(dataset_name="TestSpec")
        prep.fit(df)

        model = DecisionTreeClassifier(random_state=42)
        X, y = prep.transform(df)
        model.fit(X, y)

        metrics = evaluate_dataset_streamed(
            model=model,
            data_source=df,
            preprocessor=prep,
            class_names=["Benign", "DDoS"],
            batch_size=25
        )
        self.assertIn("Accuracy", metrics)
        self.assertIn("Macro F1", metrics)
        self.assertEqual(metrics["Per Class"]["Benign"]["support"], 50)
        self.assertEqual(metrics["Per Class"]["DDoS"]["support"], 50)

    def test_lazy_splits_loading(self):
        """load_specialist_splits with lazy_val_test=True must return file paths for 3-way splits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            df = pd.DataFrame({"f": [1.0, 2.0], "final_label": ["Benign", "DoS"]})
            df.to_parquet(os.path.join(tmpdir, "train.parquet"), index=False)
            df.to_parquet(os.path.join(tmpdir, "val.parquet"), index=False)
            df.to_parquet(os.path.join(tmpdir, "test.parquet"), index=False)

            train, val, test = load_specialist_splits(
                tmpdir, split_type="train_val_test", lazy_val_test=True
            )
            # Train is loaded as DataFrame
            self.assertIsInstance(train, pd.DataFrame)
            # Val and Test are returned as string file paths
            self.assertIsInstance(val, str)
            self.assertIsInstance(test, str)
            self.assertTrue(os.path.exists(val))
            self.assertTrue(os.path.exists(test))

    def test_streamed_evaluator_direct_import_and_parquet_execution(self):
        """Regression test: verify direct import and streamed Parquet batch evaluation."""
        # 1. Direct import verification
        from utils.specialist_evaluator import evaluate_dataset_streamed as streamed_eval

        with tempfile.TemporaryDirectory() as tmpdir:
            # 2. Create small temporary parquet dataset
            parquet_path = os.path.join(tmpdir, "test_eval.parquet")
            df_eval = pd.DataFrame({
                "feature_a": np.linspace(0.0, 10.0, 120, dtype=np.float32),
                "feature_b": np.linspace(10.0, 20.0, 120, dtype=np.float32),
                "final_label": ["Benign"] * 60 + ["DoS"] * 60
            })
            df_eval.to_parquet(parquet_path, index=False)

            # 3. Fit preprocessor on training data
            prep = SpecialistPreprocessor(dataset_name="TestStreamingSpec")
            prep.fit(df_eval)

            # 4. Train a simple decision tree model
            X_train, y_train = prep.transform(df_eval)
            model = DecisionTreeClassifier(random_state=42)
            model.fit(X_train, y_train)

            # 5. Run streamed evaluation on the Parquet file in batches of 25
            metrics = streamed_eval(
                model=model,
                data_source=parquet_path,
                preprocessor=prep,
                expected_classes=["Benign", "DoS"],
                batch_size=25
            )

            # 6. Verify returned metrics structure and values
            expected_keys = [
                "Accuracy", "Macro Precision", "Macro Recall",
                "Macro F1", "Weighted F1", "Per Class", "Confusion Matrix"
            ]
            for key in expected_keys:
                self.assertIn(key, metrics)

            self.assertEqual(metrics["Per Class"]["Benign"]["support"], 60)
            self.assertEqual(metrics["Per Class"]["DoS"]["support"], 60)
            self.assertEqual(len(metrics["Confusion Matrix"]), 2)
            self.assertGreaterEqual(metrics["Macro F1"], 0.0)
            self.assertLessEqual(metrics["Macro F1"], 1.0)

            # 7. Verify canonical taxonomy mapping is present
            self.assertIn("canonical_mapping", metrics)
            self.assertEqual(metrics["canonical_mapping"]["Benign"], 0)
            self.assertEqual(metrics["canonical_mapping"]["DoS"], 2)


if __name__ == "__main__":
    unittest.main()
