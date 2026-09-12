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
    train_all_specialists,
    get_model_instance,
    update_checkpoint,
    check_status,
    normalize_model_name,
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

    def test_checkpoint_resilience_to_boolean_and_corrupted_schema(self):
        """Checkpoint update and check must survive boolean, string, or corrupted schemas in progress.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ckpt_file = os.path.join(tmpdir, "checkpoints", "progress.json")
            os.makedirs(os.path.dirname(ckpt_file), exist_ok=True)

            # Scenario 1: Exact Colab error - "model_training" is a boolean True
            with open(ckpt_file, "w") as f:
                json.dump({"checkpoints": {}, "model_training": True}, f)

            from unittest.mock import patch
            with patch("utils.train_models.resolve_path", return_value=ckpt_file):
                # Must NOT raise TypeError: argument of type 'bool' is not iterable
                update_checkpoint("IDS2018", "DecisionTree", "running")
                self.assertEqual(check_status("IDS2018", "DecisionTree"), "running")

                update_checkpoint("IDS2018", "DecisionTree", "completed")
                self.assertEqual(check_status("IDS2018", "DecisionTree"), "completed")

                # Verify all 5 specialists and all statuses
                for spec in ["IDS2018", "CICIoT2023", "ARP_Spoofing", "IP_Spoofing", "DNS_Tunneling"]:
                    for st in ["pending", "running", "completed", "failed"]:
                        update_checkpoint(spec, "RandomForest", st)
                        self.assertEqual(check_status(spec, "RandomForest"), st)

            # Scenario 2: "model_training" is a string
            with open(ckpt_file, "w") as f:
                json.dump({"model_training": "corrupted_string_value"}, f)

            with patch("utils.train_models.resolve_path", return_value=ckpt_file):
                update_checkpoint("CICIoT2023", "XGBoost", "running")
                self.assertEqual(check_status("CICIoT2023", "XGBoost"), "running")

            # Scenario 3: progress.json has invalid JSON syntax
            with open(ckpt_file, "w") as f:
                f.write("{invalid_json: true, broken...")

            with patch("utils.train_models.resolve_path", return_value=ckpt_file):
                update_checkpoint("DNS_Tunneling", "DecisionTree", "completed")
                self.assertEqual(check_status("DNS_Tunneling", "DecisionTree"), "completed")

    def test_model_alias_normalization(self):
        """Model aliases (dt, rf, xgb, decision_tree, etc.) must normalize correctly."""
        self.assertEqual(normalize_model_name("dt"), "DecisionTree")
        self.assertEqual(normalize_model_name("decision_tree"), "DecisionTree")
        self.assertEqual(normalize_model_name("decisiontree"), "DecisionTree")
        self.assertEqual(normalize_model_name("DecisionTree"), "DecisionTree")

        self.assertEqual(normalize_model_name("rf"), "RandomForest")
        self.assertEqual(normalize_model_name("random_forest"), "RandomForest")
        self.assertEqual(normalize_model_name("randomforest"), "RandomForest")
        self.assertEqual(normalize_model_name("RandomForest"), "RandomForest")

        self.assertEqual(normalize_model_name("xgb"), "XGBoost")
        self.assertEqual(normalize_model_name("xgboost"), "XGBoost")
        self.assertEqual(normalize_model_name("XGBoost"), "XGBoost")

    def test_cli_dataset_selection(self):
        """train_all_specialists must support single specialist and comma-separated specialist lists."""
        from utils.data_preparation import load_config
        config = load_config()

        # Single specialist selection
        results_single = train_all_specialists(
            config=config,
            smoke_test=True,
            target_dataset="IDS2018",
            selected_model="dt"
        )
        self.assertEqual(list(results_single.keys()), ["IDS2018"])

        # Comma-separated specialist selection
        results_multi = train_all_specialists(
            config=config,
            smoke_test=True,
            target_dataset="ids2018, arp",
            selected_model="dt"
        )
        self.assertEqual(list(results_multi.keys()), ["IDS2018", "ARP_Spoofing"])

    def test_evaluation_metrics_and_row_count_exactness(self):
        """Evaluation metrics must be mathematically consistent and row count must not be inflated."""
        classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
        n_classes = len(classes)
        # Create deterministic synthetic true and pred arrays of 700 samples (100 per class)
        np.random.seed(42)
        y_true = np.repeat(np.arange(n_classes), 100)
        # 80% correct, 20% misclassified to class 0
        y_pred = y_true.copy()
        misclass_idx = np.random.choice(len(y_pred), size=140, replace=False)
        y_pred[misclass_idx] = 0

        metrics = evaluate_predictions(y_true, y_pred, classes)

        # 1. Total samples must equal exact row count (700), NOT 3x inflated
        self.assertEqual(metrics["total_samples"], 700)
        class_supports = [metrics["Per Class"][c]["support"] for c in classes]
        self.assertEqual(sum(class_supports), 700)
        # Verify that macro avg support (700) + weighted avg support (700) + classes (700) is 2100,
        # but total_samples correctly stays 700
        raw_sum_with_averages = sum(
            c["support"] for c in metrics["Per Class"].values() if isinstance(c, dict) and "support" in c
        )
        self.assertEqual(raw_sum_with_averages, 2100)
        self.assertEqual(metrics["total_samples"], 700)

        # 2. Confusion matrix sum must equal total samples
        cm = np.array(metrics["Confusion Matrix"])
        self.assertEqual(cm.shape, (7, 7))
        self.assertEqual(cm.sum(), 700)

        # 3. Precision and recall must strictly match confusion matrix math
        for i, cls_name in enumerate(classes):
            tp = cm[i, i]
            fp = cm[:, i].sum() - tp
            fn = cm[i, :].sum() - tp
            expected_p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            expected_r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            self.assertAlmostEqual(metrics["Per Class"][cls_name]["precision"], expected_p, places=5)
            self.assertAlmostEqual(metrics["Per Class"][cls_name]["recall"], expected_r, places=5)

        # 4. Named confusion matrix dictionary must match 2D array
        cm_dict = metrics["confusion_matrix_dict"]
        for i, true_name in enumerate(classes):
            for j, pred_name in enumerate(classes):
                self.assertEqual(cm_dict[true_name][pred_name], int(cm[i, j]))

    def test_preprocessor_canonical_label_alignment_and_remapping(self):
        """Verify that streaming evaluation remaps preprocessor local IDs to canonical class ordering."""
        # Simulated scenario: Preprocessor had alphabetical ordering
        # [0: Benign, 1: Botnet, 2: Brute Force, 3: DDoS, 4: DoS, 5: Infiltration, 6: Web Attack]
        alpha_classes = ["Benign", "Botnet", "Brute Force", "DDoS", "DoS", "Infiltration", "Web Attack"]
        preproc = SpecialistPreprocessor(dataset_name="IDS2018")
        df_dummy = pd.DataFrame({
            "f1": [1.0] * 7,
            "final_label": alpha_classes
        })
        preproc.fit(df_dummy)
        # Force preprocessor local IDs to alphabetical order
        preproc.expected_classes = alpha_classes
        preproc.classes_ = alpha_classes
        preproc.local_label_to_id = {c: i for i, c in enumerate(alpha_classes)}
        preproc.id_to_local_label = {i: c for i, c in enumerate(alpha_classes)}

        # In alphabetical order: Infiltration is local ID 5
        # Canonical order for IDS2018:
        # [0: Benign, 1: DDoS, 2: DoS, 3: Botnet, 4: Infiltration, 5: Brute Force, 6: Web Attack]
        canonical_classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]

        # Create 50 samples of Benign flows
        df_test = pd.DataFrame({
            "f1": [1.0] * 50,
            "final_label": ["Benign"] * 50
        })

        # Mock model that predicts local ID 5 (which is Infiltration in preprocessor)
        class MockModel:
            def predict(self, X):
                return np.full(len(X), 5, dtype=np.int32)

        # Evaluate with canonical class ordering
        metrics = evaluate_dataset_streamed(
            model=MockModel(),
            data_source=df_test,
            preprocessor=preproc,
            expected_classes=canonical_classes,
            batch_size=20
        )

        cm_dict = metrics["confusion_matrix_dict"]
        # In canonical order: index 4 is Infiltration, index 5 is Brute Force
        # The 50 Benign flows predicted as local ID 5 (Infiltration) must show as:
        # Benign -> Infiltration = 50, NOT Benign -> Brute Force!
        self.assertEqual(cm_dict["Benign"]["Infiltration"], 50)
        self.assertEqual(cm_dict["Benign"]["Brute Force"], 0)
        # Brute Force false positives must be 0
        cm = np.array(metrics["Confusion Matrix"])
        # Brute Force column is index 5
        self.assertEqual(cm[:, 5].sum(), 0)
        # Infiltration column is index 4
        self.assertEqual(cm[:, 4].sum(), 50)

    def test_streamed_evaluation_parity_with_in_memory(self):
        """Streaming evaluation in small chunks must yield identical results to full in-memory evaluation."""
        classes = ["Benign", "DDoS", "DoS"]
        np.random.seed(99)
        df = pd.DataFrame({
            "feat1": np.random.randn(90),
            "feat2": np.random.randn(90),
            "final_label": ["Benign"] * 30 + ["DDoS"] * 30 + ["DoS"] * 30
        })
        preproc = SpecialistPreprocessor(dataset_name="TestSpec", expected_classes=classes)
        preproc.fit(df)

        model = DecisionTreeClassifier(max_depth=3, random_state=42)
        X = preproc.transform_features(df)
        y = preproc.transform_labels(df)
        model.fit(X, y)

        # Single batch (in-memory equivalent)
        metrics_full = evaluate_dataset_streamed(model, df, preproc, classes, batch_size=100)
        # Small chunks (streamed)
        metrics_streamed = evaluate_dataset_streamed(model, df, preproc, classes, batch_size=15)

        self.assertEqual(metrics_full["total_samples"], metrics_streamed["total_samples"])
        self.assertEqual(metrics_full["Accuracy"], metrics_streamed["Accuracy"])
        self.assertEqual(metrics_full["Macro F1"], metrics_streamed["Macro F1"])
        self.assertEqual(metrics_full["Confusion Matrix"], metrics_streamed["Confusion Matrix"])

    def test_evaluate_only_mode(self):
        """--evaluate-only flag must re-evaluate existing models without fitting new ones."""
        from utils.data_preparation import load_config
        from unittest.mock import patch
        config = load_config()

        # Step 1: Run standard smoke test to generate initial models and artifacts
        train_specialist(
            spec_name="IDS2018",
            config=config,
            smoke_test=True,
            selected_model="dt",
            force_retrain=True
        )

        # Step 2: Run in evaluate-only mode with patch ensuring fit() is NEVER called on any model
        with patch.object(DecisionTreeClassifier, "fit", side_effect=AssertionError("fit() must not be called in evaluate-only mode!")):
            meta = train_specialist(
                spec_name="IDS2018",
                config=config,
                smoke_test=True,
                selected_model="dt",
                evaluate_only=True
            )

        # Step 3: Verify metadata structure and correct row counts
        self.assertIn("test_row_count", meta)
        self.assertIn("validation_row_count", meta)
        self.assertEqual(meta["test_row_count"], 30) # smoke test test split has 30 rows
        self.assertEqual(meta["validation_row_count"], 30) # smoke test val split has 30 rows
        self.assertIn("confusion_matrix_dict", meta["test_metrics"])
        self.assertIn("total_samples", meta["test_metrics"])
        self.assertEqual(meta["test_metrics"]["total_samples"], 30)

        # Verify final_model_selection.json report
        report_path = os.path.join("reports", "model_training", "IDS2018", "final_model_selection.json")
        with open(report_path, "r") as f:
            selection_rep = json.load(f)
        self.assertEqual(selection_rep["test_row_count"], 30)
        self.assertEqual(selection_rep["test_metrics"]["total_samples"], 30)


if __name__ == "__main__":
    unittest.main()
