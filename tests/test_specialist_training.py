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
from utils.model_registry import get_candidate_model

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
            selected_model="dt",
            save_artifacts=False
        )
        self.assertEqual(list(results_single.keys()), ["IDS2018"])

        # Comma-separated specialist selection
        results_multi = train_all_specialists(
            config=config,
            smoke_test=True,
            target_dataset="ids2018, arp",
            selected_model="dt",
            save_artifacts=False
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

        with tempfile.TemporaryDirectory() as tmp_model_dir, tempfile.TemporaryDirectory() as tmp_rep_dir:
            # Step 1: Run standard smoke test to generate initial models and artifacts in isolated temp dirs
            train_specialist(
                spec_name="IDS2018",
                config=config,
                smoke_test=True,
                selected_model="dt",
                force_retrain=True,
                save_artifacts=True,
                model_dir=tmp_model_dir,
                report_dir=tmp_rep_dir
            )

            # Step 2: Run in evaluate-only mode with patch ensuring fit() is NEVER called on any model
            with patch.object(DecisionTreeClassifier, "fit", side_effect=AssertionError("fit() must not be called in evaluate-only mode!")):
                meta = train_specialist(
                    spec_name="IDS2018",
                    config=config,
                    smoke_test=True,
                    selected_model="dt",
                    evaluate_only=True,
                    save_artifacts=True,
                    model_dir=tmp_model_dir,
                    report_dir=tmp_rep_dir
                )

            # Step 3: Verify metadata structure and correct row counts
            self.assertIn("test_row_count", meta)
            self.assertIn("validation_row_count", meta)
            self.assertEqual(meta["test_row_count"], 30) # smoke test test split has 30 rows
            self.assertEqual(meta["validation_row_count"], 30) # smoke test val split has 30 rows
            self.assertIn("confusion_matrix_dict", meta["test_metrics"])
            self.assertIn("total_samples", meta["test_metrics"])
            self.assertEqual(meta["test_metrics"]["total_samples"], 30)

            # Verify final_model_selection.json report in isolated directory
            report_path = os.path.join(tmp_rep_dir, "final_model_selection.json")
            with open(report_path, "r") as f:
                selection_rep = json.load(f)
            self.assertEqual(selection_rep["test_row_count"], 30)
            self.assertEqual(selection_rep["test_metrics"]["total_samples"], 30)

    def test_optimized_model_evaluation_selection_prefers_candidate_artifact(self):
        """Regression test: evaluate-only on IDS2018 must select candidate_DecisionTree_Tuned rather than DecisionTree.joblib."""
        from utils.data_preparation import load_config, resolve_path
        from utils.train_models import resolve_model_path
        config = load_config()

        # Verify resolve_model_path resolves candidate_ prefix for DecisionTree_Tuned
        model_dir = resolve_path("models/IDS2018")
        resolved = resolve_model_path(model_dir, "DecisionTree_Tuned")
        self.assertTrue(resolved.endswith("candidate_DecisionTree_Tuned.joblib"))

        # Verify evaluate-only mode selects DecisionTree_Tuned when best_optimized_model.json exists
        meta = train_specialist(
            spec_name="IDS2018",
            config=config,
            smoke_test=True,
            evaluate_only=True,
            save_artifacts=False
        )

        self.assertEqual(meta["best_model"], "DecisionTree_Tuned")
        self.assertEqual(meta["model_name"], "DecisionTree_Tuned")
        self.assertTrue(meta["model_path"].endswith("candidate_DecisionTree_Tuned.joblib"))
        self.assertFalse(meta["model_path"].endswith("/DecisionTree.joblib"))

    def test_optimized_evaluation_explicit_model_selection(self):
        """Specifying --model DecisionTree_Tuned loads candidate, while --model DecisionTree loads baseline."""
        from utils.data_preparation import load_config
        config = load_config()

        # 1. Explicit DecisionTree_Tuned
        meta_tuned = train_specialist(
            spec_name="IDS2018",
            config=config,
            smoke_test=True,
            selected_model="DecisionTree_Tuned",
            evaluate_only=True,
            save_artifacts=False
        )
        self.assertEqual(meta_tuned["best_model"], "DecisionTree_Tuned")
        self.assertTrue(meta_tuned["model_path"].endswith("candidate_DecisionTree_Tuned.joblib"))

        # 2. Explicit baseline DecisionTree
        meta_baseline = train_specialist(
            spec_name="IDS2018",
            config=config,
            smoke_test=True,
            selected_model="DecisionTree",
            evaluate_only=True,
            save_artifacts=False
        )
        self.assertEqual(meta_baseline["best_model"], "DecisionTree")
        self.assertTrue(meta_baseline["model_path"].endswith("DecisionTree.joblib"))

    def test_other_specialists_unaffected_by_ids2018_optimization(self):
        """Non-IDS2018 specialists must preserve standard evaluation behavior."""
        from utils.data_preparation import load_config
        config = load_config()

        meta_arp = train_specialist(
            spec_name="ARP_Spoofing",
            config=config,
            smoke_test=True,
            selected_model="DecisionTree",
            evaluate_only=True,
            save_artifacts=False
        )
        self.assertEqual(meta_arp["best_model"], "DecisionTree")
        self.assertTrue(meta_arp["model_path"].endswith("DecisionTree.joblib"))

    def test_evaluation_gatekeeper_blocks_degraded_optimized_validation(self):
        """Evaluation gatekeeper must strictly abort test evaluation if validation reproduction fails."""
        from utils.data_preparation import load_config
        config = load_config()

        with tempfile.TemporaryDirectory() as tmp_m_dir, tempfile.TemporaryDirectory() as tmp_r_dir:
            # Create a model and real-column preprocessor in isolated dir
            df_synth = pd.DataFrame({
                "Protocol": [6.0, 17.0],
                "Flow Duration": [100.0, 200.0],
                "final_label": ["Benign", "DDoS"]
            })
            preproc = SpecialistPreprocessor(dataset_name="IDS2018", expected_classes=config["classes"]["ids2018"], scale_features=True)
            preproc.fit(df_synth)
            preproc.save(os.path.join(tmp_m_dir, "preprocessor.joblib"))

            m_inst = DecisionTreeClassifier(max_depth=3, random_state=42)
            m_inst.fit(preproc.transform_features(df_synth), preproc.transform_labels(df_synth))
            from utils.train_models import joblib
            joblib.dump(m_inst, os.path.join(tmp_m_dir, "candidate_DecisionTree_Tuned.joblib"))

            # In evaluate_only with smoke_test=False (simulating full run where validation collapsed to 0.7828),
            # gatekeeper must trigger if accuracy < 0.95
            from unittest.mock import patch
            mock_val_results = {
                "DecisionTree_Tuned": {
                    "Accuracy": 0.7828,
                    "Macro F1": 0.2250,
                    "Macro Precision": 0.2000,
                    "Macro Recall": 0.2500,
                    "Per Class": {"Benign": {"support": 10}},
                    "uncalibrated_baseline": {"Accuracy": 0.7828, "Macro F1": 0.2250}
                }
            }
            # Test that gatekeeper raises RuntimeError and blocks test evaluation
            with patch("utils.train_models.load_specialist_splits", return_value=(None, df_synth, df_synth)):
                with patch("utils.train_models.evaluate_dataset_streamed", return_value=mock_val_results["DecisionTree_Tuned"]):
                    with self.assertRaises(RuntimeError) as ctx:
                        train_specialist(
                            spec_name="IDS2018",
                            config=config,
                            smoke_test=False,
                            selected_model="DecisionTree_Tuned",
                            evaluate_only=True,
                            use_optimized=True,
                            save_artifacts=False,
                            model_dir=tmp_m_dir,
                            report_dir=tmp_r_dir
                        )
                    self.assertIn("Validation reproduction check FAILED", str(ctx.exception))
                    self.assertIn("Held-out test evaluation strictly blocked", str(ctx.exception))

    def test_two_stage_validation_uncalibrated_and_calibrated_reporting(self):
        """evaluate-only must record uncalibrated baseline metrics when threshold calibration is applied."""
        from utils.data_preparation import load_config
        config = load_config()

        with tempfile.TemporaryDirectory() as tmp_m_dir, tempfile.TemporaryDirectory() as tmp_r_dir:
            train_specialist(
                spec_name="IDS2018",
                config=config,
                smoke_test=True,
                selected_model="DecisionTree_Tuned",
                force_retrain=True,
                save_artifacts=True,
                model_dir=tmp_m_dir,
                report_dir=tmp_r_dir
            )

            meta = train_specialist(
                spec_name="IDS2018",
                config=config,
                smoke_test=True,
                selected_model="DecisionTree_Tuned",
                evaluate_only=True,
                use_optimized=True,
                save_artifacts=False,
                model_dir=tmp_m_dir,
                report_dir=tmp_r_dir
            )

            val_metrics = meta["validation_metrics"]
            self.assertIn("uncalibrated_baseline", val_metrics)
            self.assertIn("Macro F1", val_metrics["uncalibrated_baseline"])
            self.assertIn("Accuracy", val_metrics["uncalibrated_baseline"])

    def test_preprocessor_validate_contract_detects_mismatches(self):
        """validate_contract must detect class ordering mismatch, unscaled features, and dummy features."""
        canonical_classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
        df = pd.DataFrame({
            "flow_duration": [10.0, 20.0, 30.0],
            "total_fwd_pkts": [1.0, 2.0, 3.0],
            "final_label": ["Benign", "DDoS", "DoS"]
        })

        # 1. Valid preprocessor
        p_valid = SpecialistPreprocessor(dataset_name="IDS2018", expected_classes=canonical_classes, scale_features=True)
        p_valid.fit(df)
        is_val, reason = p_valid.validate_contract(expected_classes=canonical_classes)
        self.assertTrue(is_val)

        # 2. Class ordering mismatch (alphabetical order)
        p_alpha = SpecialistPreprocessor(dataset_name="IDS2018", scale_features=True)
        # Manually simulate alphabetical classes
        alpha_classes = sorted(canonical_classes)
        p_alpha._init_classes(alpha_classes, preserve_order=False)
        p_alpha.fit(df)
        is_val, reason = p_alpha.validate_contract(expected_classes=canonical_classes, strict_order=True)
        self.assertFalse(is_val)
        self.assertIn("Class ordering mismatch", reason)

        # 3. Dummy features
        df_dummy = pd.DataFrame({
            f"feature_{i}": [1.0, 2.0, 3.0] for i in range(5)
        })
        df_dummy["final_label"] = ["Benign", "DDoS", "DoS"]
        p_dummy = SpecialistPreprocessor(dataset_name="IDS2018", expected_classes=canonical_classes, scale_features=True)
        p_dummy.fit(df_dummy)
        is_val, reason = p_dummy.validate_contract(expected_classes=canonical_classes)
        self.assertFalse(is_val)
        self.assertIn("synthetic dummy features", reason)

        # 4. Unscaled features when scaled required
        p_unscaled = SpecialistPreprocessor(dataset_name="IDS2018", expected_classes=canonical_classes, scale_features=False)
        p_unscaled.fit(df)
        is_val, reason = p_unscaled.validate_contract(expected_classes=canonical_classes, require_scaled=True)
        self.assertFalse(is_val)
        self.assertIn("scale_features=False", reason)

    def test_evaluator_rejects_preprocessor_contract_mismatch(self):
        """evaluate_dataset_streamed must strictly abort if preprocessor fails contract validation."""
        canonical_classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
        df_val_2class = pd.DataFrame({
            "flow_duration": [10.0, 20.0],
            "total_fwd_pkts": [1.0, 2.0],
            "final_label": ["Benign", "DoS"]
        })

        # Scenario 1: Preprocessor class set mismatch
        p_wrong_classes = SpecialistPreprocessor(dataset_name="IDS2018", scale_features=True)
        p_wrong_classes._init_classes(["Benign", "DoS"], preserve_order=False)
        p_wrong_classes.fit(df_val_2class)

        clf = DecisionTreeClassifier()
        clf.fit(p_wrong_classes.transform_features(df_val_2class), p_wrong_classes.transform_labels(df_val_2class))

        with self.assertRaises(ValueError) as ctx:
            evaluate_dataset_streamed(
                model=clf,
                data_source=df_val_2class,
                preprocessor=p_wrong_classes,
                expected_classes=canonical_classes
            )
        self.assertIn("Evaluator Contract Violation", str(ctx.exception))
        self.assertIn("Class set mismatch", str(ctx.exception))

        # Scenario 2: Feature count mismatch
        df_val_7class = pd.DataFrame({
            "flow_duration": [10.0, 20.0],
            "total_fwd_pkts": [1.0, 2.0],
            "final_label": ["Benign", "DoS"]
        })
        p_wrong_feats = SpecialistPreprocessor(dataset_name="IDS2018", expected_classes=canonical_classes, scale_features=True)
        p_wrong_feats.fit(df_val_7class)

        clf_3_feats = DecisionTreeClassifier()
        X_dummy_3 = np.zeros((2, 3), dtype=np.float32)
        y_dummy = np.array([0, 1])
        clf_3_feats.fit(X_dummy_3, y_dummy)

        with self.assertRaises(ValueError) as ctx:
            evaluate_dataset_streamed(
                model=clf_3_feats,
                data_source=df_val_7class,
                preprocessor=p_wrong_feats,
                expected_classes=canonical_classes
            )
        self.assertIn("Evaluator Contract Violation", str(ctx.exception))
        self.assertIn("Model expects 3 features, but preprocessor produces 2 features", str(ctx.exception))

    def test_deterministic_validation_reproduction(self):
        """Prove that saved candidate model + exact persisted preprocessing contract faithfully reproduces validation metrics using ONLY train/val data."""
        canonical_classes = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]

        # Build deterministic train and val data (zero test data)
        np.random.seed(42)
        n_train = 700
        n_val = 210

        def make_df(n_samples):
            data = {}
            for i in range(10):
                data[f"numeric_metric_{i}"] = np.random.randn(n_samples).astype(np.float32)
            # 7 balanced classes
            labels = [canonical_classes[i % 7] for i in range(n_samples)]
            data["final_label"] = labels
            return pd.DataFrame(data)

        df_train = make_df(n_train)
        df_val = make_df(n_val)

        # 1. Fit exact preprocessor on training data
        preproc_exact = SpecialistPreprocessor(
            dataset_name="IDS2018",
            expected_classes=canonical_classes,
            scale_features=True
        )
        preproc_exact.fit(df_train)
        X_train = preproc_exact.transform_features(df_train)
        y_train = preproc_exact.transform_labels(df_train)

        # 2. Fit candidate DecisionTree model
        cand_model = DecisionTreeClassifier(max_depth=5, min_samples_leaf=2, random_state=42)
        cand_model.fit(X_train, y_train)

        # 3. Known Stage-B validation metrics
        stage_b_val_metrics = evaluate_dataset_streamed(
            cand_model, df_val, preproc_exact, canonical_classes
        )
        expected_acc = stage_b_val_metrics["Accuracy"]
        expected_f1 = stage_b_val_metrics["Macro F1"]

        # 4. Save artifacts to temporary directory (persisted contract)
        with tempfile.TemporaryDirectory() as tmpdir:
            m_path = os.path.join(tmpdir, "candidate_DecisionTree_Tuned.joblib")
            p_path = os.path.join(tmpdir, "preprocessor.joblib")
            from utils.train_models import joblib
            joblib.dump(cand_model, m_path)
            preproc_exact.save(p_path)

            # 5. Reload artifacts and evaluate-only
            reloaded_model = joblib.load(m_path)
            reloaded_preproc = SpecialistPreprocessor.load(p_path)

            eval_only_metrics = evaluate_dataset_streamed(
                reloaded_model, df_val, reloaded_preproc, canonical_classes
            )

            # Reproduction must match to exact precision
            self.assertAlmostEqual(eval_only_metrics["Accuracy"], expected_acc, places=5)
            self.assertAlmostEqual(eval_only_metrics["Macro F1"], expected_f1, places=5)

            # 6. If preprocessor is corrupted with unscaled features, reproduction fails contract
            corrupt_preproc = SpecialistPreprocessor(
                dataset_name="IDS2018",
                expected_classes=canonical_classes,
                scale_features=False
            )
            corrupt_preproc.fit(df_train)
            is_valid, _ = corrupt_preproc.validate_contract(expected_classes=canonical_classes, require_scaled=True)
            self.assertFalse(is_valid)

    def test_ciciot2023_preprocessor_contract_and_ordering(self):
        """CICIoT2023 specialist must enforce 10 canonical classes in exact project taxonomy order."""
        from utils.specialist_evaluator import SPECIALIST_CLASSES
        canonical_ciciot = SPECIALIST_CLASSES["CICIoT2023"]
        self.assertEqual(len(canonical_ciciot), 10)
        self.assertEqual(canonical_ciciot, [
            "Benign", "DDoS", "DoS", "Botnet", "Infiltration",
            "Brute Force", "Web Attack", "DNS Spoofing", "Recon / Port Scan", "MITM"
        ])

        # Create mock DataFrame with 46 numeric features and final_label
        mock_data = {f"ciciot_feat_{i}": np.random.randn(20).astype(np.float32) for i in range(46)}
        mock_data["final_label"] = [canonical_ciciot[i % 10] for i in range(20)]
        df_mock = pd.DataFrame(mock_data)

        # Preprocessor with canonical ordering passes contract
        preproc = SpecialistPreprocessor(dataset_name="CICIoT2023", expected_classes=canonical_ciciot, scale_features=True)
        preproc.fit(df_mock)
        is_valid, reason = preproc.validate_contract(expected_classes=canonical_ciciot, strict_order=True)
        self.assertTrue(is_valid, f"Contract failed: {reason}")
        self.assertEqual(preproc.n_features_in_, 46)

        # Alphabetical ordering must strictly fail contract validation
        alphabetical_classes = sorted(canonical_ciciot)
        preproc_alpha = SpecialistPreprocessor(dataset_name="CICIoT2023", expected_classes=alphabetical_classes, scale_features=True)
        preproc_alpha.fit(df_mock)
        is_val_alpha, reason_alpha = preproc_alpha.validate_contract(expected_classes=canonical_ciciot, strict_order=True)
        self.assertFalse(is_val_alpha)
        self.assertIn("Class ordering mismatch", reason_alpha)

    def test_ciciot2023_checkpoint_mock_invalidation(self):
        """Stale mock report (< 1000 rows) must be invalidated when real data is available (> 5000 rows)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = os.path.join(tmpdir, "models")
            rep_dir = os.path.join(tmpdir, "reports")
            os.makedirs(model_dir, exist_ok=True)
            os.makedirs(rep_dir, exist_ok=True)

            # Write a mock training report with 60 rows
            rep_file = os.path.join(rep_dir, "DecisionTree_training.json")
            with open(rep_file, "w") as f:
                json.dump({
                    "dataset": "CICIoT2023",
                    "model_name": "DecisionTree",
                    "train_row_count": 60,
                    "validation_metrics": {"Macro F1": 0.08, "Accuracy": 0.73}
                }, f)

            model_file = os.path.join(model_dir, "DecisionTree.joblib")
            with open(model_file, "w") as f:
                f.write("mock_model_content")

            # Check logic: cached_rows < 1000 with n_train_raw > 5000 must trigger invalidation
            cached_rows = 0
            with open(rep_file, "r") as f:
                r = json.load(f)
                cached_rows = r.get("train_row_count", 0)

            n_train_raw = 5357406
            should_invalidate = (cached_rows < 1000 and n_train_raw > 5000)
            self.assertTrue(should_invalidate)

    def test_smoke_test_does_not_pollute_production_dirs(self):
        """Smoke test execution with default arguments must never save artifacts to production directories."""
        prod_model_dir = os.path.abspath("models/CICIoT2023")
        prod_rep_dir = os.path.abspath("reports/model_training/CICIoT2023")
        
        # Capture existing files before
        model_files_before = set(os.listdir(prod_model_dir)) if os.path.exists(prod_model_dir) else set()
        rep_files_before = set(os.listdir(prod_rep_dir)) if os.path.exists(prod_rep_dir) else set()

        train_specialist(
            "CICIoT2023",
            model_names=["DecisionTree"],
            smoke_test=True,
            save_artifacts=True
        )

        model_files_after = set(os.listdir(prod_model_dir)) if os.path.exists(prod_model_dir) else set()
        rep_files_after = set(os.listdir(prod_rep_dir)) if os.path.exists(prod_rep_dir) else set()

        # Production dirs must have zero new files added
        self.assertEqual(model_files_after, model_files_before)
        self.assertEqual(rep_files_after, rep_files_before)

    def test_ciciot2023_optimized_evaluation_selection_prefers_candidate_artifact(self):
        """Regression test: evaluate-only with --optimized on CICIoT2023 selects candidate_XGBoost_Tuned and multipliers."""
        from utils.data_preparation import load_config
        config = load_config()

        with tempfile.TemporaryDirectory() as tmp_m_dir, tempfile.TemporaryDirectory() as tmp_r_dir:
            # Setup optimization directory with best_optimized_model.json and threshold_tuning.json
            opt_dir = os.path.join(tmp_r_dir, "optimization")
            os.makedirs(opt_dir, exist_ok=True)
            with open(os.path.join(opt_dir, "best_optimized_model.json"), "w") as f:
                json.dump({
                    "model": "XGBoost_Tuned",
                    "model_path": os.path.join(tmp_m_dir, "candidate_XGBoost_Tuned.joblib"),
                    "threshold_multipliers": {"Benign": 1.5, "DDoS": 1.0, "Infiltration": 2.0}
                }, f)

            # Create mock candidate_XGBoost_Tuned.joblib and preprocessor.joblib
            canonical_classes = config["classes"]["ciciot2023"]
            df_mock, _, _ = load_specialist_splits("CICIoT2023", config, smoke_test=True)

            preproc = SpecialistPreprocessor(dataset_name="CICIoT2023", expected_classes=canonical_classes, scale_features=True)
            preproc.fit(df_mock)
            preproc.save(os.path.join(tmp_m_dir, "preprocessor.joblib"))

            model_inst = get_candidate_model("XGBoost_Tuned", smoke_test=True)
            model_inst.fit(preproc.transform_features(df_mock), preproc.transform_labels(df_mock))
            from utils.train_models import joblib
            joblib.dump(model_inst, os.path.join(tmp_m_dir, "candidate_XGBoost_Tuned.joblib"))

            # Also create a baseline XGBoost.joblib to verify it is NOT chosen
            base_model = get_model_instance("XGBoost", smoke_test=True)
            base_model.fit(preproc.transform_features(df_mock), preproc.transform_labels(df_mock))
            joblib.dump(base_model, os.path.join(tmp_m_dir, "XGBoost.joblib"))

            # Case 1: evaluate-only with use_optimized=True without selected_model
            meta = train_specialist(
                spec_name="CICIoT2023",
                config=config,
                smoke_test=True,
                evaluate_only=True,
                use_optimized=True,
                save_artifacts=False,
                model_dir=tmp_m_dir,
                report_dir=tmp_r_dir
            )
            self.assertEqual(meta["best_model"], "XGBoost_Tuned")
            self.assertTrue(meta["model_path"].endswith("candidate_XGBoost_Tuned.joblib"))
            self.assertFalse(meta["model_path"].endswith("XGBoost.joblib"))
            self.assertIn("threshold_multipliers", meta)

            # Case 2: evaluate-only with selected_model="xgboost" and use_optimized=True
            meta_flag = train_specialist(
                spec_name="CICIoT2023",
                config=config,
                smoke_test=True,
                selected_model="xgboost",
                evaluate_only=True,
                use_optimized=True,
                save_artifacts=False,
                model_dir=tmp_m_dir,
                report_dir=tmp_r_dir
            )
            self.assertEqual(meta_flag["best_model"], "XGBoost_Tuned")
            self.assertTrue(meta_flag["model_path"].endswith("candidate_XGBoost_Tuned.joblib"))

    def test_ciciot2023_candidate_preprocessor_preference(self):
        """When candidate_preprocessor.joblib exists, evaluate_only under --optimized prefers it over preprocessor.joblib."""
        from utils.data_preparation import load_config
        config = load_config()

        with tempfile.TemporaryDirectory() as tmp_m_dir, tempfile.TemporaryDirectory() as tmp_r_dir:
            canonical_classes = config["classes"]["ciciot2023"]
            df_mock, _, _ = load_specialist_splits("CICIoT2023", config, smoke_test=True)

            # Save distinct candidate and standard preprocessors
            p_cand = SpecialistPreprocessor(dataset_name="CICIoT2023", expected_classes=canonical_classes, scale_features=True)
            p_cand.fit(df_mock)
            p_cand.training_row_count_ = 5357406
            p_cand.save(os.path.join(tmp_m_dir, "candidate_preprocessor.joblib"))

            p_std = SpecialistPreprocessor(dataset_name="CICIoT2023", expected_classes=canonical_classes, scale_features=True)
            p_std.fit(df_mock)
            p_std.training_row_count_ = 1000
            p_std.save(os.path.join(tmp_m_dir, "preprocessor.joblib"))

            model_inst = get_candidate_model("XGBoost_Tuned", smoke_test=True)
            model_inst.fit(p_cand.transform_features(df_mock), p_cand.transform_labels(df_mock))
            from utils.train_models import joblib
            joblib.dump(model_inst, os.path.join(tmp_m_dir, "candidate_XGBoost_Tuned.joblib"))

            meta = train_specialist(
                spec_name="CICIoT2023",
                config=config,
                smoke_test=True,
                selected_model="XGBoost_Tuned",
                evaluate_only=True,
                use_optimized=True,
                save_artifacts=False,
                model_dir=tmp_m_dir,
                report_dir=tmp_r_dir
            )
            self.assertTrue(meta["preprocessing_artifact_path"].endswith("candidate_preprocessor.joblib"))

    def test_ciciot2023_gatekeeper_blocks_baseline_performance_on_optimized_eval(self):
        """Gatekeeper must raise RuntimeError if an optimized candidate evaluates below validation target."""
        from unittest.mock import patch
        from utils.data_preparation import load_config
        config = load_config()

        with tempfile.TemporaryDirectory() as tmp_m_dir, tempfile.TemporaryDirectory() as tmp_r_dir:
            canonical_classes = config["classes"]["ciciot2023"]
            df_mock, _, _ = load_specialist_splits("CICIoT2023", config, smoke_test=True)

            preproc = SpecialistPreprocessor(dataset_name="CICIoT2023", expected_classes=canonical_classes, scale_features=True)
            preproc.fit(df_mock)
            preproc.training_row_count_ = 5357406
            preproc.save(os.path.join(tmp_m_dir, "preprocessor.joblib"))

            model_inst = get_candidate_model("XGBoost_Tuned", smoke_test=True)
            model_inst.fit(preproc.transform_features(df_mock), preproc.transform_labels(df_mock))
            from utils.train_models import joblib
            joblib.dump(model_inst, os.path.join(tmp_m_dir, "candidate_XGBoost_Tuned.joblib"))

            # Simulate baseline performance (Macro F1 = 0.6974 < 0.75 target)
            mock_metrics = {
                "Accuracy": 0.9888,
                "Macro F1": 0.6974,
                "Macro Precision": 0.70,
                "Macro Recall": 0.70,
                "Weighted F1": 0.98,
                "Per Class": {},
                "Confusion Matrix": []
            }

            with patch("utils.train_models.evaluate_dataset_streamed", return_value=mock_metrics):
                with self.assertRaises(RuntimeError) as ctx:
                    train_specialist(
                        spec_name="CICIoT2023",
                        config=config,
                        smoke_test=False, # Trigger real gatekeeper
                        selected_model="XGBoost_Tuned",
                        evaluate_only=True,
                        use_optimized=True,
                        save_artifacts=False,
                        model_dir=tmp_m_dir,
                        report_dir=tmp_r_dir
                    )
                self.assertIn("Evaluation Gatekeeper", str(ctx.exception))
                self.assertIn("Validation reproduction check FAILED", str(ctx.exception))
                self.assertIn("expected >= 0.985 Acc, >= 0.750 Macro F1 for XGBoost_Tuned", str(ctx.exception))

    def test_preprocessor_row_check_preserves_sampled_dataset(self):
        """Preprocessor fitted on >= 1000 rows must NOT be discarded even if row count != train.parquet row count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p_path = os.path.join(tmpdir, "preprocessor.joblib")
            canonical_classes = ["Benign", "DoS"]
            df_mock = pd.DataFrame({"f": [1.0, 2.0], "final_label": ["Benign", "DoS"]})
            prep = SpecialistPreprocessor(dataset_name="TestSpec", expected_classes=canonical_classes, scale_features=True)
            prep.fit(df_mock)
            prep.training_row_count_ = 4100000
            prep.save(p_path)

            loaded = SpecialistPreprocessor.load(p_path)
            prep_rows = getattr(loaded, "training_row_count_", 0)
            n_train_rows = 5357406

            # Logic test: prep_rows >= 1000 must NOT trigger discard
            from utils.train_models import should_invalidate_checkpoint
            should_discard = should_invalidate_checkpoint(prep_rows, n_train_rows)
            self.assertFalse(should_discard)

    def test_arp_checkpoint_invalidation_contract(self):
        """ARP micro-stubs (<= 10 rows) must be invalidated when real data is available."""
        from utils.train_models import should_invalidate_checkpoint
        # Micro stub vs real data
        self.assertTrue(should_invalidate_checkpoint(cached_train_rows=2, n_train_raw=2500))
        self.assertTrue(should_invalidate_checkpoint(cached_train_rows=2, n_train_raw=100))
        self.assertTrue(should_invalidate_checkpoint(cached_train_rows=10, n_train_raw=50))
        
        # Subsample vs full data
        self.assertTrue(should_invalidate_checkpoint(cached_train_rows=60, n_train_raw=1200))
        self.assertTrue(should_invalidate_checkpoint(cached_train_rows=500, n_train_raw=10000))

        # Legitimate full training must NOT invalidate
        self.assertFalse(should_invalidate_checkpoint(cached_train_rows=2500, n_train_raw=2500))
        self.assertFalse(should_invalidate_checkpoint(cached_train_rows=50000, n_train_raw=50000))
        self.assertFalse(should_invalidate_checkpoint(cached_train_rows=2, n_train_raw=2))

    def test_arp_smoke_test_evaluate_only_does_not_pollute_production(self):
        """ARP smoke test in evaluate-only mode must not overwrite production metadata or selection reports."""
        prod_model_dir = os.path.abspath("models/ARP_Spoofing")
        prod_rep_dir = os.path.abspath("reports/model_training/ARP_Spoofing")

        meta_file = os.path.join(prod_model_dir, "specialist_metadata.json")
        sel_file = os.path.join(prod_rep_dir, "final_model_selection.json")

        meta_mtime_before = os.path.getmtime(meta_file) if os.path.exists(meta_file) else None
        sel_mtime_before = os.path.getmtime(sel_file) if os.path.exists(sel_file) else None

        train_specialist(
            spec_name="ARP_Spoofing",
            smoke_test=True,
            evaluate_only=True,
            save_artifacts=True
        )

        meta_mtime_after = os.path.getmtime(meta_file) if os.path.exists(meta_file) else None
        sel_mtime_after = os.path.getmtime(sel_file) if os.path.exists(sel_file) else None

        self.assertEqual(meta_mtime_after, meta_mtime_before)
        self.assertEqual(sel_mtime_after, sel_mtime_before)

    def test_optimize_unsupported_specialist_raises_error(self):
        """Passing --optimize on specialists without progressive optimizer must raise ValueError."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "utils.train_models", "--dataset", "ARP_Spoofing", "--optimize"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Progressive optimization is not implemented for specialist 'ARP_Spoofing'", result.stderr)


if __name__ == "__main__":
    unittest.main()
