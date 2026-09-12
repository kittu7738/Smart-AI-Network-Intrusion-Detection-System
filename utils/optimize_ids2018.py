import os
import sys
import json
import time
import argparse
import gc

try:
    import joblib
except ImportError:
    import pickle
    class JoblibCompat:
        @staticmethod
        def dump(obj, filename):
            with open(filename, "wb") as f:
                pickle.dump(obj, f)
        @staticmethod
        def load(filename):
            with open(filename, "rb") as f:
                return pickle.load(f)
    joblib = JoblibCompat()

import numpy as np
import pandas as pd

from utils.data_preparation import resolve_path, load_config
from utils.specialist_preprocessor import SpecialistPreprocessor
from utils.specialist_evaluator import evaluate_predictions, evaluate_dataset_streamed
from utils.class_weighting import compute_specialist_sample_weights, compute_specialist_class_weights
from utils.model_registry import (
    OPTIMIZATION_CANDIDATE_CONFIGS,
    get_candidate_model,
    SEED
)
from utils.feature_engineering import (
    analyze_features_on_training_data,
    apply_feature_representation
)
from utils.threshold_tuner import (
    tune_validation_thresholds,
    predict_with_threshold_multipliers
)
from utils.train_models import (
    load_specialist_splits,
    sample_training_data,
    SPECIALIST_SPECS
)

def run_ids2018_optimization(
    config: dict = None,
    smoke_test: bool = False,
    max_train_samples: int = None,
    candidate_list: list = None,
    feature_representations: list = None,
    tune_thresholds_flag: bool = True,
    save_artifacts: bool = True
) -> dict:
    """Execute validation-only optimization strategy for IDS2018 specialist model."""
    if config is None:
        config = load_config()

    spec_name = "IDS2018"
    spec_info = SPECIALIST_SPECS[spec_name]
    expected_classes = config["classes"][spec_info["config_class_key"]]
    
    print("\n" + "=" * 65, flush=True)
    print("STARTING IDS2018 SPECIALIST VALIDATION OPTIMIZATION", flush=True)
    print(f"Goal: Maximize Validation Macro F1 & Accuracy toward ~99% target", flush=True)
    print(f"Taxonomy ({len(expected_classes)} classes): {expected_classes}", flush=True)
    print("=" * 65, flush=True)

    opt_dir = resolve_path(os.path.join("reports", "model_training", "IDS2018", "optimization"))
    models_dir = resolve_path(os.path.join("models", "IDS2018"))
    if save_artifacts:
        os.makedirs(opt_dir, exist_ok=True)
        os.makedirs(models_dir, exist_ok=True)

    # 1. Load Data Splits (Validation only, test remains strictly untouched)
    train_df, val_source, test_source = load_specialist_splits(
        spec_name, config, smoke_test=smoke_test, lazy_val_test=True
    )
    n_train_raw = len(train_df)
    val_repr = len(val_source) if isinstance(val_source, pd.DataFrame) else "disk (streamed)"
    print(f"Splits loaded: Train={n_train_raw} | Val={val_repr} | Test=UNTOUCHED (Preserved)", flush=True)

    # 2. Sample training data if requested for resource bounds
    train_sampled, sampling_meta = sample_training_data(
        train_df, target_col="final_label", max_samples=max_train_samples, seed=SEED
    )
    del train_df
    gc.collect()

    # 3. Stage 1: Feature Analysis on Training Data
    feature_preprocessor = SpecialistPreprocessor(
        dataset_name=spec_name, expected_classes=expected_classes, scale_features=False
    )
    feature_preprocessor.fit(train_sampled)
    raw_feature_names = feature_preprocessor.feature_names_in_

    print(f"\n--- STAGE 1: Feature Analysis on Training Split ({len(raw_feature_names)} features) ---", flush=True)
    feature_analysis = analyze_features_on_training_data(
        train_sampled, raw_feature_names, target_col="final_label"
    )
    print(f"Constant zero features identified: {len(feature_analysis['constant_features'])} {feature_analysis['constant_features']}", flush=True)
    print(f"Quasi-constant features: {len(feature_analysis['quasi_constant_features'])}", flush=True)
    print(f"High correlation pairs (>0.98): {len(feature_analysis['high_correlation_pairs'])}", flush=True)

    if save_artifacts:
        with open(os.path.join(opt_dir, "feature_analysis.json"), "w") as f:
            json.dump(feature_analysis, f, indent=4)

    # 4. Stage 2: Evaluate Model Architectures & Weighting Strategies
    if candidate_list is None:
        candidate_list = [
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

    # Preprocessor for candidate comparisons (standard 77 features)
    preprocessor = SpecialistPreprocessor(
        dataset_name=spec_name, expected_classes=expected_classes, scale_features=True
    )
    preprocessor.fit(train_sampled)
    X_train = preprocessor.transform_features(train_sampled)
    y_train = preprocessor.transform_labels(train_sampled)
    
    # Pre-compute weighting vectors
    weight_vectors = {
        "unweighted": compute_specialist_sample_weights(y_train, strategy="unweighted"),
        "sqrt_balanced": compute_specialist_sample_weights(y_train, strategy="sqrt_balanced"),
        "balanced": compute_specialist_sample_weights(y_train, strategy="balanced")
    }

    print("\n" + "-" * 65, flush=True)
    print("--- STAGE 2: Evaluating Model Candidates on Validation Split ---", flush=True)
    print("-" * 65, flush=True)

    candidate_results = {}

    for cand_name in candidate_list:
        if cand_name not in OPTIMIZATION_CANDIDATE_CONFIGS:
            print(f"Skipping unknown candidate {cand_name}")
            continue

        cand_cfg = OPTIMIZATION_CANDIDATE_CONFIGS[cand_name]
        print(f"\nEvaluating Candidate: {cand_name}", flush=True)
        print(f"  Description: {cand_cfg['description']}", flush=True)
        print(f"  Default Weighting: {cand_cfg['default_weighting']}", flush=True)

        model_inst = get_candidate_model(cand_name, smoke_test=smoke_test)
        sample_w = None
        if cand_cfg["supports_sample_weight"] and cand_cfg["default_weighting"] in weight_vectors:
            sample_w = weight_vectors[cand_cfg["default_weighting"]]

        # Fit Candidate
        t0 = time.time()
        try:
            if sample_w is not None and cand_name not in ["HistGradientBoosting"]:
                model_inst.fit(X_train, y_train, sample_weight=sample_w)
            elif sample_w is not None and cand_name == "HistGradientBoosting":
                try:
                    model_inst.fit(X_train, y_train, sample_weight=sample_w)
                except (TypeError, ValueError):
                    model_inst.fit(X_train, y_train)
            else:
                model_inst.fit(X_train, y_train)
            fit_time = time.time() - t0
            print(f"  Fit Duration: {fit_time:.2f}s", flush=True)

            # Evaluate on Validation Split (Streamed)
            t_eval_0 = time.time()
            val_metrics = evaluate_dataset_streamed(
                model_inst, val_source, preprocessor, expected_classes, batch_size=100000
            )
            eval_time = time.time() - t_eval_0
            print(f"  Validation Macro F1: {val_metrics['Macro F1']:.4f} | Accuracy: {val_metrics['Accuracy']:.4f} (Eval Time: {eval_time:.2f}s)", flush=True)

            candidate_results[cand_name] = {
                "candidate_name": cand_name,
                "description": cand_cfg["description"],
                "weighting_strategy": cand_cfg["default_weighting"],
                "fit_time_seconds": fit_time,
                "eval_time_seconds": eval_time,
                "val_accuracy": val_metrics["Accuracy"],
                "val_macro_f1": val_metrics["Macro F1"],
                "val_macro_precision": val_metrics["Macro Precision"],
                "val_macro_recall": val_metrics["Macro Recall"],
                "val_weighted_f1": val_metrics["Weighted F1"],
                "per_class_metrics": val_metrics["Per Class"],
                "confusion_matrix_dict": val_metrics.get("confusion_matrix_dict", {})
            }

            # Save model checkpoint temporarily for top model tracking
            cand_model_path = os.path.join(models_dir, f"candidate_{cand_name}.joblib")
            if save_artifacts:
                joblib.dump(model_inst, cand_model_path)

        except Exception as e:
            print(f"  ERROR training candidate {cand_name}: {e}", flush=True)
        finally:
            del model_inst
            gc.collect()

    if not candidate_results:
        raise RuntimeError("No optimization candidates were successfully evaluated.")

    # 5. Stage 3: Feature Representation Comparison on Best Model Architecture
    best_cand_name = max(candidate_results.keys(), key=lambda c: candidate_results[c]["val_macro_f1"])
    print(f"\n>> Top Architecture from Stage 2: {best_cand_name} (Val Macro F1 = {candidate_results[best_cand_name]['val_macro_f1']:.4f})", flush=True)

    feature_rep_results = {}
    if feature_representations is None:
        feature_representations = ["all_77", "curated_subset", "engineered"]

    print("\n" + "-" * 65, flush=True)
    print(f"--- STAGE 3: Comparing Feature Representations with {best_cand_name} ---", flush=True)
    print("-" * 65, flush=True)

    for rep in feature_representations:
        print(f"\nTesting Feature Representation: '{rep}'", flush=True)
        train_rep_df = apply_feature_representation(train_sampled, representation=rep)
        rep_preproc = SpecialistPreprocessor(
            dataset_name=spec_name, expected_classes=expected_classes, scale_features=True
        )
        rep_preproc.fit(train_rep_df)
        X_tr_rep = rep_preproc.transform_features(train_rep_df)
        y_tr_rep = rep_preproc.transform_labels(train_rep_df)

        rep_model = get_candidate_model(best_cand_name, smoke_test=smoke_test)
        cand_cfg = OPTIMIZATION_CANDIDATE_CONFIGS[best_cand_name]
        sample_w_rep = None
        if cand_cfg["supports_sample_weight"] and cand_cfg["default_weighting"] in weight_vectors:
            sample_w_rep = compute_specialist_sample_weights(y_tr_rep, strategy=cand_cfg["default_weighting"])

        t0 = time.time()
        if sample_w_rep is not None and best_cand_name != "HistGradientBoosting":
            rep_model.fit(X_tr_rep, y_tr_rep, sample_weight=sample_w_rep)
        elif sample_w_rep is not None and best_cand_name == "HistGradientBoosting":
            try:
                rep_model.fit(X_tr_rep, y_tr_rep, sample_weight=sample_w_rep)
            except (TypeError, ValueError):
                rep_model.fit(X_tr_rep, y_tr_rep)
        else:
            rep_model.fit(X_tr_rep, y_tr_rep)
        fit_t = time.time() - t0

        # Transform validation source on the fly
        if isinstance(val_source, pd.DataFrame):
            val_rep_source = apply_feature_representation(val_source, representation=rep)
        else:
            # File path: evaluate_dataset_streamed handles chunking; we pass rep_preproc
            val_rep_source = val_source

        val_rep_metrics = evaluate_dataset_streamed(
            rep_model, val_rep_source, rep_preproc, expected_classes, batch_size=100000
        )
        print(f"  Representation '{rep}' ({rep_preproc.n_features_in_} features): Val Macro F1: {val_rep_metrics['Macro F1']:.4f} | Accuracy: {val_rep_metrics['Accuracy']:.4f}", flush=True)

        feature_rep_results[rep] = {
            "representation": rep,
            "feature_count": rep_preproc.n_features_in_,
            "val_macro_f1": val_rep_metrics["Macro F1"],
            "val_accuracy": val_rep_metrics["Accuracy"],
            "fit_time_seconds": fit_t
        }
        del train_rep_df, X_tr_rep, y_tr_rep, rep_model
        gc.collect()

    # 6. Stage 4: Threshold & Decision Calibration (Validation-Only)
    threshold_tuning_report = {}
    best_multipliers = None

    if tune_thresholds_flag:
        print("\n" + "-" * 65, flush=True)
        print("--- STAGE 4: Decision Threshold Tuning (Validation-Only) ---", flush=True)
        print("-" * 65, flush=True)

        # Load best candidate model
        top_model_path = os.path.join(models_dir, f"candidate_{best_cand_name}.joblib")
        if os.path.exists(top_model_path):
            best_model_inst = joblib.load(top_model_path)
            # Collect validation probabilities
            val_df_loaded = pd.read_parquet(val_source) if isinstance(val_source, str) else val_source
            X_val = preprocessor.transform_features(val_df_loaded)
            y_val = preprocessor.transform_labels(val_df_loaded)

            if hasattr(best_model_inst, "predict_proba"):
                print("Computing validation posterior probabilities...", flush=True)
                y_val_prob = best_model_inst.predict_proba(X_val)
                threshold_tuning_report, best_multipliers = tune_validation_thresholds(
                    y_true=y_val, y_prob=y_val_prob, class_names=expected_classes, benign_idx=0
                )
                print(f"Threshold Optimization complete:", flush=True)
                print(f"  Baseline Macro F1: {threshold_tuning_report['baseline']['macro_f1']:.4f} -> Optimized: {threshold_tuning_report['optimized']['macro_f1']:.4f}", flush=True)
                print(f"  Baseline Accuracy: {threshold_tuning_report['baseline']['accuracy']:.4f} -> Optimized: {threshold_tuning_report['optimized']['accuracy']:.4f}", flush=True)
                print(f"  Benign FPR: {threshold_tuning_report['baseline']['benign_fpr']:.4f} -> {threshold_tuning_report['optimized']['benign_fpr']:.4f}", flush=True)

                if save_artifacts:
                    with open(os.path.join(opt_dir, "threshold_tuning.json"), "w") as f:
                        json.dump(threshold_tuning_report, f, indent=4)
            del best_model_inst, X_val, y_val
            gc.collect()

    # 7. Stage 5: Final Selection & Report Generation
    best_overall = candidate_results[best_cand_name]
    best_rep_name = max(feature_rep_results.keys(), key=lambda r: feature_rep_results[r]["val_macro_f1"]) if feature_rep_results else "all_77"

    optimization_summary = {
        "dataset": spec_name,
        "primary_metric": "Validation Macro F1",
        "selected_best_model": best_cand_name,
        "selected_best_feature_representation": best_rep_name,
        "best_validation_metrics": {
            "Accuracy": best_overall["val_accuracy"],
            "Macro F1": best_overall["val_macro_f1"],
            "Macro Precision": best_overall["val_macro_precision"],
            "Macro Recall": best_overall["val_macro_recall"],
            "Weighted F1": best_overall["val_weighted_f1"]
        },
        "all_candidates_comparison": candidate_results,
        "feature_representation_comparison": feature_rep_results,
        "threshold_tuning": threshold_tuning_report,
        "recommendations": {
            "model": best_cand_name,
            "feature_representation": best_rep_name,
            "class_weighting": best_overall["weighting_strategy"],
            "training_command": f"python3 -m utils.train_models --dataset IDS2018 --model {best_cand_name.split('_')[0].lower()} --force"
        }
    }

    if save_artifacts:
        comparison_path = os.path.join(opt_dir, "validation_candidates_comparison.json")
        with open(comparison_path, "w") as f:
            json.dump(optimization_summary, f, indent=4)

        best_model_report_path = os.path.join(opt_dir, "best_optimized_model.json")
        with open(best_model_report_path, "w") as f:
            json.dump(optimization_summary["recommendations"], f, indent=4)

    print("\n" + "=" * 65, flush=True)
    print("IDS2018 OPTIMIZATION COMPLETED SUCCESSFULLY", flush=True)
    print(f"Top Model: {best_cand_name} (Val Macro F1 = {best_overall['val_macro_f1']:.4f}, Val Acc = {best_overall['val_accuracy']:.4f})", flush=True)
    print(f"Saved reports under: reports/model_training/IDS2018/optimization/", flush=True)
    print("=" * 65 + "\n", flush=True)

    return optimization_summary

def parse_args():
    parser = argparse.ArgumentParser(description="IDS2018 Specialist Validation Optimization Pipeline")
    parser.add_argument("--smoke-test", action="store_true", help="Run lightweight validation optimization test.")
    parser.add_argument("--candidates", type=str, default=None, help="Comma-separated candidate model names.")
    parser.add_argument("--max-train-samples", type=int, default=None, help="Maximum training rows for memory bounds.")
    parser.add_argument("--no-thresholds", action="store_true", help="Disable threshold tuning stage.")
    return parser.parse_args()

def main():
    args = parse_args()
    config = load_config()
    cands = [c.strip() for c in args.candidates.split(",")] if args.candidates else None
    run_ids2018_optimization(
        config=config,
        smoke_test=args.smoke_test,
        max_train_samples=args.max_train_samples,
        candidate_list=cands,
        tune_thresholds_flag=not args.no_thresholds
    )

if __name__ == "__main__":
    main()
