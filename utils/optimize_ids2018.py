import os
import sys
import json
import time
import argparse
import gc
import tempfile

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
from utils.class_weighting import compute_specialist_sample_weights
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
    tune_validation_thresholds
)
from utils.train_models import (
    load_specialist_splits,
    sample_training_data,
    SPECIALIST_SPECS
)

# Priority order specified for IDS2018 optimization
DEFAULT_PRIORITY_CANDIDATES = [
    "XGBoost_Tuned",
    "HistGradientBoosting",
    "ExtraTrees",
    "RandomForest_Tuned",
    "DecisionTree_Tuned"
]

def load_checkpoint_progress(checkpoint_file: str) -> dict:
    """Load intermediate optimization progress from disk for resume support."""
    if os.path.exists(checkpoint_file):
        try:
            with open(checkpoint_file, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {}

def save_checkpoint_progress(checkpoint_file: str, data: dict):
    """Safely persist intermediate progress with atomic replacement."""
    os.makedirs(os.path.dirname(checkpoint_file), exist_ok=True)
    temp_file = f"{checkpoint_file}.tmp"
    try:
        with open(temp_file, "w") as f:
            json.dump(data, f, indent=4)
        os.replace(temp_file, checkpoint_file)
    except Exception:
        with open(checkpoint_file, "w") as f:
            json.dump(data, f, indent=4)

def run_ids2018_optimization(
    config: dict = None,
    smoke_test: bool = False,
    screening_samples: int = None,
    top_k: int = 2,
    candidate_list: list = None,
    feature_representations: list = None,
    tune_thresholds_flag: bool = True,
    stage_a_only: bool = False,
    force: bool = False,
    save_artifacts: bool = True,
    opt_dir: str = None,
    models_dir: str = None
) -> dict:
    """Execute fast, progressive two-stage optimization for IDS2018 specialist.
    
    STAGE A — Candidate Screening:
      - Deterministic stratified training subset (default 500,000 rows).
      - Preserves 100% of rare minority classes.
      - Candidate-by-candidate progress and checkpointing (supports resume).
      - Evaluated against validation set.
      
    STAGE B — Full Training:
      - Top 2-3 winning candidates from Stage A are trained on full dataset.
      - Evaluated on full validation set.
      - Probability threshold tuning on best full model.
    """
    if config is None:
        config = load_config()

    spec_name = "IDS2018"
    spec_info = SPECIALIST_SPECS[spec_name]
    expected_classes = config["classes"][spec_info["config_class_key"]]

    # Default screening subset size: 500,000 for full runs, 60 for smoke tests
    if screening_samples is None:
        screening_samples = 60 if smoke_test else 500000

    print("\n" + "=" * 70, flush=True)
    print("PROGRESSIVE TWO-STAGE IDS2018 SPECIALIST OPTIMIZATION", flush=True)
    print(f"Goal: Maximize Validation Macro F1 & Accuracy toward ~99% target", flush=True)
    print(f"Stage A Screening Budget: {screening_samples:,} training rows", flush=True)
    print(f"Stage B Full Finalists: Top {top_k} candidates", flush=True)
    print(f"Taxonomy ({len(expected_classes)} classes): {expected_classes}", flush=True)
    print("=" * 70, flush=True)

    if opt_dir is None:
        opt_dir = resolve_path(os.path.join("reports", "model_training", "IDS2018", "optimization"))
    else:
        opt_dir = resolve_path(opt_dir)

    default_prod_opt = resolve_path(os.path.join("reports", "model_training", "IDS2018", "optimization"))
    if models_dir is None:
        if opt_dir != default_prod_opt:
            models_dir = os.path.join(opt_dir, "models")
        elif smoke_test:
            models_dir = os.path.join(tempfile.gettempdir(), "smoke_ids2018_models")
        else:
            models_dir = resolve_path(os.path.join("models", "IDS2018"))
    else:
        models_dir = resolve_path(models_dir)

    if save_artifacts:
        os.makedirs(opt_dir, exist_ok=True)
        os.makedirs(models_dir, exist_ok=True)

    stage_a_ckpt_file = os.path.join(opt_dir, "stage_a_screening_progress.json")
    stage_b_ckpt_file = os.path.join(opt_dir, "stage_b_full_training_progress.json")

    # 1. Load Data Splits (Validation only, test remains strictly untouched)
    train_df, val_source, test_source = load_specialist_splits(
        spec_name, config, smoke_test=smoke_test, lazy_val_test=True
    )
    n_train_raw = len(train_df)
    val_repr = len(val_source) if isinstance(val_source, pd.DataFrame) else "disk (streamed)"
    print(f"Splits initialized: Train={n_train_raw:,} | Val={val_repr} | Test=UNTOUCHED (Preserved)", flush=True)

    # 2. Stage 1: Feature Analysis on Training Data
    feature_analysis_file = os.path.join(opt_dir, "feature_analysis.json")
    if not force and os.path.exists(feature_analysis_file):
        try:
            with open(feature_analysis_file, "r") as f:
                feature_analysis = json.load(f)
            print(f"\n[Feature Analysis] Loaded cached analysis from {feature_analysis_file}", flush=True)
        except Exception:
            feature_analysis = None
    else:
        feature_analysis = None

    if feature_analysis is None:
        feat_preproc = SpecialistPreprocessor(
            dataset_name=spec_name, expected_classes=expected_classes, scale_features=False
        )
        sample_for_feat, _ = sample_training_data(train_df, target_col="final_label", max_samples=min(n_train_raw, 50000), seed=SEED)
        feat_preproc.fit(sample_for_feat)
        raw_feature_names = feat_preproc.feature_names_in_

        print(f"\n--- STAGE 1: Feature Analysis on Training Split ({len(raw_feature_names)} features) ---", flush=True)
        feature_analysis = analyze_features_on_training_data(sample_for_feat, raw_feature_names, target_col="final_label")
        print(f"Constant zero features identified: {len(feature_analysis['constant_features'])} {feature_analysis['constant_features']}", flush=True)
        print(f"Quasi-constant features: {len(feature_analysis['quasi_constant_features'])}", flush=True)
        print(f"High correlation pairs (>0.98): {len(feature_analysis['high_correlation_pairs'])}", flush=True)
        del sample_for_feat, feat_preproc
        gc.collect()

        if save_artifacts:
            with open(feature_analysis_file, "w") as f:
                json.dump(feature_analysis, f, indent=4)

    # 3. Create Deterministic, Stratified Minority-Preserving Screening Subset
    print(f"\n--- Preparing Stage A Screening Subset ({screening_samples:,} rows) ---", flush=True)
    train_screening, screening_meta = sample_training_data(
        train_df, target_col="final_label", max_samples=screening_samples, seed=SEED
    )
    print(f"Screening subset ready: {len(train_screening):,} rows (Method: {screening_meta['sampling_method']}).", flush=True)
    for c_name, c_cnt in train_screening["final_label"].value_counts().items():
        print(f"  - {c_name}: {c_cnt:,} rows", flush=True)

    # Preprocessor fitted strictly on screening subset
    preproc_screen = SpecialistPreprocessor(
        dataset_name=spec_name, expected_classes=expected_classes, scale_features=True
    )
    preproc_screen.fit(train_screening)
    X_train_screen = preproc_screen.transform_features(train_screening)
    y_train_screen = preproc_screen.transform_labels(train_screening)

    # Pre-compute weighting vectors for screening
    screen_weight_vectors = {
        "unweighted": compute_specialist_sample_weights(y_train_screen, strategy="unweighted"),
        "sqrt_balanced": compute_specialist_sample_weights(y_train_screen, strategy="sqrt_balanced"),
        "balanced": compute_specialist_sample_weights(y_train_screen, strategy="balanced")
    }

    # Free raw screening DataFrame to minimize RAM during Stage A
    del train_screening
    gc.collect()

    # 4. STAGE A: Candidate Screening Evaluation
    if candidate_list is None:
        candidate_list = list(DEFAULT_PRIORITY_CANDIDATES)

    print("\n" + "=" * 70, flush=True)
    print(f"STAGE A: CANDIDATE SCREENING ({len(candidate_list)} candidates on {len(X_train_screen):,} rows)", flush=True)
    print("=" * 70, flush=True)

    stage_a_results = load_checkpoint_progress(stage_a_ckpt_file) if not force else {}
    if stage_a_results:
        print(f"[Resume Checkpoint] Found {len(stage_a_results)} completed candidates in Stage A checkpoint.", flush=True)

    for idx, cand_name in enumerate(candidate_list, start=1):
        if cand_name not in OPTIMIZATION_CANDIDATE_CONFIGS:
            print(f"Skipping unknown candidate: {cand_name}", flush=True)
            continue

        cand_cfg = OPTIMIZATION_CANDIDATE_CONFIGS[cand_name]

        # Resume check
        if not force and cand_name in stage_a_results:
            prev = stage_a_results[cand_name]
            print(f"[Stage A {idx}/{len(candidate_list)}] Cached: {cand_name} | Val Macro F1: {prev['val_macro_f1']:.4f} | Accuracy: {prev['val_accuracy']:.4f}", flush=True)
            continue

        print(f"\n[Stage A {idx}/{len(candidate_list)}] Starting Screening Candidate: {cand_name}", flush=True)
        print(f"  Configuration: {cand_cfg['description']}", flush=True)
        print(f"  Weighting Strategy: {cand_cfg['default_weighting']}", flush=True)

        model_inst = get_candidate_model(cand_name, smoke_test=smoke_test)
        sample_w = None
        if cand_cfg["supports_sample_weight"] and cand_cfg["default_weighting"] in screen_weight_vectors:
            sample_w = screen_weight_vectors[cand_cfg["default_weighting"]]

        t0 = time.time()
        try:
            # Safe fitting with proper sample_weight handling
            if sample_w is not None and cand_name != "HistGradientBoosting":
                model_inst.fit(X_train_screen, y_train_screen, sample_weight=sample_w)
            elif sample_w is not None and cand_name == "HistGradientBoosting":
                try:
                    model_inst.fit(X_train_screen, y_train_screen, sample_weight=sample_w)
                except (TypeError, ValueError):
                    model_inst.fit(X_train_screen, y_train_screen)
            else:
                model_inst.fit(X_train_screen, y_train_screen)
            fit_time = time.time() - t0
            print(f"  Fit Completed in {fit_time:.2f}s", flush=True)

            # Streamed validation evaluation
            t_eval = time.time()
            val_metrics = evaluate_dataset_streamed(
                model_inst, val_source, preproc_screen, expected_classes, batch_size=100000
            )
            eval_time = time.time() - t_eval
            print(f"  Val Completed in {eval_time:.2f}s | Macro F1: {val_metrics['Macro F1']:.4f} | Accuracy: {val_metrics['Accuracy']:.4f}", flush=True)

            stage_a_results[cand_name] = {
                "candidate_name": cand_name,
                "stage": "Stage A (Screening)",
                "screening_rows": len(X_train_screen),
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

            # Checkpoint immediately to disk after every candidate
            if save_artifacts:
                save_checkpoint_progress(stage_a_ckpt_file, stage_a_results)

        except Exception as e:
            print(f"  ERROR evaluating candidate {cand_name}: {e}", flush=True)
        finally:
            del model_inst
            gc.collect()

    # Free screening training matrices
    del X_train_screen, y_train_screen, screen_weight_vectors
    gc.collect()

    if not stage_a_results:
        raise RuntimeError("Stage A screening produced no successful candidate results.")

    # Save final Stage A summary
    if save_artifacts:
        stage_a_summary_file = os.path.join(opt_dir, "stage_a_screening.json")
        with open(stage_a_summary_file, "w") as f:
            json.dump(stage_a_results, f, indent=4)

    # Sort candidates by Validation Macro F1
    sorted_stage_a = sorted(
        stage_a_results.values(),
        key=lambda x: (x["val_macro_f1"], x["val_accuracy"]),
        reverse=True
    )

    print("\n" + "=" * 70, flush=True)
    print("STAGE A SCREENING LEADERBOARD", flush=True)
    print("=" * 70, flush=True)
    print(f"{'Rank':<5} {'Candidate':<24} {'Val Macro F1':<14} {'Val Accuracy':<14} {'Fit Time (s)':<12}", flush=True)
    print("-" * 70, flush=True)
    for r_idx, c_res in enumerate(sorted_stage_a, start=1):
        print(f"{r_idx:<5} {c_res['candidate_name']:<24} {c_res['val_macro_f1']:<14.4f} {c_res['val_accuracy']:<14.4f} {c_res['fit_time_seconds']:<12.2f}", flush=True)
    print("-" * 70, flush=True)

    # Select Top K Candidates for Stage B Full Training
    top_candidates = [c["candidate_name"] for c in sorted_stage_a[:top_k]]
    print(f"\n>> Selected Top {len(top_candidates)} Finalists for Stage B Full Training: {top_candidates}", flush=True)

    stage_b_results = {}
    best_overall_cand = top_candidates[0]

    if stage_a_only:
        print("\n[Notice] --stage-a-only requested; skipping Stage B full training.", flush=True)
    else:
        # 5. STAGE B: Full Training of Finalists on Full Training Set
        print("\n" + "=" * 70, flush=True)
        print(f"STAGE B: FULL TRAINING ON {n_train_raw:,} ROWS ({len(top_candidates)} finalists)", flush=True)
        print("=" * 70, flush=True)

        stage_b_results = load_checkpoint_progress(stage_b_ckpt_file) if not force else {}
        if stage_b_results:
            print(f"[Resume Checkpoint] Found {len(stage_b_results)} completed finalists in Stage B checkpoint.", flush=True)

        # Preprocessor for full dataset
        preproc_full = SpecialistPreprocessor(
            dataset_name=spec_name, expected_classes=expected_classes, scale_features=True
        )
        preproc_full.fit(train_df)
        if save_artifacts:
            preproc_full.save(os.path.join(models_dir, "preprocessor.joblib"))
            preproc_full.save(os.path.join(models_dir, "candidate_preprocessor.joblib"))
        X_train_full = preproc_full.transform_features(train_df)
        y_train_full = preproc_full.transform_labels(train_df)

        full_weight_vectors = {
            "unweighted": compute_specialist_sample_weights(y_train_full, strategy="unweighted"),
            "sqrt_balanced": compute_specialist_sample_weights(y_train_full, strategy="sqrt_balanced"),
            "balanced": compute_specialist_sample_weights(y_train_full, strategy="balanced")
        }

        for b_idx, cand_name in enumerate(top_candidates, start=1):
            cand_cfg = OPTIMIZATION_CANDIDATE_CONFIGS[cand_name]

            # Resume check for Stage B
            if not force and cand_name in stage_b_results:
                prev = stage_b_results[cand_name]
                print(f"[Stage B {b_idx}/{len(top_candidates)}] Cached: {cand_name} | Full Val Macro F1: {prev['val_macro_f1']:.4f} | Accuracy: {prev['val_accuracy']:.4f}", flush=True)
                continue

            print(f"\n[Stage B {b_idx}/{len(top_candidates)}] Training Full Finalist: {cand_name} on {n_train_raw:,} rows...", flush=True)
            model_inst = get_candidate_model(cand_name, smoke_test=smoke_test)
            sample_w = None
            if cand_cfg["supports_sample_weight"] and cand_cfg["default_weighting"] in full_weight_vectors:
                sample_w = full_weight_vectors[cand_cfg["default_weighting"]]

            t0 = time.time()
            try:
                if sample_w is not None and cand_name != "HistGradientBoosting":
                    model_inst.fit(X_train_full, y_train_full, sample_weight=sample_w)
                elif sample_w is not None and cand_name == "HistGradientBoosting":
                    try:
                        model_inst.fit(X_train_full, y_train_full, sample_weight=sample_w)
                    except (TypeError, ValueError):
                        model_inst.fit(X_train_full, y_train_full)
                else:
                    model_inst.fit(X_train_full, y_train_full)
                fit_time = time.time() - t0
                print(f"  Full Fit Completed in {fit_time:.2f}s", flush=True)

                # Save candidate full model to models/
                cand_model_path = os.path.join(models_dir, f"candidate_{cand_name}.joblib")
                if save_artifacts:
                    joblib.dump(model_inst, cand_model_path)

                # Streamed evaluation on full validation set
                t_eval = time.time()
                val_metrics = evaluate_dataset_streamed(
                    model_inst, val_source, preproc_full, expected_classes, batch_size=100000
                )
                eval_time = time.time() - t_eval
                print(f"  Full Val Completed in {eval_time:.2f}s | Macro F1: {val_metrics['Macro F1']:.4f} | Accuracy: {val_metrics['Accuracy']:.4f}", flush=True)

                stage_b_results[cand_name] = {
                    "candidate_name": cand_name,
                    "stage": "Stage B (Full Training)",
                    "training_rows": n_train_raw,
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

                if save_artifacts:
                    save_checkpoint_progress(stage_b_ckpt_file, stage_b_results)

            except Exception as e:
                print(f"  ERROR training full finalist {cand_name}: {e}", flush=True)
            finally:
                del model_inst
                gc.collect()

        # Free full training matrix
        del X_train_full, y_train_full, full_weight_vectors
        gc.collect()

        if stage_b_results:
            sorted_stage_b = sorted(
                stage_b_results.values(),
                key=lambda x: (x["val_macro_f1"], x["val_accuracy"]),
                reverse=True
            )
            best_overall_cand = sorted_stage_b[0]["candidate_name"]

            print("\n" + "=" * 70, flush=True)
            print("STAGE B FULL TRAINING LEADERBOARD", flush=True)
            print("=" * 70, flush=True)
            print(f"{'Rank':<5} {'Candidate':<24} {'Val Macro F1':<14} {'Val Accuracy':<14} {'Fit Time (s)':<12}", flush=True)
            print("-" * 70, flush=True)
            for r_idx, c_res in enumerate(sorted_stage_b, start=1):
                print(f"{r_idx:<5} {c_res['candidate_name']:<24} {c_res['val_macro_f1']:<14.4f} {c_res['val_accuracy']:<14.4f} {c_res['fit_time_seconds']:<12.2f}", flush=True)
            print("-" * 70, flush=True)

            if save_artifacts:
                stage_b_summary_file = os.path.join(opt_dir, "stage_b_full_training.json")
                with open(stage_b_summary_file, "w") as f:
                    json.dump(stage_b_results, f, indent=4)

    # 6. Stage 4: Decision Threshold Tuning on Winning Model
    threshold_tuning_report = {}
    if tune_thresholds_flag:
        print("\n" + "-" * 70, flush=True)
        print(f"--- DECISION THRESHOLD TUNING ON BEST MODEL: {best_overall_cand} ---", flush=True)
        print("-" * 70, flush=True)

        top_model_path = os.path.join(models_dir, f"candidate_{best_overall_cand}.joblib")
        if os.path.exists(top_model_path):
            best_model_inst = joblib.load(top_model_path)
            eval_preproc = preproc_full if 'preproc_full' in locals() else preproc_screen
            val_df_loaded = pd.read_parquet(val_source) if isinstance(val_source, str) else val_source
            X_val = eval_preproc.transform_features(val_df_loaded)
            y_val = eval_preproc.transform_labels(val_df_loaded)

            if hasattr(best_model_inst, "predict_proba"):
                print("Computing validation posterior probabilities for calibration...", flush=True)
                y_val_prob = best_model_inst.predict_proba(X_val)
                model_classes = getattr(best_model_inst, "classes_", None)
                threshold_tuning_report, best_multipliers = tune_validation_thresholds(
                    y_true=y_val, y_prob=y_val_prob, class_names=expected_classes, benign_idx=0, model_classes=model_classes
                )
                print(f"Threshold Optimization Complete:", flush=True)
                print(f"  Baseline Macro F1: {threshold_tuning_report['baseline']['macro_f1']:.4f} -> Calibrated: {threshold_tuning_report['optimized']['macro_f1']:.4f}", flush=True)
                print(f"  Baseline Accuracy: {threshold_tuning_report['baseline']['accuracy']:.4f} -> Calibrated: {threshold_tuning_report['optimized']['accuracy']:.4f}", flush=True)
                print(f"  Benign FPR: {threshold_tuning_report['baseline']['benign_fpr']:.4f} -> {threshold_tuning_report['optimized']['benign_fpr']:.4f}", flush=True)

                if save_artifacts:
                    with open(os.path.join(opt_dir, "threshold_tuning.json"), "w") as f:
                        json.dump(threshold_tuning_report, f, indent=4)
            del best_model_inst, X_val, y_val
            gc.collect()

    # Free remaining train dataframe
    del train_df
    gc.collect()

    # 7. Final Selection & Report Packaging
    best_results = stage_b_results.get(best_overall_cand) or stage_a_results[best_overall_cand]
    final_model_name_for_cli = best_overall_cand.split("_")[0].lower()

    optimization_summary = {
        "dataset": spec_name,
        "search_strategy": "Progressive Two-Stage (Stage A Screening + Stage B Full Training)",
        "primary_selection_metric": "Validation Macro F1",
        "selected_best_model": best_overall_cand,
        "best_validation_metrics": {
            "Accuracy": best_results["val_accuracy"],
            "Macro F1": best_results["val_macro_f1"],
            "Macro Precision": best_results["val_macro_precision"],
            "Macro Recall": best_results["val_macro_recall"],
            "Weighted F1": best_results["val_weighted_f1"]
        },
        "stage_a_screening": stage_a_results,
        "stage_b_full_training": stage_b_results,
        "threshold_tuning": threshold_tuning_report,
        "recommendations": {
            "model": best_overall_cand,
            "class_weighting": best_results["weighting_strategy"],
            "model_path": os.path.join(models_dir, f"candidate_{best_overall_cand}.joblib"),
            "threshold_multipliers": threshold_tuning_report.get("optimized", {}).get("multipliers", None),
            "evaluation_command": "python3 -m utils.train_models --dataset IDS2018 --evaluate-only --optimized",
            "training_command": f"python3 -m utils.train_models --dataset IDS2018 --model {best_overall_cand.lower()} --force"
        }
    }

    if save_artifacts:
        comparison_path = os.path.join(opt_dir, "validation_candidates_comparison.json")
        with open(comparison_path, "w") as f:
            json.dump(optimization_summary, f, indent=4)

        best_model_report_path = os.path.join(opt_dir, "best_optimized_model.json")
        with open(best_model_report_path, "w") as f:
            json.dump(optimization_summary["recommendations"], f, indent=4)

    print("\n" + "=" * 70, flush=True)
    print("PROGRESSIVE IDS2018 OPTIMIZATION COMPLETED SUCCESSFULLY", flush=True)
    print(f"Selected Winning Model: {best_overall_cand}", flush=True)
    print(f"Validation Macro F1: {best_results['val_macro_f1']:.4f} | Validation Accuracy: {best_results['val_accuracy']:.4f}", flush=True)
    print(f"Saved artifacts under: reports/model_training/IDS2018/optimization/", flush=True)
    print(f"Recommended Colab Evaluation Command: {optimization_summary['recommendations']['evaluation_command']}", flush=True)
    print("=" * 70 + "\n", flush=True)

    return optimization_summary

def parse_args():
    parser = argparse.ArgumentParser(description="IDS2018 Progressive Two-Stage Validation Optimization Pipeline")
    parser.add_argument("--smoke-test", action="store_true", help="Run lightweight smoke test.")
    parser.add_argument("--screening-samples", type=int, default=None, help="Stage A screening sample size (default 500,000).")
    parser.add_argument("--top-k", type=int, default=2, help="Number of Stage A finalists to train on full dataset in Stage B.")
    parser.add_argument("--candidates", type=str, default=None, help="Comma-separated candidate list.")
    parser.add_argument("--stage-a-only", "--skip-stage-b", action="store_true", dest="stage_a_only", help="Run Stage A screening only.")
    parser.add_argument("--force", action="store_true", help="Ignore cached checkpoints and force re-run.")
    parser.add_argument("--no-thresholds", action="store_true", help="Disable threshold tuning.")
    return parser.parse_args()

def main():
    args = parse_args()
    config = load_config()
    cands = [c.strip() for c in args.candidates.split(",")] if args.candidates else None
    
    screening_samples = args.screening_samples
    if screening_samples is None and "NIDS_SCREENING_SAMPLES" in os.environ:
        try:
            screening_samples = int(os.environ["NIDS_SCREENING_SAMPLES"])
        except ValueError:
            pass

    run_ids2018_optimization(
        config=config,
        smoke_test=args.smoke_test,
        screening_samples=screening_samples,
        top_k=args.top_k,
        candidate_list=cands,
        stage_a_only=args.stage_a_only,
        force=args.force,
        tune_thresholds_flag=not args.no_thresholds
    )

if __name__ == "__main__":
    main()
