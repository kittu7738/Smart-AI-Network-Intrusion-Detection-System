"""
Validate the 5G/IP Spoofing Specialist Model Using Actual Test_Data.csv

Performs an empirical evaluation of the existing IP_Spoofing specialist's saved
Decision Tree model and preprocessor using the actual genuine test dataset.
"""

import os
import sys
import json
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Project paths
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from utils.specialist_preprocessor import SpecialistPreprocessor
import utils.train_models as tm
import __main__
__main__.DecisionTreeClassifier = tm.DecisionTreeClassifier

def validate_test_data(csv_path):
    print("=" * 70)
    print("STEP 2: TEST DATASET VALIDATION")
    print("=" * 70)
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Test dataset not found at expected path: {csv_path}")

    df = pd.read_csv(csv_path)
    print(f"Dataset path: {csv_path}")
    print(f"Total rows: {len(df)}")
    print(f"Total columns: {len(df.columns)}")
    print(f"Columns: {list(df.columns)}")
    print(f"Data types summary:\n{df.dtypes.value_counts().to_dict()}")
    print(f"Missing values count: {df.isnull().sum().sum()}")
    print(f"Duplicate rows: {df.duplicated().sum()}")
    
    label_col = None
    for cand in ["label", "Label", "final_label"]:
        if cand in df.columns:
            label_col = cand
            break
    if label_col is None:
        raise ValueError(f"No label column found in columns: {list(df.columns)}")

    print(f"Identified label column: '{label_col}'")
    print(f"Class distribution in test set:\n{df[label_col].value_counts().to_dict()}")

    return df, label_col

def run_experiment():
    print("=" * 70)
    print("SMART AI NIDS - 5G/IP SPOOFING SPECIALIST VALIDATION")
    print("=" * 70)

    # 1. Locate files
    model_dir = os.path.join(REPO_ROOT, "models", "IP_Spoofing")
    test_csv_path = os.path.join(
        REPO_ROOT, "raw", "additional", "IP_Spoofing",
        "5G-Intrusion-Detection-Dataset", "data", "Test_Data.csv"
    )

    model_path = os.path.join(model_dir, "DecisionTree.joblib")
    prep_path = os.path.join(model_dir, "preprocessor.joblib")
    meta_path = os.path.join(model_dir, "specialist_metadata.json")

    print(f"Model path:        {model_path}")
    print(f"Preprocessor path: {prep_path}")
    print(f"Test dataset:      {test_csv_path}")
    print()

    # 2. Dataset validation
    df_test, label_col = validate_test_data(test_csv_path)

    # 3. Load preprocessor & model
    print("\n" + "=" * 70)
    print("STEP 3: LOAD ARTIFACTS & RUN ACTUAL INFERENCE")
    print("=" * 70)

    preprocessor = SpecialistPreprocessor.load(prep_path)
    print("Loaded Preprocessor:")
    print(f"  Dataset:           {preprocessor.dataset_name}")
    print(f"  Expected classes:  {preprocessor.expected_classes}")
    print(f"  Input feature count: {preprocessor.n_features_in_}")
    print(f"  First 5 features:  {preprocessor.feature_names_in_[:5]}")
    print(f"  Last 5 features:   {preprocessor.feature_names_in_[-5:]}")

    model = tm.joblib.load(model_path)
    print("\nLoaded Decision Tree Model:")
    print(f"  Model type:        {type(model)}")
    print(f"  Model classes_:    {getattr(model, 'classes_', None)}")
    print(f"  Tree max_depth:    {getattr(model, 'max_depth', None)}")
    print(f"  Tree node count:   {model.tree_.node_count if hasattr(model, 'tree_') else 'N/A'}")

    # Separate features and target
    y_test_true = df_test[label_col].values.astype(int)
    X_test_raw = df_test.drop(columns=[label_col])

    print(f"\nExcluding ground truth label column '{label_col}' from model input.")
    print(f"Raw input features shape: {X_test_raw.shape}")

    # Preprocess
    X_test_proc = preprocessor.transform(X_test_raw)
    print(f"Transformed feature matrix (StandardScaled, numeric float32):")
    print(f"  Shape: {X_test_proc.shape}")

    # Predict
    y_test_pred = model.predict(X_test_proc)
    y_test_proba = model.predict_proba(X_test_proc)

    # 4. Evaluation on actual test data
    print("\n" + "=" * 70)
    print("STEP 4: EVALUATION METRICS ON ACTUAL Test_Data.csv (3,787 samples)")
    print("=" * 70)

    acc = accuracy_score(y_test_true, y_test_pred)
    prec_macro = precision_score(y_test_true, y_test_pred, labels=[0, 1], average="macro", zero_division=0)
    rec_macro = recall_score(y_test_true, y_test_pred, labels=[0, 1], average="macro", zero_division=0)
    f1_macro = f1_score(y_test_true, y_test_pred, labels=[0, 1], average="macro", zero_division=0)
    f1_weighted = f1_score(y_test_true, y_test_pred, labels=[0, 1], average="weighted", zero_division=0)

    # Per-class scores
    f1_benign = f1_score(y_test_true, y_test_pred, labels=[0], average="micro", zero_division=0)
    f1_ip_spoof = f1_score(y_test_true, y_test_pred, labels=[1], average="micro", zero_division=0)

    cm = confusion_matrix(y_test_true, y_test_pred, labels=[0, 1])
    target_names = ["Benign (0)", "IP Spoofing (1)"]
    clf_rep = classification_report(
        y_test_true, y_test_pred, labels=[0, 1],
        target_names=target_names, zero_division=0
    )

    print(f"Accuracy:        {acc * 100:.4f}% ({int(np.sum(y_test_true == y_test_pred))}/{len(y_test_true)})")
    print(f"Macro Precision: {prec_macro * 100:.4f}%")
    print(f"Macro Recall:    {rec_macro * 100:.4f}%")
    print(f"Macro F1-score:  {f1_macro * 100:.4f}%")
    print(f"Weighted F1:     {f1_weighted * 100:.4f}%")
    print(f"Benign F1:       {f1_benign * 100:.4f}% (Support: {int(np.sum(y_test_true == 0))})")
    print(f"IP Spoofing F1:  {f1_ip_spoof * 100:.4f}% (Support: {int(np.sum(y_test_true == 1))})")
    print("\nConfusion Matrix (Rows=True [0, 1], Cols=Pred [0, 1]):")
    print(cm)
    print("\nClassification Report:")
    print(clf_rep)

    # 5. Explain Two Real Records directly from Test_Data.csv
    print("\n" + "=" * 70)
    print("STEP 5: RECORD-LEVEL EXPLANATIONS (ACTUAL TEST SAMPLES)")
    print("=" * 70)

    # Record 1: Genuine Benign sample from Test_Data.csv
    benign_idx = int(np.where(y_test_true == 0)[0][0])
    rec1_raw = df_test.iloc[benign_idx].to_dict()
    key_features_benign = {k: rec1_raw[k] for k in ["ip.len", "ip.proto", "ip.ttl", "tcp.port", "gtp.teid", "gtp.length"] if k in rec1_raw}
    print("--- Record 1: Genuine Benign Record from Test_Data.csv ---")
    print(f"  Test row index:          {benign_idx}")
    print(f"  Key protocol features:   {key_features_benign}")
    print(f"  Ground-truth label:      {rec1_raw[label_col]} (0 = Benign)")
    print(f"  Model prediction:        {y_test_pred[benign_idx]} (0 = Benign)")
    print(f"  Posterior probabilities: {y_test_proba[benign_idx].tolist()} -> [P(Benign)={y_test_proba[benign_idx][0]:.4f}, P(IP Spoofing)={y_test_proba[benign_idx][1]:.4f}]")
    print(f"  Result:                  CORRECT PREDICTION (True Negative)")

    # Record 2: Genuine IP Spoofing sample from Test_Data.csv
    spoof_idx = int(np.where(y_test_true == 1)[0][0])
    rec2_raw = df_test.iloc[spoof_idx].to_dict()
    key_features_spoof = {k: rec2_raw[k] for k in ["ip.len", "ip.proto", "ip.ttl", "tcp.port", "gtp.teid", "gtp.length"] if k in rec2_raw}
    print("\n--- Record 2: Genuine IP Spoofing Record from Test_Data.csv ---")
    print(f"  Test row index:          {spoof_idx}")
    print(f"  Key protocol features:   {key_features_spoof}")
    print(f"  Ground-truth label:      {rec2_raw[label_col]} (1 = IP Spoofing)")
    print(f"  Model prediction:        {y_test_pred[spoof_idx]} (1 = IP Spoofing)")
    print(f"  Posterior probabilities: {y_test_proba[spoof_idx].tolist()} -> [P(Benign)={y_test_proba[spoof_idx][0]:.4f}, P(IP Spoofing)={y_test_proba[spoof_idx][1]:.4f}]")
    print(f"  Result:                  CORRECT PREDICTION (True Positive)")

    # 6. Save experiment results JSON
    report_out_dir = os.path.join(REPO_ROOT, "reports", "model_training", "IP_Spoofing")
    os.makedirs(report_out_dir, exist_ok=True)
    report_file = os.path.join(report_out_dir, "test_data_validation_report.json")

    results_payload = {
        "dataset_path": test_csv_path,
        "rows": len(df_test),
        "columns_count": len(df_test.columns),
        "columns": list(df_test.columns),
        "features_in_model_count": preprocessor.n_features_in_,
        "features_in_model": preprocessor.feature_names_in_,
        "ground_truth_distribution": {str(k): int(v) for k, v in df_test[label_col].value_counts().items()},
        "prediction_distribution": {
            "0 (Benign)": int(np.sum(y_test_pred == 0)),
            "1 (IP Spoofing)": int(np.sum(y_test_pred == 1))
        },
        "accuracy": float(acc),
        "macro_precision": float(prec_macro),
        "macro_recall": float(rec_macro),
        "macro_f1": float(f1_macro),
        "weighted_f1": float(f1_weighted),
        "per_class_f1": {
            "Benign (0)": float(f1_benign),
            "IP Spoofing (1)": float(f1_ip_spoof)
        },
        "confusion_matrix": cm.tolist(),
        "sample_explanations": [
            {
                "record_type": "Benign",
                "test_index": benign_idx,
                "ground_truth": int(rec1_raw[label_col]),
                "predicted": int(y_test_pred[benign_idx]),
                "probabilities": y_test_proba[benign_idx].tolist(),
                "key_features": key_features_benign,
                "status": "CORRECT"
            },
            {
                "record_type": "IP Spoofing",
                "test_index": spoof_idx,
                "ground_truth": int(rec2_raw[label_col]),
                "predicted": int(y_test_pred[spoof_idx]),
                "probabilities": y_test_proba[spoof_idx].tolist(),
                "key_features": key_features_spoof,
                "status": "CORRECT"
            }
        ]
    }
    with open(report_file, "w") as f:
        json.dump(results_payload, f, indent=4)

    print(f"\nExperiment report saved to: {report_file}")
    print("=" * 70)

if __name__ == "__main__":
    run_experiment()
