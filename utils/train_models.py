import os
import json
import time
import pandas as pd
import numpy as np
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.utils.class_weight import compute_class_weight

BASE_DIR = os.environ.get("NIDS_PROJECT_ROOT", os.getcwd())
SEED = 42

def update_checkpoint(dataset, model, status):
    ckpt_path = os.path.join(BASE_DIR, "checkpoints", "progress.json")
    if os.path.exists(ckpt_path):
        with open(ckpt_path, "r") as f:
            cfg = json.load(f)
    else:
        cfg = {"model_training": {}}
        
    if "model_training" not in cfg:
        cfg["model_training"] = {}
    if dataset not in cfg["model_training"]:
        cfg["model_training"][dataset] = {}
        
    cfg["model_training"][dataset][model] = status
    with open(ckpt_path, "w") as f:
        json.dump(cfg, f, indent=4)

def check_status(dataset, model):
    ckpt_path = os.path.join(BASE_DIR, "checkpoints", "progress.json")
    if os.path.exists(ckpt_path):
        with open(ckpt_path, "r") as f:
            cfg = json.load(f)
            return cfg.get("model_training", {}).get(dataset, {}).get(model, "not_started")
    return "not_started"

def get_sampled_data(df, target_col, max_rows=200000, seed=42):
    """Deterministic sampling to avoid OOM on 8GB system.
       Keeps all minority class samples and downsamples majority."""
    class_counts = df[target_col].value_counts()
    n_classes = len(class_counts)
    
    # Fairly distribute allowed rows, but cap at actual count
    target_per_class = max_rows // n_classes
    
    sampled_dfs = []
    for cls, count in class_counts.items():
        cls_df = df[df[target_col] == cls]
        if count > target_per_class:
            sampled_dfs.append(cls_df.sample(n=target_per_class, random_state=seed))
        else:
            sampled_dfs.append(cls_df)
            
    return pd.concat(sampled_dfs).sample(frac=1, random_state=seed)

def evaluate_model(model, X, y, labels):
    preds = model.predict(X)
    acc = accuracy_score(y, preds)
    macro_p = precision_score(y, preds, average='macro', zero_division=0)
    macro_r = recall_score(y, preds, average='macro', zero_division=0)
    macro_f1 = f1_score(y, preds, average='macro', zero_division=0)
    wt_f1 = f1_score(y, preds, average='weighted', zero_division=0)
    
    class_report = classification_report(y, preds, target_names=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y, preds, labels=range(len(labels)))
    
    return {
        "Accuracy": acc,
        "Macro Precision": macro_p,
        "Macro Recall": macro_r,
        "Macro F1": macro_f1,
        "Weighted F1": wt_f1,
        "Per Class": class_report,
        "Confusion Matrix": cm.tolist()
    }

def train_and_evaluate(dataset_name, data_dir, expected_labels):
    print(f"\n--- Processing {dataset_name} ---")
    
    # Load Data
    print("Loading data...")
    train_full = pd.read_parquet(os.path.join(data_dir, "train.parquet"))
    val_full = pd.read_parquet(os.path.join(data_dir, "val.parquet"))
    
    # Sample Data due to 8GB RAM limit
    print("Sampling data to prevent OOM...")
    train = get_sampled_data(train_full, "final_label", 200000, SEED)
    val = get_sampled_data(val_full, "final_label", 50000, SEED)
    
    # Encode labels
    label_map = {k: v for v, k in enumerate(expected_labels)}
    y_train = train["final_label"].map(label_map).fillna(-1).astype(int)
    y_val = val["final_label"].map(label_map).fillna(-1).astype(int)
    
    # Exclude unknown labels
    train_mask = y_train != -1
    val_mask = y_val != -1
    
    X_train = train[train_mask].drop(columns=["final_label"])
    y_train = y_train[train_mask]
    X_val = val[val_mask].drop(columns=["final_label"])
    y_val = y_val[val_mask]
    
    # Free memory
    del train_full
    del val_full
    
    classes_present = np.unique(y_train)
    weights = compute_class_weight('balanced', classes=classes_present, y=y_train)
    weight_dict = {c: w for c, w in zip(classes_present, weights)}
    
    models = {
        "DecisionTree": DecisionTreeClassifier(random_state=SEED, class_weight=weight_dict),
        "RandomForest": RandomForestClassifier(random_state=SEED, class_weight=weight_dict, n_estimators=50, n_jobs=-1),
        "XGBoost": XGBClassifier(random_state=SEED, use_label_encoder=False, eval_metric='mlogloss', n_jobs=-1)
        # XGB handles class weights natively via sample_weight during fit
    }
    
    report_dir = os.path.join(BASE_DIR, "reports", "model_training", dataset_name)
    model_dir = os.path.join(BASE_DIR, "models", dataset_name)
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(model_dir, exist_ok=True)
    
    sample_weights = np.array([weight_dict[y] for y in y_train])
    
    val_results = {}
    
    for name, model in models.items():
        status = check_status(dataset_name, name)
        if status == "completed":
            print(f"Skipping {name} (already completed)")
            with open(os.path.join(report_dir, f"{name}_training.json"), "r") as f:
                r = json.load(f)
                val_results[name] = r["validation_metrics"]
            continue
            
        print(f"Training {name}...")
        update_checkpoint(dataset_name, name, "running")
        
        t0 = time.time()
        try:
            if name == "XGBoost":
                model.fit(X_train, y_train, sample_weight=sample_weights)
            else:
                model.fit(X_train, y_train)
            t_train = time.time() - t0
            
            print(f"Evaluating {name} on Validation Set...")
            metrics = evaluate_model(model, X_val, y_val, expected_labels)
            val_results[name] = metrics
            
            # Save Model
            model_path = os.path.join(model_dir, f"{name}.joblib")
            joblib.dump(model, model_path)
            
            # Save Report
            rep = {
                "dataset": dataset_name,
                "model": name,
                "feature_count": len(X_train.columns),
                "training_row_count": len(X_train),
                "validation_row_count": len(X_val),
                "class_distribution": y_train.value_counts().to_dict(),
                "class_weights": weight_dict,
                "training_duration": t_train,
                "validation_metrics": metrics,
                "model_path": model_path,
                "random_seed": SEED,
                "completion_status": "Success"
            }
            with open(os.path.join(report_dir, f"{name}_training.json"), "w") as f:
                json.dump(rep, f, indent=4)
                
            update_checkpoint(dataset_name, name, "completed")
            
        except Exception as e:
            print(f"Failed to train {name}: {str(e)}")
            update_checkpoint(dataset_name, name, "failed")
            
    # Model Comparison
    comp_data = []
    for name, metrics in val_results.items():
        comp_data.append({
            "Model": name,
            "Accuracy": metrics["Accuracy"],
            "Macro Precision": metrics["Macro Precision"],
            "Macro Recall": metrics["Macro Recall"],
            "Macro F1": metrics["Macro F1"],
            "Weighted F1": metrics["Weighted F1"]
        })
    comp_df = pd.DataFrame(comp_data).sort_values(by="Macro F1", ascending=False)
    comp_df.to_json(os.path.join(report_dir, "comparison.json"), orient="records", indent=4)
    print(f"\n{dataset_name} Validation Comparison:")
    print(comp_df.to_string(index=False))
    
    best_model_name = comp_df.iloc[0]["Model"]
    print(f"\nBest Model for {dataset_name}: {best_model_name}")
    
    # Final Test
    print(f"Running FINAL TEST for {dataset_name} using {best_model_name}...")
    test_full = pd.read_parquet(os.path.join(data_dir, "test.parquet"))
    test = get_sampled_data(test_full, "final_label", 50000, SEED)
    y_test = test["final_label"].map(label_map).fillna(-1).astype(int)
    test_mask = y_test != -1
    X_test = test[test_mask].drop(columns=["final_label"])
    y_test = y_test[test_mask]
    
    best_model = joblib.load(os.path.join(model_dir, f"{best_model_name}.joblib"))
    
    # Validation step: reload and small prediction
    sample_pred = best_model.predict(X_test.head(5))
    assert len(sample_pred) == 5, "Model reload validation failed."
    
    test_metrics = evaluate_model(best_model, X_test, y_test, expected_labels)
    
    final_sel = {
        "dataset": dataset_name,
        "best_model": best_model_name,
        "test_row_count": len(X_test),
        "test_metrics": test_metrics,
        "sampling_note": "Due to 8GB RAM constraints, training was deterministically downsampled to max 200k rows (balanced) and eval to 50k rows. Minority classes were strictly preserved.",
        "reload_validation": "Success"
    }
    with open(os.path.join(report_dir, "final_model_selection.json"), "w") as f:
        json.dump(final_sel, f, indent=4)
        
    return comp_df, best_model_name, test_metrics

def main():
    ids_labels = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"]
    ciciot_labels = ["Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack", "Spoofing", "Recon / Port Scan", "MITM"]
    
    ids_dir = os.path.join(BASE_DIR, "data", "processed", "IDS2018")
    ciciot_dir = os.path.join(BASE_DIR, "data", "processed", "CICIoT2023")
    
    comp_ids, best_ids, test_ids = train_and_evaluate("IDS2018", ids_dir, ids_labels)
    comp_iot, best_iot, test_iot = train_and_evaluate("CICIoT2023", ciciot_dir, ciciot_labels)
    
    print("\n================ TRAINING COMPLETE ================")

if __name__ == "__main__":
    main()
