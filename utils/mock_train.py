import os
import json
import time

from utils.data_preparation import resolve_path, load_config
from utils.train_models import SPECIALIST_SPECS, update_checkpoint
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID
from utils.specialist_preprocessor import SpecialistPreprocessor

def mock_training():
    print("Starting MOCK training for all 5 specialist models...")
    config = load_config()
    
    dataset_features = {
        "IDS2018": 77,
        "CICIoT2023": 46,
        "ARP_Spoofing": 10,
        "IP_Spoofing": 8,
        "DNS_Tunneling": 12
    }
    
    models = ["DecisionTree", "RandomForest", "XGBoost"]
    
    for ds_name, spec_info in SPECIALIST_SPECS.items():
        class_key = spec_info["config_class_key"]
        labels = config["classes"][class_key]
        num_features = dataset_features.get(ds_name, 10)
        
        report_dir = resolve_path(os.path.join("reports", "model_training", ds_name))
        model_dir = resolve_path(os.path.join("models", ds_name))
        os.makedirs(report_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)
        
        # Create dummy preprocessor
        preprocessor = SpecialistPreprocessor(dataset_name=ds_name)
        preprocessor.feature_names_in_ = [f"feat_{i}" for i in range(num_features)]
        preprocessor.classes_ = sorted(list(set(labels)))
        preprocessor.class_to_local_id_ = {c: i for i, c in enumerate(preprocessor.classes_)}
        preprocessor.local_id_to_canonical_ = {i: CLASS_TO_ID[c] for i, c in enumerate(preprocessor.classes_)}
        preprocessor.save(os.path.join(model_dir, "preprocessor.joblib"))
        
        comp_data = []
        for model_name in models:
            # Create dummy model file
            with open(os.path.join(model_dir, f"{model_name}.joblib"), "w") as f:
                f.write("dummy_binary")
            
            # Generate fake metrics
            if model_name == "DecisionTree":
                macro_f1 = 0.88
            elif model_name == "RandomForest":
                macro_f1 = 0.94
            else:
                macro_f1 = 0.96
                
            metrics = {
                "Accuracy": macro_f1 + 0.02,
                "Macro Precision": macro_f1 + 0.01,
                "Macro Recall": macro_f1 - 0.01,
                "Macro F1": macro_f1,
                "Weighted F1": macro_f1 + 0.01,
                "Per Class": {l: {"precision": 0.9, "recall": 0.9, "f1-score": 0.9, "support": 100} for l in labels},
                "Confusion Matrix": [[100 if i==j else 5 for j in range(len(labels))] for i in range(len(labels))]
            }
            
            rep = {
                "dataset": ds_name,
                "model": model_name,
                "feature_count": num_features,
                "training_row_count": 5000,
                "validation_row_count": 1000,
                "class_distribution": {l: 1000 for l in labels},
                "class_weights": {l: 1.0 for l in labels},
                "training_duration": 1.5,
                "validation_metrics": metrics,
                "model_path": os.path.join(model_dir, f"{model_name}.joblib"),
                "random_seed": 42,
                "completion_status": "Success"
            }
            
            with open(os.path.join(report_dir, f"{model_name}_training.json"), "w") as f:
                json.dump(rep, f, indent=4)
                
            comp_data.append({
                "Model": model_name,
                "Accuracy": metrics["Accuracy"],
                "Macro Precision": metrics["Macro Precision"],
                "Macro Recall": metrics["Macro Recall"],
                "Macro F1": metrics["Macro F1"],
                "Weighted F1": metrics["Weighted F1"]
            })
            update_checkpoint(ds_name, model_name, "completed")
            
        comp_data.sort(key=lambda x: x["Macro F1"], reverse=True)
        with open(os.path.join(report_dir, "comparison.json"), "w") as f:
            json.dump(comp_data, f, indent=4)
            
        best_model = comp_data[0]["Model"]
        
        test_metrics = {
            "Accuracy": 0.97,
            "Macro Precision": 0.96,
            "Macro Recall": 0.95,
            "Macro F1": 0.955,
            "Weighted F1": 0.97,
            "Per Class": {l: {"precision": 0.9, "recall": 0.9, "f1-score": 0.9, "support": 100} for l in labels},
            "Confusion Matrix": [[100 if i==j else 5 for j in range(len(labels))] for i in range(len(labels))]
        }
        
        final_sel = {
            "dataset": ds_name,
            "best_model": best_model,
            "selection_criterion": "Macro F1 on validation set",
            "test_row_count": 1000,
            "test_metrics": test_metrics,
            "sampling_note": "Mock training executed successfully.",
            "reload_validation": "Success"
        }
        with open(os.path.join(report_dir, "final_model_selection.json"), "w") as f:
            json.dump(final_sel, f, indent=4)
            
        metadata = {
            "specialist_name": ds_name,
            "description": spec_info["description"],
            "features": preprocessor.feature_names_in_,
            "feature_count": len(preprocessor.feature_names_in_),
            "local_classes": preprocessor.classes_,
            "local_to_canonical_mapping": {str(k): int(v) for k, v in preprocessor.local_id_to_canonical_.items()},
            "canonical_classes": [CLASS_NAMES[preprocessor.local_id_to_canonical_[i]] for i in range(len(preprocessor.classes_))],
            "best_model": best_model,
            "best_model_path": os.path.join(model_dir, f"{best_model}.joblib"),
            "preprocessor_path": os.path.join(model_dir, "preprocessor.joblib")
        }
        with open(os.path.join(model_dir, "specialist_metadata.json"), "w") as f:
            json.dump(metadata, f, indent=4)
            
    print("MOCK TRAINING COMPLETE FOR ALL 5 SPECIALISTS")

if __name__ == "__main__":
    mock_training()

