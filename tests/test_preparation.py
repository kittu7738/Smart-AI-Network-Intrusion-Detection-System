import os
import unittest
import pandas as pd
import numpy as np
import sys

# Ensure utils is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.data_preparation import handle_invalid_numeric, check_leakage, split_stratified, load_config

class TestDataPreparation(unittest.TestCase):
    
    def test_invalid_numeric_handling(self):
        df = pd.DataFrame({
            "A": [1, 2, np.inf, 4],
            "B": [-np.inf, 2, 3, 4],
            "C": [1, np.nan, 3, 4],
            "D": [1, 2, 3, 4] # only last row is fully valid
        })
        clean_df, dropped = handle_invalid_numeric(df)
        self.assertEqual(len(clean_df), 1)
        self.assertEqual(dropped, 3)
        self.assertEqual(clean_df.iloc[0]["D"], 4)
        
    def test_leakage_detection(self):
        df = pd.DataFrame({
            "Target": [1, 0, 1],
            "SourceIP": ["192", "192", "192"],
            "Timestamp": [123, 124, 125],
            "NormalFeature": [5, 6, 7],
            "Constant": [9, 9, 9]
        })
        suspicious, constant = check_leakage(df, "Target")
        self.assertIn("SourceIP", suspicious)
        self.assertIn("Timestamp", suspicious)
        self.assertIn("Constant", constant)
        self.assertNotIn("NormalFeature", suspicious)
        self.assertNotIn("NormalFeature", constant)
        
    def test_split_integrity_and_stratification(self):
        # Create dummy df with 10 rows
        df = pd.DataFrame({
            "Feature": range(100),
            "Label": ["Benign"]*60 + ["DDoS"]*40
        })
        X_train, X_val, X_test = split_stratified(df, "Label", seed=42)
        
        self.assertEqual(len(X_train), 70)
        self.assertEqual(len(X_val), 15)
        self.assertEqual(len(X_test), 15)
        
        # Check stratification for DDoS
        train_ddos = len(X_train[X_train["Label"] == "DDoS"])
        self.assertEqual(train_ddos, 28) # 70% of 40 = 28
        
    def test_config_loading(self):
        # This tests that the pipeline can load its config properly
        config = load_config()
        self.assertIn("paths", config)
        self.assertIn("version", config)
        self.assertIn("raw_ids2018", config["paths"])

    def test_resolve_path_with_env(self):
        from utils.data_preparation import resolve_path
        os.environ["NIDS_DATA_ROOT"] = "/test_drive_root"
        
        # Test specific Colab mappings
        self.assertEqual(resolve_path("Datasets/ids2018_combined_7attacks_benign.parquet"), "/test_drive_root/raw/IDS2018/ids2018_combined_7attacks_benign.parquet")
        self.assertEqual(resolve_path("Datasets/CICIOT23"), "/test_drive_root/raw/CICIoT2023")
        self.assertEqual(resolve_path("data/processed/IDS2018"), "/test_drive_root/processed/IDS2018")
        
        # Test generic fallback
        self.assertEqual(resolve_path("config/preprocessing_config.json"), "/test_drive_root/config/preprocessing_config.json")
        
        del os.environ["NIDS_DATA_ROOT"]

    def test_process_ciciot2023_missing_file_contract(self):
        # Tests that process_file_chunked properly returns 3 values (None, set(), 0) when missing,
        # avoiding a ValueError unpack exception.
        from utils.data_preparation import process_ciciot2023
        config = load_config()
        
        # Point to a fake raw directory that definitely doesn't exist
        config["paths"]["raw_ciciot2023_dir"] = "fake_non_existent_directory_for_test"
        config["paths"]["processed_ciciot2023"] = "fake_non_existent_processed_dir"
        
        # Should gracefully return None because train.csv is missing
        mapping = {"CICIoT2023": {}}
        result = process_ciciot2023(config, mapping)
        self.assertIsNone(result)

    def test_update_env_checkpoint_missing_key(self):
        import json
        import tempfile
        from utils.data_preparation import update_env_checkpoint
        
        # Create a temporary progress.json without the "checkpoints" key
        with tempfile.TemporaryDirectory() as tmpdir:
            # We must monkeypatch resolve_path temporarily to write to our tmpdir
            # or just change NIDS_PROJECT_ROOT so resolve_path writes there
            os.environ["NIDS_PROJECT_ROOT"] = tmpdir
            
            progress_path = os.path.join(tmpdir, "checkpoints", "progress.json")
            os.makedirs(os.path.dirname(progress_path), exist_ok=True)
            
            # Write invalid config without 'checkpoints' key
            with open(progress_path, "w") as f:
                json.dump({"some_other_key": {}}, f)
                
            # Should safely initialize 'checkpoints' and update
            update_env_checkpoint("test_key", "Success")
            
            # Verify
            with open(progress_path, "r") as f:
                cfg = json.load(f)
                
            self.assertIn("some_other_key", cfg)
            self.assertIn("checkpoints", cfg)
            self.assertEqual(cfg["checkpoints"]["test_key"], "Success")
            
            del os.environ["NIDS_PROJECT_ROOT"]

if __name__ == '__main__':
    unittest.main()
