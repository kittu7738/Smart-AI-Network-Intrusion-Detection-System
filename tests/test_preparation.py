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

if __name__ == '__main__':
    unittest.main()
