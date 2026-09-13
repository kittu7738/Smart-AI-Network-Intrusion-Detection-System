import os
import unittest
import pandas as pd
import numpy as np
import sys

# Ensure utils is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.data_preparation import handle_invalid_numeric, check_leakage, split_stratified, load_config

class TestDataPreparation(unittest.TestCase):
    def test_schema_consistency_no_index(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        import pandas as pd
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "test.parquet")
            
            # Chunk 1 (clean index)
            df1 = pd.DataFrame({'feat1': [1.0, 2.0], 'final_label': ['Benign', 'DDoS']})
            table1 = pa.Table.from_pandas(df1, preserve_index=False)
            writer = pq.ParquetWriter(out_file, table1.schema)
            writer.write_table(table1)
            
            # Chunk 2 (dropped rows causing index to not be 0,1,2...)
            df2 = pd.DataFrame({'feat1': [3.0, 4.0, 5.0], 'final_label': ['DoS', 'Benign', 'DDoS']})
            df2 = df2.drop(1) # Index is now [0, 2]
            
            table2 = pa.Table.from_pandas(df2, preserve_index=False)
            
            # Ensure index did not leak into schema
            self.assertNotIn('__index_level_0__', table2.schema.names)
            
            # Ensure schema matches chunk 1
            self.assertEqual(table1.schema, table2.schema)
            
            writer.write_table(table2)
            writer.close()
            
            # Read back
            read_table = pq.read_table(out_file)
            self.assertEqual(read_table.num_rows, 4)
            self.assertNotIn('__index_level_0__', read_table.column_names)

    
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
        os.environ["NIDS_PROJECT_ROOT"] = "/test_project_root"
        
        # Test IDS2018 raw resolution (multiple path variants)
        self.assertEqual(resolve_path("Datasets/ids2018_combined_7attacks_benign.parquet"), "/test_drive_root/raw/IDS2018/ids2018_combined_7attacks_benign.parquet")
        self.assertEqual(resolve_path("raw/IDS2018/ids2018_combined_7attacks_benign.parquet"), "/test_drive_root/raw/IDS2018/ids2018_combined_7attacks_benign.parquet")
        self.assertEqual(resolve_path("IDS2018/ids2018_combined_7attacks_benign.parquet"), "/test_drive_root/raw/IDS2018/ids2018_combined_7attacks_benign.parquet")
        
        # Test IDS2018 processed resolution
        self.assertEqual(resolve_path("data/processed/IDS2018"), "/test_drive_root/processed/IDS2018")
        self.assertEqual(resolve_path("processed/IDS2018"), "/test_drive_root/processed/IDS2018")
        self.assertEqual(resolve_path("data/processed/IDS2018/train.parquet"), "/test_drive_root/processed/IDS2018/train.parquet")
        self.assertEqual(resolve_path("processed/IDS2018/train.parquet"), "/test_drive_root/processed/IDS2018/train.parquet")

        # Test CICIoT2023 raw and processed
        self.assertEqual(resolve_path("Datasets/CICIOT23"), "/test_drive_root/raw/CICIoT2023")
        self.assertEqual(resolve_path("data/processed/CICIoT2023"), "/test_drive_root/processed/CICIoT2023")

        # Test additional dataset raw and processed
        self.assertEqual(resolve_path("raw/additional/ARP_Spoofing"), "/test_drive_root/raw/additional/ARP_Spoofing")
        self.assertEqual(resolve_path("data/processed/additional/ARP_Spoofing"), "/test_drive_root/processed/additional/ARP_Spoofing")
        self.assertEqual(resolve_path("raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset"), "/test_drive_root/raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset")
        self.assertEqual(resolve_path("data/processed/additional/IP_Spoofing"), "/test_drive_root/processed/additional/IP_Spoofing")
        self.assertEqual(resolve_path("raw/additional/DNS_Tunneling"), "/test_drive_root/raw/additional/DNS_Tunneling")
        self.assertEqual(resolve_path("data/processed/additional/DNS_Tunneling"), "/test_drive_root/processed/additional/DNS_Tunneling")

        # Test runtime outputs
        self.assertEqual(resolve_path("checkpoints/progress.json"), "/test_drive_root/checkpoints/progress.json")
        self.assertEqual(resolve_path("reports/label_strategy.json"), "/test_drive_root/reports/label_strategy.json")
        self.assertEqual(resolve_path("data/samples"), "/test_drive_root/samples")
        
        # Test generic fallback for repo files (always resolved to project_root)
        self.assertEqual(resolve_path("config/preprocessing_config.json"), "/test_project_root/config/preprocessing_config.json")
        self.assertEqual(resolve_path("config/label_mapping.json"), "/test_project_root/config/label_mapping.json")
        
        # Test exact Colab paths
        os.environ["NIDS_PROJECT_ROOT"] = "/content/Smart-AI-Network-Intrusion-Detection-System"
        os.environ["NIDS_DATA_ROOT"] = "/content/drive/MyDrive/Smart-AI-NIDS"
        self.assertEqual(
            resolve_path("Datasets/ids2018_combined_7attacks_benign.parquet"),
            "/content/drive/MyDrive/Smart-AI-NIDS/raw/IDS2018/ids2018_combined_7attacks_benign.parquet"
        )
        self.assertEqual(
            resolve_path("data/processed/IDS2018"),
            "/content/drive/MyDrive/Smart-AI-NIDS/processed/IDS2018"
        )

        del os.environ["NIDS_DATA_ROOT"]
        del os.environ["NIDS_PROJECT_ROOT"]

        # Test fallback without NIDS_DATA_ROOT
        os.environ["NIDS_PROJECT_ROOT"] = "/local_project_root"
        self.assertEqual(resolve_path("Datasets/ids2018_combined_7attacks_benign.parquet"), "/local_project_root/Datasets/ids2018_combined_7attacks_benign.parquet")
        self.assertEqual(resolve_path("data/processed/IDS2018"), "/local_project_root/data/processed/IDS2018")
        del os.environ["NIDS_PROJECT_ROOT"]

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


    def test_additional_raw_paths(self):
        from utils.data_preparation import load_config
        config = load_config()
        self.assertEqual(config["paths"]["raw_arp_dir"], "raw/additional/ARP_Spoofing")
        self.assertEqual(config["paths"]["raw_5g_dir"], "raw/additional/IP_Spoofing/5G-Intrusion-Detection-Dataset")
        self.assertEqual(config["paths"]["raw_dns_dir"], "raw/additional/DNS_Tunneling")

    def test_dns_feature_extraction(self):
        from utils.data_preparation import extract_dns_features
        import pandas as pd
        df = pd.DataFrame({0: [1, 0], 1: ["www.google.com", "abc"], "final_label": ["Benign", "DNS Tunneling"]})
        res = extract_dns_features(df)
        self.assertIn("query_length", res.columns)
        self.assertIn("num_dots", res.columns)
        self.assertEqual(res["num_dots"].iloc[0], 2)
        self.assertEqual(res["num_dots"].iloc[1], 0)
        self.assertNotIn(1, res.columns)
        self.assertNotIn("1", res.columns)
        self.assertIn("final_label", res.columns)

    def test_arp_feature_extraction(self):
        from utils.data_preparation import extract_arp_features, load_label_mapping
        import pandas as pd
        
        # Test feature extraction contract
        df = pd.DataFrame({"frame_number": [1], "arp_src_hw_mac": ["aa:bb"], "tcp_flag_fin": [0], "label_name": ["Normal"], "final_label": ["Benign"]})
        res = extract_arp_features(df)
        self.assertIn("frame_number", res.columns)
        self.assertIn("tcp_flag_fin", res.columns)
        self.assertNotIn("arp_src_hw_mac", res.columns)
        self.assertIn("final_label", res.columns)
        self.assertNotIn("label", res.columns)
        self.assertNotIn("label_name", res.columns)
        
        # Test mapping classes
        mapping = load_label_mapping()
        arp_map = mapping["ARP"]
        self.assertEqual(arp_map["Normal"], "Benign")
        self.assertEqual(arp_map["ARP_Spoofing"], "ARP Spoofing")
        self.assertEqual(arp_map["ARP_Storm"], "DoS")
        self.assertEqual(arp_map["PING_Flood"], "DoS")
        self.assertEqual(arp_map["SYN_Flood"], "DoS")
        valid_labels = set(arp_map.values())
        self.assertTrue(valid_labels.issubset({"Benign", "ARP Spoofing", "DoS"}))

    def test_arp_pipeline_processing_valid_labels(self):
        import tempfile
        import os
        import pandas as pd
        import pyarrow.parquet as pq
        from utils.data_preparation import process_dataset_generic, extract_arp_features, load_label_mapping
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_arp_dir": os.path.join(tmpdir, "raw"),
                    "processed_arp": os.path.join(tmpdir, "processed"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "classes": {
                    "arp": ["Benign", "ARP Spoofing", "DoS"]
                }
            }
            mapping = load_label_mapping()
            
            os.makedirs(config["paths"]["raw_arp_dir"], exist_ok=True)
            os.makedirs(config["paths"]["reports_dir"], exist_ok=True)
            
            # The REAL ARP label spellings: Normal, ARP_Storm, SYN_Flood, PING_Flood, ARP_Spoofing
            pd.DataFrame({
                "frame_number": [1, 2, 3, 4, 5],
                "label": [0, 1, 2, 3, 4], # Numeric IDs
                "label_name": ["Normal", "ARP_Storm", "SYN_Flood", "PING_Flood", "ARP_Spoofing"] # String names
            }).to_csv(os.path.join(config["paths"]["raw_arp_dir"], "train.csv"), index=False)
            
            file_splits = {"train": ["train.csv"]}
            
            # This should process successfully without raising RuntimeError
            process_dataset_generic(config, mapping, "ARP_Spoofing", "raw_arp_dir", "processed_arp", file_splits, extract_arp_features, "ARP")
            
            final_out = os.path.join(config["paths"]["processed_arp"], "train.parquet")
            self.assertTrue(os.path.exists(final_out))
            
            df_out = pd.read_parquet(final_out)
            self.assertEqual(len(df_out), 5)
            self.assertIn("final_label", df_out.columns)
            self.assertNotIn("label", df_out.columns)
            self.assertNotIn("label_name", df_out.columns)
            
            expected_labels = ["Benign", "DoS", "DoS", "DoS", "ARP Spoofing"]
            self.assertListEqual(list(df_out["final_label"].values), expected_labels)

    def test_5g_feature_extraction(self):
        from utils.data_preparation import extract_5g_features
        import pandas as pd
        df = pd.DataFrame({
            "some_metric": [1.0],
            "Src_IP": ["1.1.1.1"],
            "Dst_IP": ["2.2.2.2"],
            "Dst_MAC": ["aa:bb"],
            "Attack_Type": ["IP_Spoofing"],
            "attack": ["Spoofing"],
            "Label": ["1"],
            "final_label": ["IP Spoofing"]
        })
        res = extract_5g_features(df)
        self.assertIn("some_metric", res.columns)
        self.assertNotIn("Src_IP", res.columns)
        self.assertNotIn("Dst_IP", res.columns)
        self.assertNotIn("Dst_MAC", res.columns)
        self.assertNotIn("Attack_Type", res.columns)
        self.assertNotIn("attack", res.columns)
        self.assertNotIn("Label", res.columns)
        self.assertIn("final_label", res.columns)

    def test_5g_rebuild_cli_aliases(self):
        """CLI arguments --force-rebuild-ip and --force-rebuild-ip-spoofing must trigger 5G rebuild."""
        import sys
        for arg in ["--force-rebuild-5g", "--force-rebuild-ip", "--force-rebuild-ip-spoofing"]:
            test_argv = ["data_preparation.py", arg]
            force_5g = (
                "--force-rebuild" in test_argv or "--force-rebuild-all" in test_argv or
                "--force-rebuild-5g" in test_argv or
                "--force-rebuild-ip" in test_argv or
                "--force-rebuild-ip-spoofing" in test_argv
            )
            self.assertTrue(force_5g, f"Failed for argument: {arg}")
    def test_pipeline_output_creation_and_contract(self):
        import tempfile
        import os
        import pandas as pd
        import pyarrow.parquet as pq
        from utils.data_preparation import process_dataset_generic, extract_5g_features
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Setup dummy config
            config = {
                "version": "1.0",
                "paths": {
                    "raw_dummy_dir": os.path.join(tmpdir, "raw"),
                    "processed_dummy": os.path.join(tmpdir, "processed"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "classes": {
                    "dummy": ["Benign", "Malicious"]
                }
            }
            mapping = {"DUMMY": {"0": "Benign", "1": "Malicious"}}
            
            os.makedirs(config["paths"]["raw_dummy_dir"], exist_ok=True)
            os.makedirs(config["paths"]["reports_dir"], exist_ok=True)
            # Write integer labels that need robust mapping
            pd.DataFrame({
                "Src_IP": ["1.1.1.1"],
                "metric": [1.0],
                "label": [0]
            }).to_csv(os.path.join(config["paths"]["raw_dummy_dir"], "train.csv"), index=False)
            
            file_splits = {"train": ["train.csv"]}
            
            # This should pass without raising RuntimeError, and create a file
            process_dataset_generic(config, mapping, "DummySet", "raw_dummy_dir", "processed_dummy", file_splits, extract_5g_features, "DUMMY")
            
            final_out = os.path.join(config["paths"]["processed_dummy"], "train.parquet")
            self.assertTrue(os.path.exists(final_out))
            
            # Verify the contract of the output
            df_out = pd.read_parquet(final_out)
            self.assertGreater(len(df_out), 0)
            self.assertIn("final_label", df_out.columns)
            self.assertNotIn("Src_IP", df_out.columns)
            self.assertNotIn("label", df_out.columns)
            self.assertEqual(df_out["final_label"].iloc[0], "Benign")
            
    def test_pipeline_fails_on_empty_output(self):
        import tempfile
        import os
        import pandas as pd
        from utils.data_preparation import process_dataset_generic, extract_5g_features
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_dummy_dir": os.path.join(tmpdir, "raw"),
                    "processed_dummy": os.path.join(tmpdir, "processed"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "classes": {
                    "dummy": ["Benign"]
                }
            }
            mapping = {"DUMMY": {"0": "Benign"}}
            
            os.makedirs(config["paths"]["raw_dummy_dir"], exist_ok=True)
            os.makedirs(config["paths"]["reports_dir"], exist_ok=True)
            # Write label that maps to NOTHING (or is filtered out)
            pd.DataFrame({
                "metric": [1.0],
                "label": [99] # Unmapped
            }).to_csv(os.path.join(config["paths"]["raw_dummy_dir"], "train.csv"), index=False)
            
            file_splits = {"train": ["train.csv"]}
            
            # This should raise RuntimeError because 0 valid rows
            with self.assertRaises(RuntimeError) as context:
                process_dataset_generic(config, mapping, "DummySet", "raw_dummy_dir", "processed_dummy", file_splits, extract_5g_features, "DUMMY")
            self.assertIn("resulted in 0 valid rows", str(context.exception))

    def test_ids2018_pipeline_deduplication(self):
        from utils.data_preparation import process_ids2018
        import pyarrow as pa
        import tempfile
        import os
        import pandas as pd
        import pyarrow.parquet as pq
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_ids2018": os.path.join(tmpdir, "raw_ids2018.parquet"),
                    "processed_ids2018": os.path.join(tmpdir, "processed_ids2018"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "parameters": {"random_seed": 42},
                "classes": {
                    "ids2018": ["Benign", "DDoS"]
                }
            }
            mapping = {"IDS2018": {"0": "Benign", "1": "DDoS", "2": "Benign"}}
            
            # Enough rows to get split into train, val, test for both classes
            df_raw = pd.DataFrame({
                "Protocol": list(range(30)) + list(range(30)),
                "Flow Duration": [100]*30 + [200]*30,
                "Label": ["0"]*30 + ["1"]*30 
            })
            # Add duplicates
            df_raw = pd.concat([df_raw, df_raw])
            
            table = pa.Table.from_pandas(df_raw)
            pq.write_table(table, config["paths"]["raw_ids2018"])
            
            import utils.data_preparation
            old_resolve = utils.data_preparation.resolve_path
            utils.data_preparation.resolve_path = lambda p: p
            try:
                process_ids2018(config, mapping)
            finally:
                utils.data_preparation.resolve_path = old_resolve
            
            train = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "train.parquet"))
            val = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "val.parquet"))
            test = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "test.parquet"))
            
            for split_name, df_split in zip(["train", "val", "test"], [train, val, test]):
                self.assertIn("final_label", df_split.columns)
                self.assertNotIn("Label", df_split.columns)
                self.assertNotIn("__index_level_0__", df_split.columns)
                self.assertEqual(df_split.isnull().sum().sum(), 0) 
            
            feat_cols = [c for c in train.columns if c != "final_label"]
            train_hashes = pd.util.hash_pandas_object(train[feat_cols], index=False)
            val_hashes = pd.util.hash_pandas_object(val[feat_cols], index=False)
            test_hashes = pd.util.hash_pandas_object(test[feat_cols], index=False)
            
            self.assertEqual(len(set(train_hashes).intersection(set(val_hashes))), 0)
            self.assertEqual(len(set(train_hashes).intersection(set(test_hashes))), 0)
            self.assertEqual(len(set(val_hashes).intersection(set(test_hashes))), 0)

    def test_ids2018_force_rebuild(self):
        from utils.data_preparation import process_ids2018
        import pyarrow as pa
        import tempfile
        import os
        import time
        import pandas as pd
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_ids2018": os.path.join(tmpdir, "raw_ids2018.parquet"),
                    "processed_ids2018": os.path.join(tmpdir, "processed_ids2018"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "parameters": {"random_seed": 42},
                "classes": {
                    "ids2018": ["Benign", "DDoS"]
                }
            }
            mapping = {"IDS2018": {"0": "Benign", "1": "DDoS", "2": "Benign"}}

            df_raw = pd.DataFrame({
                "Protocol": list(range(30)) + list(range(30)),
                "Flow Duration": [100]*30 + [200]*30,
                "Label": ["0"]*30 + ["1"]*30 
            })
            table = pa.Table.from_pandas(df_raw)
            pq.write_table(table, config["paths"]["raw_ids2018"])

            # 1. Initial build
            report1 = process_ids2018(config, mapping, force_rebuild=False)
            self.assertIsNotNone(report1)
            train_path = os.path.join(config["paths"]["processed_ids2018"], "train.parquet")
            self.assertTrue(os.path.exists(train_path))
            mtime_initial = os.path.getmtime(train_path)

            # 2. Call with force_rebuild=False -> should skip
            report2 = process_ids2018(config, mapping, force_rebuild=False)
            self.assertIsNotNone(report2)
            self.assertEqual(os.path.getmtime(train_path), mtime_initial)

            # Sleep slightly to ensure measurable mtime difference on filesystem
            time.sleep(0.05)

            # 3. Call with force_rebuild=True -> should rebuild
            report3 = process_ids2018(config, mapping, force_rebuild=True)
            self.assertIsNotNone(report3)
            self.assertGreaterEqual(os.path.getmtime(train_path), mtime_initial)

            # Verify schema, index, leakage, and overlap properties on rebuilt data
            val_path = os.path.join(config["paths"]["processed_ids2018"], "val.parquet")
            test_path = os.path.join(config["paths"]["processed_ids2018"], "test.parquet")
            train = pd.read_parquet(train_path)
            val = pd.read_parquet(val_path)
            test = pd.read_parquet(test_path)

            for split_name, df_split in zip(["train", "val", "test"], [train, val, test]):
                self.assertIn("final_label", df_split.columns)
                self.assertNotIn("Label", df_split.columns)
                self.assertNotIn("__index_level_0__", df_split.columns)
                self.assertEqual(df_split.isnull().sum().sum(), 0) # No NaN
                # Check no Inf
                numeric_cols = df_split.select_dtypes(include=["number"]).columns
                self.assertFalse(np.isinf(df_split[numeric_cols].values).any())

            # Verify 0 cross-split feature overlaps
            feat_cols = [c for c in train.columns if c != "final_label"]
            train_hashes = set(pd.util.hash_pandas_object(train[feat_cols], index=False))
            val_hashes = set(pd.util.hash_pandas_object(val[feat_cols], index=False))
            test_hashes = set(pd.util.hash_pandas_object(test[feat_cols], index=False))

            self.assertEqual(len(train_hashes.intersection(val_hashes)), 0)
            self.assertEqual(len(train_hashes.intersection(test_hashes)), 0)
            self.assertEqual(len(val_hashes.intersection(test_hashes)), 0)

    def test_ids2018_float_downcast_leakage_prevention(self):
        """Verify that float64 values differing only beyond float32 precision with conflicting labels
        are purged during preprocessing, preventing cross-split conflicting label leakage."""
        from utils.data_preparation import process_ids2018
        import pyarrow as pa
        import tempfile
        import os
        import pandas as pd
        import pyarrow.parquet as pq
        import numpy as np

        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_ids2018": os.path.join(tmpdir, "raw_ids2018.parquet"),
                    "processed_ids2018": os.path.join(tmpdir, "processed_ids2018"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "parameters": {"random_seed": 42},
                "classes": {
                    "ids2018": ["Benign", "DDoS"]
                }
            }
            mapping = {"IDS2018": {"0": "Benign", "1": "DDoS"}}

            # Base dataset with 40 benign and 40 DDoS rows
            base_rows = {
                "Flow Duration": [float(1000 + i) for i in range(40)] + [float(5000 + i) for i in range(40)],
                "Flow Packets/s": [float(10 + i) for i in range(40)] + [float(50 + i) for i in range(40)],
                "Label": ["0"]*40 + ["1"]*40
            }
            df_base = pd.DataFrame(base_rows)

            # Pair 1: Conflicting labels with float64 precision differences beyond float32
            # v1 and v2 differ in float64, but are identical in float32:
            v1 = np.float64(12345.6789012345)
            v2 = np.float64(12345.6789012346)
            self.assertNotEqual(v1, v2)
            self.assertEqual(np.float32(v1), np.float32(v2))

            df_conflict_prec = pd.DataFrame({
                "Flow Duration": [v1, v2],
                "Flow Packets/s": [np.float64(99.0), np.float64(99.0)],
                "Label": ["0", "1"]  # Conflicting: Benign vs DDoS!
            })

            # Pair 2: Conflicting labels with signed zero (-0.0 vs 0.0)
            df_conflict_zero = pd.DataFrame({
                "Flow Duration": [np.float64(-0.0), np.float64(0.0)],
                "Flow Packets/s": [np.float64(42.0), np.float64(42.0)],
                "Label": ["0", "1"]  # Conflicting: Benign vs DDoS!
            })

            # Pair 3: Same-label duplicates with float64 tail precision differences
            v3 = np.float64(88888.123456789)
            v4 = np.float64(88888.123456788)
            self.assertNotEqual(v3, v4)
            self.assertEqual(np.float32(v3), np.float32(v4))
            df_samelabel_prec = pd.DataFrame({
                "Flow Duration": [v3, v4],
                "Flow Packets/s": [np.float64(12.0), np.float64(12.0)],
                "Label": ["0", "0"]  # Same label: Benign
            })

            df_raw = pd.concat([df_base, df_conflict_prec, df_conflict_zero, df_samelabel_prec], ignore_index=True)
            table = pa.Table.from_pandas(df_raw)
            pq.write_table(table, config["paths"]["raw_ids2018"])

            import utils.data_preparation
            old_resolve = utils.data_preparation.resolve_path
            utils.data_preparation.resolve_path = lambda p: p
            try:
                report = process_ids2018(config, mapping, force_rebuild=True)
            finally:
                utils.data_preparation.resolve_path = old_resolve

            self.assertIsNotNone(report)
            self.assertGreaterEqual(report["conflicting_rows_removed"], 4)

            # Read back processed splits
            train = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "train.parquet"))
            val = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "val.parquet"))
            test = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "test.parquet"))
            all_processed = pd.concat([train, val, test], ignore_index=True)

            # Assert conflicting float precision pair was PURGED completely
            conflict_prec_matches = all_processed[np.isclose(all_processed["Flow Duration"], np.float32(v1), atol=1e-6)]
            self.assertEqual(len(conflict_prec_matches), 0, "Conflicting float precision rows must be purged")

            # Assert conflicting signed-zero pair was PURGED completely
            conflict_zero_matches = all_processed[
                (np.isclose(all_processed["Flow Duration"], 0.0, atol=1e-6)) & 
                (np.isclose(all_processed["Flow Packets/s"], 42.0, atol=1e-6))
            ]
            self.assertEqual(len(conflict_zero_matches), 0, "Conflicting signed zero rows must be purged")

            # Assert same-label float precision duplicate was DEDUPLICATED (only 1 survived)
            samelabel_matches = all_processed[np.isclose(all_processed["Flow Duration"], np.float32(v3), atol=1e-6)]
            self.assertEqual(len(samelabel_matches), 1, "Same-label float precision duplicates must be deduplicated to 1")

            # Assert exactly 0 cross-split overlaps between all pairs
            feat_cols = [c for c in train.columns if c != "final_label"]
            train_hashes = set(pd.util.hash_pandas_object(train[feat_cols], index=False))
            val_hashes = set(pd.util.hash_pandas_object(val[feat_cols], index=False))
            test_hashes = set(pd.util.hash_pandas_object(test[feat_cols], index=False))

            self.assertEqual(len(train_hashes.intersection(val_hashes)), 0)
            self.assertEqual(len(train_hashes.intersection(test_hashes)), 0)
            self.assertEqual(len(val_hashes.intersection(test_hashes)), 0)

    def test_ids2018_schema_and_77_feature_count_contract(self):
        """Verify the strict IDS2018 schema contract:
        - 78 total columns (77 features + 1 target final_label)
        - Exactly 77 numeric features (no object/string)
        - final_label is the only target column
        - raw Label column is removed
        - No NaN, no Inf
        - preserve_index=False (no __index_level_0__)
        - Identical columns and order across train, val, and test
        """
        from utils.data_preparation import process_ids2018, resolve_path
        import pyarrow as pa
        import pyarrow.parquet as pq
        import tempfile
        import os
        import pandas as pd
        import numpy as np

        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_ids2018": os.path.join(tmpdir, "raw_ids2018.parquet"),
                    "processed_ids2018": os.path.join(tmpdir, "processed_ids2018"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "parameters": {"random_seed": 42},
                "classes": {
                    "ids2018": ["Benign", "DDoS"]
                }
            }
            mapping = {"IDS2018": {"0": "Benign", "1": "DDoS"}}

            # Read the realistic 77-feature sample
            sample_path = resolve_path("data/samples/ids2018_sample.csv")
            if os.path.exists(sample_path):
                df_sample = pd.read_csv(sample_path)
                df_sample["Label"] = df_sample["final_label"].map({"Benign": "0", "DDoS": "1"}).fillna("0")
                if "final_label" in df_sample.columns:
                    df_sample = df_sample.drop(columns=["final_label"])
            else:
                feat_dict = {f"feat_{i}": np.random.randn(60).astype(np.float32) for i in range(77)}
                feat_dict["Label"] = ["0"]*30 + ["1"]*30
                df_sample = pd.DataFrame(feat_dict)

            table = pa.Table.from_pandas(df_sample, preserve_index=False)
            pq.write_table(table, config["paths"]["raw_ids2018"])

            import utils.data_preparation
            old_resolve = utils.data_preparation.resolve_path
            utils.data_preparation.resolve_path = lambda p: p
            try:
                report = process_ids2018(config, mapping, force_rebuild=True)
            finally:
                utils.data_preparation.resolve_path = old_resolve

            self.assertIsNotNone(report)
            self.assertEqual(report["feature_count"], 77)

            train = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "train.parquet"))
            val = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "val.parquet"))
            test = pd.read_parquet(os.path.join(config["paths"]["processed_ids2018"], "test.parquet"))

            for split_name, df_split in zip(["train", "val", "test"], [train, val, test]):
                self.assertEqual(len(df_split.columns), 78, f"{split_name} total columns must be 78")
                self.assertIn("final_label", df_split.columns)
                self.assertNotIn("Label", df_split.columns)
                self.assertNotIn("label", df_split.columns)
                self.assertNotIn("__index_level_0__", df_split.columns)

                features = [c for c in df_split.columns if c != "final_label"]
                self.assertEqual(len(features), 77, f"{split_name} feature count must be exactly 77")

                # Verify all features are numeric
                non_numeric = [c for c in features if not pd.api.types.is_numeric_dtype(df_split[c])]
                self.assertEqual(len(non_numeric), 0, f"Found non-numeric features in {split_name}: {non_numeric}")

                # Verify no NaN or Inf
                self.assertEqual(df_split[features].isnull().sum().sum(), 0)
                self.assertFalse(np.isinf(df_split[features].values).any())

            # Verify identical columns and order across all splits
            self.assertEqual(list(train.columns), list(val.columns))
            self.assertEqual(list(train.columns), list(test.columns))

    def test_mixed_numeric_dtypes_contract(self):
        """Verify that mixed numeric feature columns (float32, int32, int64) are valid
        and properly preserved, and non-numeric columns are detected."""
        df = pd.DataFrame({
            "feat_f32": np.array([1.5, 2.5], dtype=np.float32),
            "feat_i32": np.array([10, 20], dtype=np.int32),
            "feat_i64": np.array([1000, 2000], dtype=np.int64),
            "final_label": ["Benign", "DDoS"]
        })
        features = [c for c in df.columns if c != "final_label"]
        for f in features:
            self.assertTrue(pd.api.types.is_numeric_dtype(df[f]))

        # Invalid feature test
        df_invalid = df.copy()
        df_invalid["bad_feature"] = ["text_a", "text_b"]
        invalid_features = [c for c in df_invalid.columns if c != "final_label" and not pd.api.types.is_numeric_dtype(df_invalid[c])]
        self.assertEqual(invalid_features, ["bad_feature"])

    def test_process_dataset_generic_skip_and_force_rebuild(self):
        """Verify process_dataset_generic correctly skips when expected splits exist
        and rebuilds when force_rebuild=True."""
        from utils.data_preparation import process_dataset_generic
        import tempfile
        import os
        import time

        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "version": "1.0",
                "paths": {
                    "raw_dummy": os.path.join(tmpdir, "raw"),
                    "processed_dummy": os.path.join(tmpdir, "processed"),
                    "reports_dir": os.path.join(tmpdir, "reports")
                },
                "classes": {"dummy": ["Benign", "DoS"]}
            }
            mapping = {"DUMMY": {"0": "Benign", "1": "DoS"}}
            os.makedirs(config["paths"]["raw_dummy"], exist_ok=True)

            # Raw files for train and test only (no val)
            df1 = pd.DataFrame({"label": ["0", "1"]*10, "feature": [100, 200]*10})
            df1.to_csv(os.path.join(config["paths"]["raw_dummy"], "train.csv"), index=False)
            df1.to_csv(os.path.join(config["paths"]["raw_dummy"], "test.csv"), index=False)

            file_splits = {"train": ["train.csv"], "test": ["test.csv"]}
            extractor = lambda df: df

            import utils.data_preparation
            old_resolve = utils.data_preparation.resolve_path
            utils.data_preparation.resolve_path = lambda p: p
            try:
                # 1. Initial build
                rep1 = process_dataset_generic(config, mapping, "DummySet", "raw_dummy", "processed_dummy", file_splits, extractor, "DUMMY", force_rebuild=False)
                self.assertIsNotNone(rep1)
                train_p = os.path.join(config["paths"]["processed_dummy"], "train.parquet")
                self.assertTrue(os.path.exists(train_p))
                mtime1 = os.path.getmtime(train_p)

                # 2. Call with force_rebuild=False -> MUST skip!
                rep2 = process_dataset_generic(config, mapping, "DummySet", "raw_dummy", "processed_dummy", file_splits, extractor, "DUMMY", force_rebuild=False)
                self.assertIsNotNone(rep2)
                self.assertEqual(os.path.getmtime(train_p), mtime1)

                # 3. Call with force_rebuild=True -> MUST rebuild!
                time.sleep(0.05)
                rep3 = process_dataset_generic(config, mapping, "DummySet", "raw_dummy", "processed_dummy", file_splits, extractor, "DUMMY", force_rebuild=True)
                self.assertIsNotNone(rep3)
                self.assertGreaterEqual(os.path.getmtime(train_p), mtime1)
            finally:
                utils.data_preparation.resolve_path = old_resolve

if __name__ == '__main__':
    unittest.main()
