import os
import unittest
import json
import sys

# Ensure utils is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.data_preparation import resolve_path, load_config, load_label_mapping

class TestTaxonomy(unittest.TestCase):
    
    def test_universal_class_list_is_exactly_10(self):
        config = load_config()
        self.assertEqual(len(config["classes"]["ciciot2023"]), 10)
        self.assertEqual(len(config["classes"]["ids2018"]), 7)
        self.assertNotIn("Heart""bleed", config["classes"]["ciciot2023"])
        self.assertNotIn("Heart""bleed", config["classes"]["ids2018"])

    def test_label_mappings_do_not_contain_hb(self):
        mapping = load_label_mapping()
        
        for k, v in mapping["IDS2018"].items():
            self.assertNotEqual(v, "Heart""bleed")
            
        for k, v in mapping["CICIoT2023"].items():
            self.assertNotEqual(v, "Heart""bleed")
            
    def test_data_preparation_does_not_mention_hb(self):
        with open(resolve_path("utils/data_preparation.py"), "r") as f:
            content = f.read()
            self.assertNotIn("hb_count", content)
            self.assertNotIn("hb_status", content)
            self.assertNotIn("Heart""bleed", content)
            
if __name__ == '__main__':
    unittest.main()
