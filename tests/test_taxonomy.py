import os
import unittest
import json
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.data_preparation import resolve_path, load_config, load_label_mapping
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID, ID_TO_CLASS

class TestTaxonomy(unittest.TestCase):
    def test_exactly_13_classes(self):
        self.assertEqual(len(CLASS_NAMES), 13)
        self.assertEqual(len(CLASS_TO_ID), 13)
        self.assertEqual(len(ID_TO_CLASS), 13)
        
    def test_mac_spoofing_absent(self):
        self.assertNotIn("MAC Spoofing", CLASS_NAMES)
        self.assertNotIn("MAC Spoofing", CLASS_TO_ID)
        
    def test_ids_unique_contiguous(self):
        ids = list(CLASS_TO_ID.values())
        self.assertEqual(sorted(ids), list(range(13)))
        
    def test_label_mappings_only_canonical(self):
        mapping = load_label_mapping()
        for k, v in mapping["IDS2018"].items():
            self.assertIn(v, CLASS_NAMES)
        for k, v in mapping["CICIoT2023"].items():
            self.assertIn(v, CLASS_NAMES)

if __name__ == '__main__':
    unittest.main()
