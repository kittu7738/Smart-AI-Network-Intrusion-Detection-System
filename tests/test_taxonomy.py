import os
import unittest
import json
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.data_preparation import resolve_path, load_config, load_label_mapping
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID, ID_TO_CLASS

class TestTaxonomy(unittest.TestCase):
    EXPECTED_13_CLASSES = [
        "Benign",
        "DDoS",
        "DoS",
        "Botnet",
        "Infiltration",
        "Brute Force",
        "Web Attack",
        "DNS Spoofing",
        "IP Spoofing",
        "ARP Spoofing",
        "Recon / Port Scan",
        "MITM",
        "DNS Tunneling",
    ]

    def test_exactly_13_classes(self):
        self.assertEqual(len(CLASS_NAMES), 13)
        self.assertEqual(len(CLASS_TO_ID), 13)
        self.assertEqual(len(ID_TO_CLASS), 13)
        self.assertEqual(CLASS_NAMES, self.EXPECTED_13_CLASSES)

    def test_canonical_ordering_and_ids(self):
        for idx, name in enumerate(self.EXPECTED_13_CLASSES):
            self.assertEqual(CLASS_TO_ID[name], idx)
            self.assertEqual(ID_TO_CLASS[idx], name)

    def test_ids_unique_contiguous(self):
        ids = list(CLASS_TO_ID.values())
        self.assertEqual(sorted(ids), list(range(13)))
        self.assertEqual(len(set(ids)), 13)

    def test_mac_spoofing_absent(self):
        for variant in ["MAC Spoofing", "MAC_Spoofing", "mac_spoofing", "mac spoofing"]:
            self.assertNotIn(variant, CLASS_NAMES)
            self.assertNotIn(variant, CLASS_TO_ID)

    def test_label_mappings_only_canonical(self):
        mapping = load_label_mapping()
        # Verify all datasets in label mapping terminate in canonical classes
        for ds_name, ds_map in mapping.items():
            for raw_lbl, mapped_lbl in ds_map.items():
                self.assertIn(
                    mapped_lbl, 
                    CLASS_NAMES, 
                    f"Dataset {ds_name} raw label '{raw_lbl}' mapped to non-canonical class '{mapped_lbl}'"
                )

    def test_preprocessing_config_taxonomy_agreement(self):
        cfg = load_config()
        # Check taxonomy dict in preprocessing_config.json
        taxonomy_cfg = cfg.get("taxonomy", {})
        self.assertEqual(len(taxonomy_cfg), 13)
        for k, v in taxonomy_cfg.items():
            self.assertEqual(int(k), CLASS_TO_ID[v])
            self.assertEqual(v, CLASS_NAMES[int(k)])

        # Check all class lists in config
        for ds_name, class_list in cfg.get("classes", {}).items():
            for cls in class_list:
                self.assertIn(cls, CLASS_NAMES, f"Config class list for {ds_name} contains non-canonical '{cls}'")

    def test_mac_spoofing_strictly_absent_in_all_configs(self):
        config_dir = resolve_path("config")
        for fname in os.listdir(config_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(config_dir, fname)
                with open(fpath, "r") as f:
                    content = f.read().lower()
                self.assertNotIn("mac spoofing", content, f"Found 'mac spoofing' in {fpath}")
                self.assertNotIn("mac_spoofing", content, f"Found 'mac_spoofing' in {fpath}")

if __name__ == '__main__':
    unittest.main()
