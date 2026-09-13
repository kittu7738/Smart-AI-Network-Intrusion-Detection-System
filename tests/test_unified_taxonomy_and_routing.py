import os
import sys
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.taxonomy import (
    CLASS_NAMES,
    CLASS_TO_ID,
    ID_TO_CLASS,
    NUM_CLASSES,
    SPECIALIST_SUB_TAXONOMIES,
    SPECIALIST_LOCAL_TO_CANONICAL,
    SPECIALIST_FEATURE_INDICATORS,
    project_local_to_canonical_probabilities,
    detect_specialist_from_features
)
from utils.specialist_preprocessor import SpecialistPreprocessor

class TestUnifiedTaxonomyAndRouting(unittest.TestCase):
    """Test suite for Unified 13-Class NIDS taxonomy, probability projection, and routing."""

    def test_canonical_taxonomy_cardinality_and_ordering(self):
        """Verify the taxonomy has exactly 13 classes numbered 0 to 12."""
        self.assertEqual(NUM_CLASSES, 13)
        self.assertEqual(len(CLASS_NAMES), 13)
        self.assertEqual(len(CLASS_TO_ID), 13)
        self.assertEqual(len(ID_TO_CLASS), 13)
        
        # Verify exact IDs 0 to 12
        expected_classes = [
            "Benign", "DDoS", "DoS", "Botnet", "Infiltration",
            "Brute Force", "Web Attack", "DNS Spoofing", "IP Spoofing",
            "ARP Spoofing", "Recon / Port Scan", "MITM", "DNS Tunneling"
        ]
        self.assertEqual(CLASS_NAMES, expected_classes)
        for idx, name in enumerate(expected_classes):
            self.assertEqual(CLASS_TO_ID[name], idx)
            self.assertEqual(ID_TO_CLASS[idx], name)

    def test_all_specialist_sub_taxonomies_are_subsets(self):
        """Ensure all 5 specialist pipelines use valid subsets of the 13 canonical classes."""
        self.assertEqual(len(SPECIALIST_SUB_TAXONOMIES), 5)
        for spec_name, sub_tax in SPECIALIST_SUB_TAXONOMIES.items():
            for cls_name in sub_tax:
                self.assertIn(cls_name, CLASS_NAMES, f"Specialist {spec_name} has invalid class {cls_name}")
            # Ensure Benign is always present and at index 0
            self.assertEqual(sub_tax[0], "Benign", f"Specialist {spec_name} does not have Benign at index 0")

    def test_specialist_local_to_canonical_mappings(self):
        """Verify exact local ID to canonical ID mappings for each specialist."""
        # 1. IDS2018 (7 classes -> canonical 0, 1, 2, 3, 4, 5, 6)
        ids_map = SPECIALIST_LOCAL_TO_CANONICAL["IDS2018"]
        self.assertEqual(ids_map, {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6})

        # 2. CICIoT2023 (10 classes -> canonical 0, 1, 2, 3, 4, 5, 6, 7, 10, 11)
        ciciot_map = SPECIALIST_LOCAL_TO_CANONICAL["CICIoT2023"]
        self.assertEqual(ciciot_map, {
            0: 0,   # Benign
            1: 1,   # DDoS
            2: 2,   # DoS
            3: 3,   # Botnet
            4: 4,   # Infiltration
            5: 5,   # Brute Force
            6: 6,   # Web Attack
            7: 7,   # DNS Spoofing
            8: 10,  # Recon / Port Scan
            9: 11   # MITM
        })

        # 3. ARP_Spoofing (3 classes -> canonical 0, 9, 2)
        arp_map = SPECIALIST_LOCAL_TO_CANONICAL["ARP_Spoofing"]
        self.assertEqual(arp_map, {
            0: 0,  # Benign
            1: 9,  # ARP Spoofing
            2: 2   # DoS
        })

        # 4. IP_Spoofing (2 classes -> canonical 0, 8)
        ip_map = SPECIALIST_LOCAL_TO_CANONICAL["IP_Spoofing"]
        self.assertEqual(ip_map, {
            0: 0,  # Benign
            1: 8   # IP Spoofing
        })

        # 5. DNS_Tunneling (2 classes -> canonical 0, 12)
        dns_map = SPECIALIST_LOCAL_TO_CANONICAL["DNS_Tunneling"]
        self.assertEqual(dns_map, {
            0: 0,   # Benign
            1: 12   # DNS Tunneling
        })

    def test_mac_spoofing_absence_across_all_definitions(self):
        """Strictly guarantee MAC Spoofing is absent from all dictionaries, indicators, and taxonomies."""
        for spec_name, sub_tax in SPECIALIST_SUB_TAXONOMIES.items():
            for c in sub_tax:
                self.assertNotIn("mac", c.lower())

        for name in CLASS_NAMES:
            self.assertNotIn("mac", name.lower())

        for spec_name, indicators in SPECIALIST_FEATURE_INDICATORS.items():
            for ind in indicators:
                self.assertNotIn("mac", ind.lower())

    def test_project_probabilities_1d_and_2d(self):
        """Test probability projection into 13-class canonical space for 1D and 2D arrays."""
        # Test ARP_Spoofing projection: local [0.1, 0.7, 0.2] (Benign, ARP Spoofing, DoS)
        # Expected canonical: index 0: 0.1, index 9: 0.7, index 2: 0.2, all others 0.0
        local_p = np.array([0.1, 0.7, 0.2], dtype=np.float32)
        canon_p = project_local_to_canonical_probabilities(local_p, specialist_name="ARP_Spoofing")
        
        self.assertEqual(canon_p.shape, (13,))
        self.assertAlmostEqual(canon_p[0], 0.1, places=5)
        self.assertAlmostEqual(canon_p[9], 0.7, places=5)
        self.assertAlmostEqual(canon_p[2], 0.2, places=5)
        self.assertAlmostEqual(float(np.sum(canon_p)), 1.0, places=5)
        for idx in [1, 3, 4, 5, 6, 7, 8, 10, 11, 12]:
            self.assertEqual(canon_p[idx], 0.0)

        # Test batch (2D) for DNS_Tunneling: shape (2, 2)
        batch_local = np.array([
            [0.9, 0.1],  # Benign: 0.9, DNS Tunneling: 0.1
            [0.05, 0.95] # Benign: 0.05, DNS Tunneling: 0.95
        ], dtype=np.float32)
        batch_canon = project_local_to_canonical_probabilities(batch_local, specialist_name="DNS_Tunneling")
        
        self.assertEqual(batch_canon.shape, (2, 13))
        np.testing.assert_allclose(np.sum(batch_canon, axis=1), [1.0, 1.0], rtol=1e-5)
        self.assertAlmostEqual(batch_canon[0, 0], 0.9, places=5)
        self.assertAlmostEqual(batch_canon[0, 12], 0.1, places=5)
        self.assertAlmostEqual(batch_canon[1, 0], 0.05, places=5)
        self.assertAlmostEqual(batch_canon[1, 12], 0.95, places=5)

    def test_specialist_preprocessor_probability_projection(self):
        """Test SpecialistPreprocessor's project_probabilities_to_canonical method."""
        prep = SpecialistPreprocessor(
            dataset_name="CICIoT2023",
            expected_classes=SPECIALIST_SUB_TAXONOMIES["CICIoT2023"],
            scale_features=False
        )
        # 10 classes in CICIoT2023
        dummy_probs = np.zeros((1, 10), dtype=np.float32)
        dummy_probs[0, 8] = 0.6  # Recon / Port Scan (local 8 -> canonical 10)
        dummy_probs[0, 9] = 0.4  # MITM (local 9 -> canonical 11)

        canon_p = prep.project_probabilities_to_canonical(dummy_probs)
        self.assertEqual(canon_p.shape, (1, 13))
        self.assertAlmostEqual(canon_p[0, 10], 0.6, places=5)
        self.assertAlmostEqual(canon_p[0, 11], 0.4, places=5)
        self.assertAlmostEqual(canon_p[0, 0], 0.0, places=5)
        self.assertAlmostEqual(float(np.sum(canon_p)), 1.0, places=5)

    def test_detect_specialist_from_features(self):
        """Test automated schema-based routing from column lists."""
        # 1. DNS schema
        dns_cols = ["query_length", "num_dots", "entropy"]
        self.assertEqual(detect_specialist_from_features(dns_cols), "DNS_Tunneling")

        # 2. ARP schema
        arp_cols = ["frame_number", "arp_opcode", "tcp_flag_fin"]
        self.assertEqual(detect_specialist_from_features(arp_cols), "ARP_Spoofing")

        # 3. IDS2018 schema
        ids_cols = ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts"]
        self.assertEqual(detect_specialist_from_features(ids_cols), "IDS2018")

        # 4. CICIoT2023 schema
        iot_cols = ["Rate", "Srate", "Drate", "Header_Length"]
        self.assertEqual(detect_specialist_from_features(iot_cols), "CICIoT2023")

        # 5. IP Spoofing schema
        ip_cols = ["Seq", "GTP", "5G"]
        self.assertEqual(detect_specialist_from_features(ip_cols), "IP_Spoofing")

        # 6. Incompatible / unknown schema raises ValueError
        with self.assertRaises(ValueError):
            detect_specialist_from_features(["customer_id", "transaction_amount", "zipcode"])

if __name__ == '__main__':
    unittest.main()
