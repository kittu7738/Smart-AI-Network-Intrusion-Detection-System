import os
import sys
import unittest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.taxonomy import (
    CLASS_NAMES,
    CLASS_TO_ID,
    ID_TO_CLASS,
    NUM_CLASSES,
    SPECIALIST_SUB_TAXONOMIES,
    SPECIALIST_LOCAL_TO_CANONICAL,
)
from utils.specialist_preprocessor import SpecialistPreprocessor
from utils.unified_nids import UnifiedNIDS
from utils.data_preparation import load_config, resolve_path
from utils.model_registry import get_candidate_model


class TestUnifiedNIDSInference(unittest.TestCase):
    """Integration test suite for the Unified 13-Class NIDS inference engine."""

    @classmethod
    def setUpClass(cls):
        cls.config = load_config()
        cls.engine = UnifiedNIDS()

        # If CICIoT2023 artifact is not present locally (since it was trained on Colab),
        # register a valid preprocessor and candidate model to enable local testing.
        ciciot_dir = resolve_path("models/CICIoT2023")
        ciciot_has_artifacts = (
            os.path.exists(os.path.join(ciciot_dir, "candidate_XGBoost_Tuned.joblib")) or
            os.path.exists(os.path.join(ciciot_dir, "XGBoost.joblib"))
        ) and (
            os.path.exists(os.path.join(ciciot_dir, "candidate_preprocessor.joblib")) or
            os.path.exists(os.path.join(ciciot_dir, "preprocessor.joblib"))
        )

        if not ciciot_has_artifacts:
            # Construct standard 46-feature schema for CICIoT2023
            ciciot_classes = SPECIALIST_SUB_TAXONOMIES["CICIoT2023"]
            from utils.train_models import load_specialist_splits
            df_mock, _, _ = load_specialist_splits("CICIoT2023", cls.config, smoke_test=True)
            p_ciciot = SpecialistPreprocessor(
                dataset_name="CICIoT2023",
                expected_classes=ciciot_classes,
                scale_features=True
            )
            p_ciciot.fit(df_mock)
            m_ciciot = get_candidate_model("XGBoost_Tuned", smoke_test=True)
            m_ciciot.fit(p_ciciot.transform_features(df_mock), p_ciciot.transform_labels(df_mock))
            cls.engine.register_specialist(
                specialist_name="CICIoT2023",
                model=m_ciciot,
                preprocessor=p_ciciot,
                threshold_multipliers={"Benign": 1.5, "Infiltration": 2.0}
            )

    def test_specialist_loading_and_registration(self):
        """Verify that available production models load cleanly into memory."""
        # 4 specialists exist in models/ locally: IDS2018, ARP_Spoofing, IP_Spoofing, DNS_Tunneling
        for spec in ["IDS2018", "ARP_Spoofing", "IP_Spoofing", "DNS_Tunneling"]:
            loaded = self.engine.load_specialist(spec)
            self.assertIn("model", loaded)
            self.assertIn("preprocessor", loaded)
            self.assertTrue(hasattr(loaded["preprocessor"], "transform_features"))

        # CICIoT2023 is loaded (either from disk or registered)
        self.assertTrue(self.engine.is_specialist_loaded("CICIoT2023"))

    def test_inference_path_all_five_specialists(self):
        """Verify the complete unified inference execution path for every specialist."""
        for spec in UnifiedNIDS.SPECIALIST_NAMES:
            if not self.engine.is_specialist_loaded(spec):
                self.engine.load_specialist(spec)

            spec_info = self.engine._specialists[spec]
            prep = spec_info["preprocessor"]
            feature_names = prep.feature_names_in_

            # Construct minimal synthetic feature row
            sample_data = {feat: 0.5 for feat in feature_names}

            # 1. Run inference
            result = self.engine.predict(sample_data, specialist=spec)

            # 2. Verify returned structure
            self.assertIsInstance(result, dict)
            self.assertEqual(result["specialist"], spec)
            self.assertIn("canonical_id", result)
            self.assertIn("class_name", result)
            self.assertIn("confidence", result)
            self.assertIn("probabilities", result)

            # 3. Verify canonical class ID bounds [0, 12]
            cid = result["canonical_id"]
            self.assertGreaterEqual(cid, 0)
            self.assertLessEqual(cid, 12)
            self.assertEqual(CLASS_TO_ID[result["class_name"]], cid)

            # 4. Verify class belongs to specialist's valid canonical sub-taxonomy
            valid_sub_taxonomy = SPECIALIST_SUB_TAXONOMIES[spec]
            self.assertIn(result["class_name"], valid_sub_taxonomy)

            # 5. Verify probability vector has exactly 13 elements and sums to 1.0
            probs = result["probabilities"]
            self.assertEqual(len(probs), 13)
            self.assertAlmostEqual(sum(probs), 1.0, places=4)

            # 6. Verify zero probability for classes outside the specialist's taxonomy
            local_to_canon = SPECIALIST_LOCAL_TO_CANONICAL[spec]
            allowed_canonical_ids = set(local_to_canon.values())
            for c_idx in range(13):
                if c_idx not in allowed_canonical_ids:
                    self.assertEqual(
                        probs[c_idx], 0.0,
                        f"Specialist {spec} produced non-zero probability for out-of-scope class {ID_TO_CLASS[c_idx]} (ID {c_idx})"
                    )

    def test_automatic_schema_routing(self):
        """Verify automated routing for distinct specialist schemas."""
        # 1. DNS Tunneling schema
        dns_row = {"query_length": 35.0, "num_dots": 3, "entropy": 3.8}
        self.assertEqual(self.engine.route_traffic(dns_row), "DNS_Tunneling")

        # 2. ARP Spoofing schema
        arp_row = {"arp_opcode": 1.0, "frame_number": 102.0, "tcp_flag_fin": 0.0}
        self.assertEqual(self.engine.route_traffic(arp_row), "ARP_Spoofing")

        # 3. IDS2018 enterprise schema
        ids_row = {"Flow Duration": 12000.0, "Tot Fwd Pkts": 5.0, "Tot Bwd Pkts": 4.0}
        self.assertEqual(self.engine.route_traffic(ids_row), "IDS2018")

        # 4. CICIoT2023 IoT schema
        iot_row = {"Rate": 15.2, "Srate": 10.1, "Drate": 5.1, "Header_Length": 54.0}
        self.assertEqual(self.engine.route_traffic(iot_row), "CICIoT2023")

        # 5. IP Spoofing schema
        ip_row = {"Seq": 10.0, "GTP": 1.0, "5G": 1.0}
        self.assertEqual(self.engine.route_traffic(ip_row), "IP_Spoofing")

    def test_invalid_and_ambiguous_schema_rejection(self):
        """Invalid, empty, or unroutable schemas must raise clear ValueErrors."""
        # Ambiguous / non-network data
        bad_data = {"customer_age": 30, "salary": 50000}
        with self.assertRaises(ValueError) as ctx:
            self.engine.route_traffic(bad_data)
        self.assertIn("Unable to route input", str(ctx.exception))

        # Empty data list
        with self.assertRaises(ValueError):
            self.engine.predict([])

    def test_mac_spoofing_strict_rejection(self):
        """MAC Spoofing must be rejected on arrival and can never be predicted."""
        # 1. Payload containing MAC column
        mac_data = {"src_mac": "00:11:22:33:44:55", "query_length": 15.0}
        with self.assertRaises(ValueError) as ctx:
            self.engine.predict(mac_data)
        self.assertIn("MAC Spoofing is permanently excluded", str(ctx.exception))

        # 2. Explicit request with MAC
        with self.assertRaises(ValueError) as ctx:
            self.engine.route_traffic({"mac_spoofing": 1.0})
        self.assertIn("MAC Spoofing is permanently excluded", str(ctx.exception))

    def test_batch_prediction_vectorization(self):
        """Verify batch prediction returns consistent vectorized arrays."""
        spec = "DNS_Tunneling"
        if not self.engine.is_specialist_loaded(spec):
            self.engine.load_specialist(spec)
        prep = self.engine._specialists[spec]["preprocessor"]
        feats = prep.feature_names_in_

        df_batch = pd.DataFrame([
            {f: 0.1 for f in feats},
            {f: 0.9 for f in feats}
        ])

        batch_out = self.engine.predict_batch(df_batch, specialist=spec)
        self.assertEqual(batch_out["specialist"], spec)
        self.assertEqual(len(batch_out["canonical_ids"]), 2)
        self.assertEqual(len(batch_out["class_names"]), 2)
        self.assertEqual(batch_out["probabilities"].shape, (2, 13))
        np.testing.assert_allclose(np.sum(batch_out["probabilities"], axis=1), [1.0, 1.0], rtol=1e-4)


if __name__ == '__main__':
    unittest.main()
