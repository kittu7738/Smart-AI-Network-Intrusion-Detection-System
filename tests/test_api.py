"""API integration test suite for the Smart AI NIDS FastAPI Backend."""

import os
import sys
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.main import app, get_engine
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID, NUM_CLASSES, SPECIALIST_SUB_TAXONOMIES


class TestFastAPIBackend(unittest.TestCase):
    """Comprehensive test suite for the FastAPI backend endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.engine = get_engine()

    def test_01_health_endpoint_returns_200(self):
        """GET /health must return HTTP 200 with engine readiness and status."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["engine_ready"])
        self.assertIn("service", data)
        self.assertIn("version", data)
        self.assertIn("available_specialists", data)
        self.assertIn("loaded_specialists", data)
        self.assertEqual(len(data["available_specialists"]), 5)

    def test_02_models_endpoint_returns_all_five_specialists(self):
        """GET /models must return all 5 specialists and canonical taxonomy without MAC Spoofing."""
        response = self.client.get("/models")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        expected_specialists = {"IDS2018", "CICIoT2023", "ARP_Spoofing", "IP_Spoofing", "DNS_Tunneling"}
        self.assertEqual(set(data["specialists"].keys()), expected_specialists)
        
        # Verify 13 canonical classes
        self.assertEqual(len(data["canonical_classes"]), 13)
        self.assertEqual(data["canonical_classes"], CLASS_NAMES)
        self.assertEqual(data["canonical_class_to_id"], CLASS_TO_ID)

        # Strictly verify MAC Spoofing is absent
        for spec_name, detail in data["specialists"].items():
            for c in detail["canonical_classes"]:
                self.assertNotIn("mac spoofing", c.lower())
        for c in data["canonical_classes"]:
            self.assertNotIn("mac spoofing", c.lower())

    def test_03_predict_valid_synthetic_payload_succeeds(self):
        """POST /predict with valid synthetic payload must return HTTP 200."""
        # Using ARP_Spoofing minimal schema
        payload = {
            "features": {"frame_number": 100.0, "arp_opcode": 1.0},
            "specialist": "ARP_Spoofing"
        }
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["specialist"], "ARP_Spoofing")
        self.assertIn(data["predicted_class"], SPECIALIST_SUB_TAXONOMIES["ARP_Spoofing"])

    def test_04_prediction_response_contains_all_required_fields(self):
        """POST /predict response must contain all specified fields."""
        payload = {
            "features": {"some_feature": 0.5},
            "specialist": "IP_Spoofing"
        }
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        required_fields = ["predicted_class_id", "predicted_class", "confidence", "specialist", "probabilities"]
        for field in required_fields:
            self.assertIn(field, data)
        self.assertIsInstance(data["predicted_class_id"], int)
        self.assertIsInstance(data["predicted_class"], str)
        self.assertIsInstance(data["confidence"], float)
        self.assertIsInstance(data["specialist"], str)
        self.assertIsInstance(data["probabilities"], list)

    def test_05_probabilities_length_is_exactly_13(self):
        """Posterior probabilities array must contain exactly 13 canonical class probabilities."""
        payload = {"query": "malicious.dns-tunneling.test.org"}
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["probabilities"]), 13)

    def test_06_probabilities_sum_approximately_to_one(self):
        """Probabilities must normalize to 1.0 (within standard float tolerance)."""
        payload = {"query": "normal-traffic-domain.com"}
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        probs = response.json()["probabilities"]
        self.assertAlmostEqual(sum(probs), 1.0, places=4)

    def test_07_automated_specialist_routing_works(self):
        """Traffic without explicit specialist must be automatically routed to the correct specialist."""
        # 1. DNS signature features
        dns_payload = {"query": "sample-dns-routing-test.com"}
        r_dns = self.client.post("/predict", json=dns_payload)
        self.assertEqual(r_dns.status_code, 200)
        self.assertEqual(r_dns.json()["specialist"], "DNS_Tunneling")

        # 2. ARP signature features
        arp_payload = {"arp_opcode": 1.0, "frame_number": 50.0}
        r_arp = self.client.post("/predict", json=arp_payload)
        self.assertEqual(r_arp.status_code, 200)
        self.assertEqual(r_arp.json()["specialist"], "ARP_Spoofing")

        # 3. IP signature features
        ip_payload = {"some_feature": 1.5, "Seq": 10.0}
        r_ip = self.client.post("/predict", json=ip_payload)
        self.assertEqual(r_ip.status_code, 200)
        self.assertEqual(r_ip.json()["specialist"], "IP_Spoofing")

    def test_08_raw_dns_query_input_works(self):
        """Passing a raw DNS query string must trigger automatic feature extraction and classification."""
        payload = {"query": "tunnel-exfiltration-packet.evil.net"}
        response = self.client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["specialist"], "DNS_Tunneling")
        self.assertIn(data["predicted_class"], ["Benign", "DNS Tunneling"])
        self.assertIn(data["predicted_class_id"], [0, 12])

    def test_09_missing_required_features_produces_clean_4xx(self):
        """Omitting required specialist features must return HTTP 400 with descriptive error."""
        # IDS2018 requires 77 features
        incomplete_payload = {
            "features": {"Flow Duration": 12000.0},
            "specialist": "IDS2018"
        }
        response = self.client.post("/predict", json=incomplete_payload)
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("detail", data)
        self.assertIn("missing features", data["detail"].lower())

    def test_10_invalid_or_unknown_schema_produces_clean_4xx(self):
        """Passing completely unknown/non-network columns must return HTTP 400."""
        bad_payload = {"employee_id": 999, "office_branch": "HQ"}
        response = self.client.post("/predict", json=bad_payload)
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("detail", data)
        self.assertIn("unable to route input", data["detail"].lower())

    def test_11_empty_batch_is_rejected_cleanly(self):
        """Submitting an empty batch must return HTTP 400."""
        # Empty array
        r1 = self.client.post("/predict/batch", json=[])
        self.assertEqual(r1.status_code, 400)
        self.assertIn("cannot be empty", r1.json()["detail"].lower())

        # Empty records dict
        r2 = self.client.post("/predict/batch", json={"records": []})
        self.assertEqual(r2.status_code, 400)
        self.assertIn("cannot be empty", r2.json()["detail"].lower())

    def test_12_valid_batch_returns_correct_number_of_results(self):
        """Valid batch input must return exactly one prediction result per record."""
        batch = [
            {"query": "google.com"},
            {"query": "subdomain.tunneling.exfiltration.test.net"},
            {"query": "safe-portal.company.com"}
        ]
        response = self.client.post("/predict/batch", json=batch)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["predictions"]), 3)
        self.assertEqual(data["specialist"], "DNS_Tunneling")
        for pred in data["predictions"]:
            self.assertIn("predicted_class_id", pred)
            self.assertIn("predicted_class", pred)
            self.assertEqual(len(pred["probabilities"]), 13)

    def test_13_mac_spoofing_strictly_rejected(self):
        """Any payload containing MAC references or mac_spoofing fields must return HTTP 400."""
        # 1. In /predict with MAC address field
        r1 = self.client.post("/predict", json={"src_mac": "00:11:22:33:44:55"})
        self.assertEqual(r1.status_code, 400)
        self.assertIn("mac spoofing is permanently excluded", r1.json()["detail"].lower())

        # 2. In /predict with explicit mac_spoofing flag
        r2 = self.client.post("/predict", json={"mac_spoofing": 1.0})
        self.assertEqual(r2.status_code, 400)
        self.assertIn("mac spoofing is permanently excluded", r2.json()["detail"].lower())

        # 3. In /predict/batch with MAC column
        batch = [
            {"query": "legit.org"},
            {"src_mac": "00:aa:bb:cc:dd:ee"}
        ]
        r3 = self.client.post("/predict/batch", json=batch)
        self.assertEqual(r3.status_code, 400)
        self.assertIn("mac spoofing is permanently excluded", r3.json()["detail"].lower())

    def test_14_flat_and_nested_payload_formats_both_supported(self):
        """API must support both flat `{"query": "..."}` and nested `{"features": {"query": "..."}}`."""
        flat = {"query": "flat-format.org"}
        nested = {"features": {"query": "nested-format.org"}, "specialist": "DNS_Tunneling"}
        
        r_flat = self.client.post("/predict", json=flat)
        self.assertEqual(r_flat.status_code, 200)
        
        r_nested = self.client.post("/predict", json=nested)
        self.assertEqual(r_nested.status_code, 200)
        self.assertEqual(r_flat.json()["specialist"], r_nested.json()["specialist"])


if __name__ == "__main__":
    unittest.main()
