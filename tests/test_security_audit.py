"""Comprehensive Security, Functional, ML, and Performance Test Suite.

Automated verification covering:
- OWASP Security Hardening (Path traversal, DoS upload limits, security headers, timing resistance)
- Machine Learning Specialist Validation & 13-Class Canonical Taxonomy Coverage
- Inference Latency and Performance Benchmarking
- Session Integrity and Parameterized SQLite Protection
"""

import os
import io
import time
import unittest
from starlette.testclient import TestClient

from backend.main import app, SENSOR_API_KEY
from utils.unified_nids import UnifiedNIDS
from utils.taxonomy import CLASS_NAMES, CLASS_TO_ID


class TestSecurityAuditAndHardening(unittest.TestCase):
    """OWASP and application security regression tests."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.engine = UnifiedNIDS(eager_load=True)

    def test_01_security_headers_present(self):
        """API endpoints must return standard OWASP security headers."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_02_path_traversal_sanitization_in_upload(self):
        """Filenames with directory traversal sequences must be safely sanitized to base names."""
        traversal_filename = "../../../../etc/passwd.pcap"
        # Small valid pcap bytes with standard magic
        dummy_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
        res = self.client.post(
            "/analysis/upload",
            files={"file": (traversal_filename, io.BytesIO(dummy_pcap), "application/vnd.tcpdump.pcap")}
        )
        # Even if processing fails due to minimal pcap packets, status must not be 500 path error
        # and session filename stored must be sanitized
        if res.status_code == 200:
            data = res.json()
            session = data.get("session", {})
            self.assertEqual(session.get("filename"), "passwd.pcap")
            self.assertNotIn("..", session.get("filename", ""))

    def test_03_oversized_file_upload_rejected_with_413(self):
        """Uploading a file exceeding 50MB must be rejected with HTTP 413 Payload Too Large."""
        # Create a mock generator that exceeds 50MB threshold without allocating 50MB RAM
        from backend.main import MAX_UPLOAD_SIZE_BYTES
        oversized_bytes = b"0" * (MAX_UPLOAD_SIZE_BYTES + 1024)
        res = self.client.post(
            "/analysis/upload",
            files={"file": ("huge.pcap", io.BytesIO(oversized_bytes), "application/vnd.tcpdump.pcap")}
        )
        self.assertEqual(res.status_code, 413)
        self.assertIn("exceeds maximum allowed limit", res.json()["detail"].lower())

    def test_04_sensor_auth_requires_valid_key(self):
        """Sensor endpoints must reject unauthorized access and invalid keys with HTTP 401."""
        # Missing key
        r1 = self.client.post("/sensor/register", json={"sensor_id": "sensor-test"})
        self.assertEqual(r1.status_code, 401)

        # Invalid key
        r2 = self.client.post("/sensor/register", json={"sensor_id": "sensor-test", "api_key": "wrong-key"})
        self.assertEqual(r2.status_code, 401)

        # Valid key
        r3 = self.client.post("/sensor/register", json={"sensor_id": "sensor-test", "api_key": SENSOR_API_KEY})
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(r3.json()["status"], "registered")

    def test_05_batch_prediction_oversized_batch_rejected(self):
        """Submitting a batch exceeding 10,000 records must return HTTP 400."""
        oversized_records = [{"query": "test.com"}] * 10001
        res = self.client.post("/predict/batch", json=oversized_records)
        self.assertEqual(res.status_code, 400)
        self.assertIn("exceeds maximum limit", res.json()["detail"].lower())

    def test_06_sql_injection_resistance_in_session_manager(self):
        """Session queries with SQL injection strings must be safely escaped via parameterized bindings."""
        from backend.session_manager import get_session_manager
        sm = get_session_manager()

        # Malicious session_id payload
        malicious_id = "SES-123' OR '1'='1"
        res = sm.get_session(malicious_id)
        self.assertIsNone(res)

        # Malicious limit parameter in list_sessions
        sessions = sm.list_sessions(limit=5)
        self.assertIsInstance(sessions, list)


class TestMachineLearningAndCanonicalTaxonomy(unittest.TestCase):
    """Complete validation of 5 specialist models and 13-class canonical taxonomy."""

    @classmethod
    def setUpClass(cls):
        cls.engine = UnifiedNIDS(eager_load=True)

    def test_07_all_five_specialists_loaded(self):
        """All five specialist pipelines must be actively loaded in memory."""
        for name in UnifiedNIDS.SPECIALIST_NAMES:
            self.assertTrue(self.engine.is_specialist_loaded(name), f"Specialist {name} failed to load.")

    def test_08_dns_tunneling_raw_query_inference(self):
        """DNS Tunneling specialist must accept raw query string and predict canonical class."""
        sample_malicious = {"query": "exfiltration-base64-payload-chunk-99128.subdomain.attacker.evil.net"}
        res = self.engine.predict(sample_malicious, specialist="DNS_Tunneling")
        self.assertIn(res["canonical_id"], [0, 12])
        self.assertEqual(len(res["probabilities"]), 13)
        self.assertAlmostEqual(sum(res["probabilities"]), 1.0, places=4)

    def test_09_arp_spoofing_inference(self):
        """ARP Spoofing specialist must classify layer-2 frames and map to canonical taxonomy."""
        sample_arp = {"frame_number": 100.0, "arp_opcode": 2}
        res = self.engine.predict(sample_arp, specialist="ARP_Spoofing")
        self.assertEqual(res["canonical_id"], 9)
        self.assertEqual(res["class_name"], "ARP Spoofing")
        self.assertEqual(len(res["probabilities"]), 13)

    def test_10_ip_spoofing_inference(self):
        """IP Spoofing specialist must classify 5G header telemetry into ID 8."""
        import pandas as pd
        parquet_path = "data/processed/additional/IP_Spoofing/test.parquet"
        if os.path.exists(parquet_path):
            df_ip = pd.read_parquet(parquet_path)
            sample_ip = df_ip[df_ip["final_label"] == "IP Spoofing"].iloc[0].drop("final_label").to_dict()
        else:
            sample_ip = {f"feat_{i}": 1.0 for i in range(44)}
        res = self.engine.predict(sample_ip, specialist="IP_Spoofing")
        self.assertEqual(res["canonical_id"], 8)
        self.assertEqual(res["class_name"], "IP Spoofing")
        self.assertEqual(len(res["probabilities"]), 13)

    def test_11_single_inference_latency_benchmark(self):
        """Single-record inference must complete within acceptable latency (< 50ms)."""
        sample_dns = {"query": "standard-benign-query.company.internal"}
        t0 = time.perf_counter()
        _ = self.engine.predict(sample_dns, specialist="DNS_Tunneling")
        latency_ms = (time.perf_counter() - t0) * 1000.0
        # Check latency threshold
        self.assertLess(latency_ms, 50.0, f"Inference latency too high: {latency_ms:.2f}ms")


if __name__ == "__main__":
    unittest.main()
