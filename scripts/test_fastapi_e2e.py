"""
End-to-end HTTP API Verification Script for Smart AI-NIDS
Tests all 13 canonical classes and batch predictions directly against the live FastAPI server.
"""

import os
import sys
import json
import urllib.request
import pyarrow.parquet as pq
import pandas as pd

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_BASE = "http://127.0.0.1:8000"

def test_api():
    print("=" * 80)
    print("SMART AI NIDS - E2E FASTAPI HTTP VERIFICATION (13 CANONICAL CLASSES)")
    print("=" * 80)

    # 1. Test /health
    with urllib.request.urlopen(f"{API_BASE}/health") as r:
        health = json.loads(r.read())
        print(f"[HEALTH] Status: {health.get('status')} | Service: {health.get('service')}")
        assert health["status"] == "ok"
        assert health["engine_ready"] is True

    # 2. Test /models
    with urllib.request.urlopen(f"{API_BASE}/models") as r:
        models = json.loads(r.read())
        specs = list(models.get("specialists", {}).keys())
        classes = models.get("canonical_classes", [])
        print(f"[MODELS] Available specialists ({len(specs)}): {specs}")
        print(f"[MODELS] Canonical classes ({len(classes)}): {classes}")
        assert len(specs) == 5
        assert len(classes) == 13

    # 3. Load genuine test records
    p_ciciot = os.path.join(REPO_ROOT, "data", "processed", "CICIoT2023", "test.parquet")
    p_5g = os.path.join(REPO_ROOT, "data", "processed", "additional", "IP_Spoofing", "test.parquet")

    df_ciciot = pq.read_table(p_ciciot).to_pandas()
    df_5g = pd.read_parquet(p_5g)

    test_cases = [
        (0, "Benign", df_ciciot[df_ciciot["final_label"] == "Benign"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (1, "DDoS", df_ciciot[df_ciciot["final_label"] == "DDoS"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (2, "DoS", df_ciciot[df_ciciot["final_label"] == "DoS"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (3, "Botnet", df_ciciot[df_ciciot["final_label"] == "Botnet"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (4, "Infiltration", df_ciciot[df_ciciot["final_label"] == "Infiltration"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (5, "Brute Force", df_ciciot[df_ciciot["final_label"] == "Brute Force"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (6, "Web Attack", df_ciciot[df_ciciot["final_label"] == "Web Attack"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (7, "DNS Spoofing", df_ciciot[df_ciciot["final_label"] == "DNS Spoofing"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (8, "IP Spoofing", df_5g[df_5g["final_label"] == "IP Spoofing"].iloc[0].drop("final_label").to_dict(), "IP_Spoofing"),
        (9, "ARP Spoofing", {"frame_number": 2.0, "arp_opcode": 2}, "ARP_Spoofing"),
        (10, "Recon / Port Scan", df_ciciot[df_ciciot["final_label"] == "Recon / Port Scan"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (11, "MITM", df_ciciot[df_ciciot["final_label"] == "MITM"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        (12, "DNS Tunneling", {"query": "a.b.c.d.e.f.g.h.i.j.tunnel.com"}, "DNS_Tunneling")
    ]

    print("-" * 80)
    print("Testing /predict Endpoint on All 13 Canonical Classes:")
    all_passed = True
    http_results = []

    for cid, expected_name, feats, exp_spec in test_cases:
        payload = json.dumps({"features": feats, "specialist": "auto"}).encode("utf-8")
        req = urllib.request.Request(f"{API_BASE}/predict", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read())
            matched = (res["predicted_class_id"] == cid)
            if not matched:
                all_passed = False
            status = "PASS" if matched else "FAIL"
            print(f"Class {cid:2d} | Expected: {expected_name:<18} | Routed: {res['specialist']:<14} | Predicted: {res['predicted_class']:<18} (ID={res['predicted_class_id']:2d}, Conf={res['confidence']:.4f}) [{status}]")
            http_results.append({
                "canonical_id": cid,
                "expected": expected_name,
                "predicted": res["predicted_class"],
                "predicted_id": res["predicted_class_id"],
                "specialist": res["specialist"],
                "confidence": res["confidence"],
                "status": status
            })

    # 4. Test /predict/batch
    print("-" * 80)
    print("Testing /predict/batch Endpoint with Heterogeneous Record Set...")
    batch_records = [tc[2] for tc in test_cases]
    batch_payload = json.dumps({"records": batch_records, "specialist": "auto"}).encode("utf-8")
    req_batch = urllib.request.Request(f"{API_BASE}/predict/batch", data=batch_payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_batch) as resp:
        res_batch = json.loads(resp.read())
        preds = res_batch.get("predictions", [])
        print(f"Batch returned {len(preds)} predictions.")
        assert len(preds) == 13
        for idx, p in enumerate(preds):
            exp_cid = test_cases[idx][0]
            exp_name = test_cases[idx][1]
            m = (p["predicted_class_id"] == exp_cid)
            st = "PASS" if m else "FAIL"
            print(f"  Batch Record #{idx:2d} -> Expected: {exp_name:<18} | Got: {p['predicted_class']:<18} (ID={p['predicted_class_id']:2d}) [{st}]")
            if not m:
                all_passed = False

    print("=" * 80)
    print(f"OVERALL E2E FASTAPI TEST STATUS: {'ALL PASSED (13/13)' if all_passed else 'SOME FAILED'}")
    print("=" * 80)

    # Save e2e report
    out_path = os.path.join(REPO_ROOT, "reports", "fastapi_e2e_verification_report.json")
    with open(out_path, "w") as f:
        json.dump({
            "status": "PASS" if all_passed else "FAIL",
            "all_passed": all_passed,
            "results": http_results
        }, f, indent=4)
    print(f"Saved E2E report to: {out_path}")

    return all_passed

if __name__ == "__main__":
    success = test_api()
    sys.exit(0 if success else 1)
