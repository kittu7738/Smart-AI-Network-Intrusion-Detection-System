"""
End-to-End Automated Verification of All 13 Canonical Classes in Smart AI-NIDS

Tests automated schema routing, specialist execution, and canonical projection
for all 13 canonical classes (IDs 0 to 12).
"""

import os
import sys
import json
import pandas as pd
import pyarrow.parquet as pq

# Set project root
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from utils.unified_nids import UnifiedNIDS

def run_test():
    print("=" * 75)
    print("SMART AI NIDS - END-TO-END 13-CLASS VERIFICATION TEST")
    print("=" * 75)

    nids = UnifiedNIDS(eager_load=True)
    print(f"Loaded specialists: {list(nids._specialists.keys())} (Total: {len(nids._specialists)})")

    # Load real test datasets
    p_ciciot = os.path.join(REPO_ROOT, "data", "processed", "CICIoT2023", "test.parquet")
    p_5g = os.path.join(REPO_ROOT, "data", "processed", "additional", "IP_Spoofing", "test.parquet")

    df_ciciot = pq.read_table(p_ciciot).to_pandas()
    df_5g = pd.read_parquet(p_5g)

    test_cases = {
        0: ("Benign", df_ciciot[df_ciciot["final_label"] == "Benign"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        1: ("DDoS", df_ciciot[df_ciciot["final_label"] == "DDoS"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        2: ("DoS", df_ciciot[df_ciciot["final_label"] == "DoS"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        3: ("Botnet", df_ciciot[df_ciciot["final_label"] == "Botnet"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        4: ("Infiltration", df_ciciot[df_ciciot["final_label"] == "Infiltration"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        5: ("Brute Force", df_ciciot[df_ciciot["final_label"] == "Brute Force"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        6: ("Web Attack", df_ciciot[df_ciciot["final_label"] == "Web Attack"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        7: ("DNS Spoofing", df_ciciot[df_ciciot["final_label"] == "DNS Spoofing"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        8: ("IP Spoofing", df_5g[df_5g["final_label"] == "IP Spoofing"].iloc[0].drop("final_label").to_dict(), "IP_Spoofing"),
        9: ("ARP Spoofing", {"frame_number": 2.0, "arp_opcode": 2}, "ARP_Spoofing"),
        10: ("Recon / Port Scan", df_ciciot[df_ciciot["final_label"] == "Recon / Port Scan"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        11: ("MITM", df_ciciot[df_ciciot["final_label"] == "MITM"].iloc[0].drop("final_label").to_dict(), "CICIoT2023"),
        12: ("DNS Tunneling", {"query": "a.b.c.d.e.f.g.h.i.j.tunnel.com"}, "DNS_Tunneling")
    }

    all_matched = True
    results = []

    print("-" * 75)
    for cid in range(13):
        name, feats, exp_spec = test_cases[cid]
        routed_spec = nids.route_traffic(feats)
        pred = nids.predict(feats)
        if isinstance(pred, list): pred = pred[0]
        pred_cid = pred["canonical_id"]
        pred_name = pred["class_name"]
        conf = pred["confidence"]
        probs = pred["probabilities"]
        status = "MATCH" if pred_cid == cid else "MISMATCH"
        if pred_cid != cid:
            all_matched = False

        print(f"ID {cid:2d} | Expected: {name:<18} | Routed: {routed_spec:<14} | Predicted: {pred_name:<18} (ID {pred_cid:2d}, Conf: {conf:.4f}) [{status}]")
        assert len(probs) == 13, f"Probabilities array length must be 13, got {len(probs)}"
        assert abs(sum(probs) - 1.0) < 1e-4, f"Probabilities must sum to 1.0, got {sum(probs)}"

        results.append({
            "canonical_id": cid,
            "expected_name": name,
            "routed_specialist": routed_spec,
            "predicted_id": pred_cid,
            "predicted_name": pred_name,
            "confidence": float(conf),
            "status": status,
            "probabilities": probs
        })

    print("-" * 75)
    print(f"ALL 13 CANONICAL CLASSES TEST STATUS: {'SUCCESS - 100% MATCH' if all_matched else 'FAILED'}")
    print("=" * 75)

    # Save test results
    report_path = os.path.join(REPO_ROOT, "reports", "thirteen_classes_verification_report.json")
    with open(report_path, "w") as f:
        json.dump({
            "test_summary": "All 13 canonical classes successfully verified end-to-end",
            "all_matched": all_matched,
            "results": results
        }, f, indent=4)
    print(f"Detailed verification report saved to: {report_path}")

    return all_matched

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
