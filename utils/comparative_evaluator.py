"""
Comparative Evaluation Engine: Traditional NIDS (Suricata) vs Proposed Smart AI-NIDS
Executes parallel evaluation on identical PCAP traffic, correlates detections,
and computes comparative performance, latency, and detection coverage metrics.
"""

import os
import time
from typing import Dict, Any, List, Optional
from collections import Counter

from utils.suricata_runner import run_suricata_pcap, get_suricata_version
from utils.suricata_eve_parser import SuricataEveParser
from utils.suricata_mapper import map_suricata_alert, RULE_COVERAGE_STATUS
from utils.pcap_flow_extractor import PcapFlowExtractor
from utils.unified_nids import UnifiedNIDS
from utils.taxonomy import CLASS_NAMES, ID_TO_CLASS


class ComparativeEvaluator:
    """Orchestrates side-by-side empirical comparison between Suricata and UnifiedNIDS."""

    def __init__(self, nids_engine: Optional[UnifiedNIDS] = None):
        if nids_engine is None:
            self.nids = UnifiedNIDS(eager_load=True)
        else:
            self.nids = nids_engine

    def evaluate_pcap(
        self,
        pcap_path: str,
        config_path: Optional[str] = None,
        max_packets: int = 25000
    ) -> Dict[str, Any]:
        """Run identical PCAP traffic through both Suricata and UnifiedNIDS.

        Returns comprehensive side-by-side evaluation metrics.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        pcap_size = os.path.getsize(pcap_path)

        # ----------------------------------------------------------------------
        # 1. TRADITIONAL NIDS BRANCH: Suricata Analysis
        # ----------------------------------------------------------------------
        suricata_status = get_suricata_version()
        suricata_results = {
            "available": suricata_status["available"],
            "version": suricata_status["version"],
            "execution_duration": 0.0,
            "alerts": [],
            "flows": [],
            "alert_count": 0,
            "raw_events_count": 0,
            "class_distribution": {name: 0 for name in CLASS_NAMES}
        }

        if suricata_status["available"]:
            run_out = run_suricata_pcap(pcap_path, config_path=config_path) if config_path else run_suricata_pcap(pcap_path)
            if run_out["status"] == "SUCCESS" and run_out["eve_path"]:
                parser = SuricataEveParser(run_out["eve_path"])
                parsed_eve = parser.parse_all()

                suricata_results["execution_duration"] = run_out["duration_seconds"]
                suricata_results["raw_events_count"] = parsed_eve["summary"]["total_records"]
                suricata_results["flows"] = parsed_eve["flows"]

                # Map each alert to canonical taxonomy
                mapped_alerts = []
                for a in parsed_eve["alerts"]:
                    mapped = map_suricata_alert(a)
                    a["canonical_id"] = mapped["canonical_id"]
                    a["canonical_class"] = mapped["canonical_class"]
                    a["mapping_method"] = mapped["mapping_method"]
                    mapped_alerts.append(a)

                    if mapped["canonical_class"] in suricata_results["class_distribution"]:
                        suricata_results["class_distribution"][mapped["canonical_class"]] += 1
                    else:
                        suricata_results["class_distribution"]["Unmapped Alert"] = (
                            suricata_results["class_distribution"].get("Unmapped Alert", 0) + 1
                        )

                suricata_results["alerts"] = mapped_alerts
                suricata_results["alert_count"] = len(mapped_alerts)

        # ----------------------------------------------------------------------
        # 2. PROPOSED AI-NIDS BRANCH: Flow Extraction + Unified Inference
        # ----------------------------------------------------------------------
        ai_start = time.perf_counter()
        extractor = PcapFlowExtractor(pcap_path, max_packets=max_packets)
        extracted_flows = extractor.extract_flows()
        extraction_duration = time.perf_counter() - ai_start

        ai_infer_start = time.perf_counter()
        ai_predictions = []
        ai_class_counts = {name: 0 for name in CLASS_NAMES}
        total_packets_processed = 0

        for f_rec in extracted_flows:
            meta = f_rec.pop("_meta", {})
            total_packets_processed += meta.get("packet_count", 1)

            # Predict using auto-routing
            pred = self.nids.predict(f_rec, specialist="auto")
            if isinstance(pred, list):
                pred = pred[0]

            pred_record = {
                "canonical_id": pred["canonical_id"],
                "class_name": pred["class_name"],
                "confidence": pred["confidence"],
                "specialist": pred["specialist"],
                "probabilities": pred["probabilities"],
                "src_ip": meta.get("src_ip"),
                "dest_ip": meta.get("dest_ip"),
                "src_port": meta.get("src_port"),
                "dest_port": meta.get("dest_port"),
                "proto": meta.get("proto"),
                "packet_count": meta.get("packet_count"),
                "byte_count": meta.get("byte_count")
            }
            ai_predictions.append(pred_record)
            ai_class_counts[pred["class_name"]] = ai_class_counts.get(pred["class_name"], 0) + 1

        ai_infer_duration = time.perf_counter() - ai_infer_start
        total_ai_duration = extraction_duration + ai_infer_duration

        ai_threat_count = sum(1 for p in ai_predictions if p["canonical_id"] != 0)

        # ----------------------------------------------------------------------
        # 3. CORRELATION & COMPARATIVE METRICS
        # ----------------------------------------------------------------------
        # Index Suricata alerts by 5-tuple
        suricata_alert_5tuples = set()
        for a in suricata_results["alerts"]:
            key = (str(a.get("src_ip")), str(a.get("dest_ip")), a.get("src_port"), a.get("dest_port"), a.get("proto"))
            suricata_alert_5tuples.add(key)
            # Add reverse key for bidirectional matching
            rev_key = (str(a.get("dest_ip")), str(a.get("src_ip")), a.get("dest_port"), a.get("src_port"), a.get("proto"))
            suricata_alert_5tuples.add(rev_key)

        both_threat = 0
        ai_only_threat = 0
        suricata_only_threat = 0
        both_benign = 0

        for p in ai_predictions:
            flow_key = (str(p["src_ip"]), str(p["dest_ip"]), p["src_port"], p["dest_port"], p["proto"])
            has_suricata_alert = flow_key in suricata_alert_5tuples
            is_ai_threat = (p["canonical_id"] != 0)

            if has_suricata_alert and is_ai_threat:
                both_threat += 1
            elif not has_suricata_alert and is_ai_threat:
                ai_only_threat += 1
            elif has_suricata_alert and not is_ai_threat:
                suricata_only_threat += 1
            else:
                both_benign += 1

        # Throughput calculations
        suri_dur = max(0.001, suricata_results["execution_duration"])
        ai_dur = max(0.001, total_ai_duration)

        return {
            "traffic_source": {
                "file_path": os.path.abspath(pcap_path),
                "file_size_bytes": pcap_size,
                "total_packets": total_packets_processed,
                "total_flows": len(ai_predictions)
            },
            "traditional_nids_suricata": {
                "engine": "Suricata",
                "version": suricata_results["version"],
                "status": "ONLINE" if suricata_status["available"] else "OFFLINE",
                "total_alerts": suricata_results["alert_count"],
                "total_flows_tracked": len(suricata_results["flows"]),
                "execution_duration_sec": suricata_results["execution_duration"],
                "throughput_packets_per_sec": round(total_packets_processed / suri_dur, 1) if suricata_status["available"] else 0.0,
                "class_distribution": suricata_results["class_distribution"],
                "sample_alerts": suricata_results["alerts"][:15]
            },
            "smart_ai_nids": {
                "engine": "UnifiedNIDS (5 ML Specialists)",
                "status": "ONLINE",
                "total_inferences": len(ai_predictions),
                "threats_detected": ai_threat_count,
                "benign_classified": len(ai_predictions) - ai_threat_count,
                "extraction_duration_sec": round(extraction_duration, 4),
                "inference_duration_sec": round(ai_infer_duration, 4),
                "total_duration_sec": round(total_ai_duration, 4),
                "throughput_flows_per_sec": round(len(ai_predictions) / ai_dur, 1),
                "class_distribution": ai_class_counts,
                "sample_predictions": ai_predictions[:15]
            },
            "comparative_analysis": {
                "mutual_threat_detections": both_threat,
                "ai_only_novel_detections": ai_only_threat,
                "suricata_only_detections": suricata_only_threat,
                "mutual_benign_flows": both_benign,
                "detection_coverage_delta": {
                    "suricata_covered_classes": sum(1 for c, st in RULE_COVERAGE_STATUS.items() if st["supported"]),
                    "ai_covered_classes": 13,
                    "unsupported_in_suricata": ["ARP Spoofing"]
                },
                "latency_comparison": {
                    "suricata_total_sec": suricata_results["execution_duration"],
                    "ai_total_sec": round(total_ai_duration, 4),
                    "ai_inference_only_sec": round(ai_infer_duration, 4)
                }
            }
        }
