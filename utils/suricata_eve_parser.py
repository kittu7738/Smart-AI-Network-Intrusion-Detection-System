"""
Suricata EVE JSON Telemetry Parser for Smart AI-NIDS
Extracts alerts, flows, anomalies, DNS, and HTTP events into structured forensic objects.
"""

import os
import json
from typing import Dict, Any, List, Optional


class SuricataEveParser:
    """Parser and aggregator for Suricata Extensible Event Format (EVE JSON)."""

    def __init__(self, eve_path: str):
        if not os.path.exists(eve_path):
            raise FileNotFoundError(f"EVE JSON file not found at: {eve_path}")
        self.eve_path = eve_path

    def parse_all(self) -> Dict[str, Any]:
        """Parse the complete EVE JSON file into organized event streams."""
        alerts: List[Dict[str, Any]] = []
        flows: List[Dict[str, Any]] = []
        dns_events: List[Dict[str, Any]] = []
        http_events: List[Dict[str, Any]] = []
        tls_events: List[Dict[str, Any]] = []
        anomalies: List[Dict[str, Any]] = []
        raw_count = 0
        corrupt_lines = 0

        with open(self.eve_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    record = json.loads(clean_line)
                    raw_count += 1
                except Exception:
                    corrupt_lines += 1
                    continue

                event_type = record.get("event_type")

                if event_type == "alert":
                    alerts.append(self._parse_alert(record))
                elif event_type == "flow":
                    flows.append(self._parse_flow(record))
                elif event_type == "dns":
                    dns_events.append(self._parse_dns(record))
                elif event_type == "http":
                    http_events.append(self._parse_http(record))
                elif event_type == "tls":
                    tls_events.append(self._parse_tls(record))
                elif event_type == "anomaly":
                    anomalies.append(self._parse_anomaly(record))

        return {
            "summary": {
                "total_records": raw_count,
                "corrupt_records": corrupt_lines,
                "alert_count": len(alerts),
                "flow_count": len(flows),
                "dns_count": len(dns_events),
                "http_count": len(http_events),
                "tls_count": len(tls_events),
                "anomaly_count": len(anomalies)
            },
            "alerts": alerts,
            "flows": flows,
            "dns": dns_events,
            "http": http_events,
            "tls": tls_events,
            "anomalies": anomalies
        }

    def _extract_common(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract standardized 5-tuple and timing headers."""
        return {
            "timestamp": rec.get("timestamp"),
            "flow_id": rec.get("flow_id"),
            "pcap_cnt": rec.get("pcap_cnt"),
            "src_ip": rec.get("src_ip"),
            "src_port": rec.get("src_port"),
            "dest_ip": rec.get("dest_ip"),
            "dest_port": rec.get("dest_port"),
            "proto": rec.get("proto"),
            "app_proto": rec.get("app_proto"),
            "community_id": rec.get("community_id")
        }

    def _parse_alert(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract structured alert details."""
        alert_info = rec.get("alert", {})
        data = self._extract_common(rec)
        data.update({
            "event_type": "alert",
            "action": alert_info.get("action", "allowed"),
            "gid": alert_info.get("gid", 1),
            "sid": alert_info.get("signature_id"),
            "rev": alert_info.get("rev", 1),
            "signature": alert_info.get("signature", "Unknown Signature"),
            "category": alert_info.get("category", "Potentially Bad Traffic"),
            "severity": alert_info.get("severity", 3),
            "metadata": alert_info.get("metadata", {}),
            "payload_printable": rec.get("payload_printable", "")
        })
        return data

    def _parse_flow(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract flow-level aggregation metrics."""
        flow_info = rec.get("flow", {})
        data = self._extract_common(rec)
        data.update({
            "event_type": "flow",
            "pkts_toserver": flow_info.get("pkts_toserver", 0),
            "pkts_toclient": flow_info.get("pkts_toclient", 0),
            "bytes_toserver": flow_info.get("bytes_toserver", 0),
            "bytes_toclient": flow_info.get("bytes_toclient", 0),
            "start": flow_info.get("start"),
            "end": flow_info.get("end"),
            "age": flow_info.get("age", 0),
            "state": flow_info.get("state"),
            "reason": flow_info.get("reason"),
            "alerted": flow_info.get("alerted", False)
        })
        return data

    def _parse_dns(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract DNS transaction telemetry."""
        dns_info = rec.get("dns", {})
        data = self._extract_common(rec)
        data.update({
            "event_type": "dns",
            "type": dns_info.get("type"),
            "id": dns_info.get("id"),
            "rrname": dns_info.get("rrname"),
            "rrtype": dns_info.get("rrtype"),
            "tx_id": dns_info.get("tx_id"),
            "rcode": dns_info.get("rcode")
        })
        return data

    def _parse_http(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract HTTP protocol transaction."""
        http_info = rec.get("http", {})
        data = self._extract_common(rec)
        data.update({
            "event_type": "http",
            "hostname": http_info.get("hostname"),
            "url": http_info.get("url"),
            "http_method": http_info.get("http_method"),
            "status": http_info.get("status"),
            "http_user_agent": http_info.get("http_user_agent"),
            "length": http_info.get("length")
        })
        return data

    def _parse_tls(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract TLS handshake metadata."""
        tls_info = rec.get("tls", {})
        data = self._extract_common(rec)
        data.update({
            "event_type": "tls",
            "subject": tls_info.get("subject"),
            "issuerdn": tls_info.get("issuerdn"),
            "fingerprint": tls_info.get("fingerprint"),
            "version": tls_info.get("version"),
            "sni": tls_info.get("sni")
        })
        return data

    def _parse_anomaly(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract stream or decoder anomaly telemetry."""
        anom_info = rec.get("anomaly", {})
        data = self._extract_common(rec)
        data.update({
            "event_type": "anomaly",
            "anomaly_type": anom_info.get("type"),
            "anomaly_event": anom_info.get("event")
        })
        return data
