"""Shared Analysis Session Manager for Smart AI-NIDS.

Manages persistent SQLite storage of traffic analysis sessions,
flows, and security alerts across the 4 Operations pages:
- Security Overview
- Traffic Analysis
- Threat Detection
- Alerts & Events
"""

import json
import os
import sqlite3
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class SessionManager:
    """Thread-safe SQLite storage for shared analysis sessions."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_dir = os.path.join(repo_root, "database")
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, "sessions.db")

        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    file_size_bytes INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_packets INTEGER DEFAULT 0,
                    total_flows INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    benign_count INTEGER DEFAULT 0,
                    detection_rate REAL DEFAULT 0.0,
                    duration_sec REAL DEFAULT 0.0,
                    suricata_alerts_count INTEGER DEFAULT 0,
                    protocol_dist_json TEXT DEFAULT '{}',
                    top_src_ips_json TEXT DEFAULT '[]',
                    top_dest_ips_json TEXT DEFAULT '[]',
                    attack_dist_json TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'COMPLETED'
                )
            """)

            # 2. Flows table (AI-NIDS inferences & network 5-tuples)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_flows (
                    flow_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    flow_index INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dest_ip TEXT,
                    src_port INTEGER,
                    dest_port INTEGER,
                    proto INTEGER,
                    packet_count INTEGER DEFAULT 1,
                    byte_count INTEGER DEFAULT 0,
                    specialist TEXT NOT NULL,
                    canonical_id INTEGER NOT NULL,
                    class_name TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    probabilities_json TEXT DEFAULT '[]',
                    is_threat INTEGER DEFAULT 0,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)

            # 3. Alerts table (Security incidents generated from detections)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_alerts (
                    alert_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    flow_id TEXT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dest_ip TEXT,
                    src_port INTEGER,
                    dest_port INTEGER,
                    proto INTEGER,
                    attack_category TEXT NOT NULL,
                    canonical_id INTEGER NOT NULL,
                    engine TEXT NOT NULL,
                    specialist TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    signature_info TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)

            # Indices for rapid querying and filtering
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_session ON session_flows(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session ON session_alerts(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON session_alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_cat ON session_alerts(attack_category)")
            conn.commit()

    def create_session(
        self,
        filename: str,
        file_type: str,
        file_size_bytes: int,
        total_packets: int,
        total_flows: int,
        threats_detected: int,
        benign_count: int,
        duration_sec: float,
        suricata_alerts_count: int,
        protocol_dist: Dict[str, int],
        top_src_ips: List[Dict[str, Any]],
        top_dest_ips: List[Dict[str, Any]],
        attack_dist: Dict[str, int],
        flows: List[Dict[str, Any]],
        alerts: List[Dict[str, Any]],
        status: str = "COMPLETED"
    ) -> str:
        """Create a new unified analysis session and store all flows and alerts atomically."""
        now = time.time()
        dt_str = datetime.fromtimestamp(now).strftime("%Y%m%d-%H%M%S")
        short_id = uuid.uuid4().hex[:6].upper()
        session_id = f"SES-{dt_str}-{short_id}"
        iso_now = datetime.fromtimestamp(now).isoformat()

        detection_rate = round((threats_detected / total_flows * 100.0), 2) if total_flows > 0 else 0.0

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Insert session
            cursor.execute("""
                INSERT INTO sessions (
                    session_id, filename, file_type, file_size_bytes, created_at,
                    timestamp, total_packets, total_flows, threats_detected,
                    benign_count, detection_rate, duration_sec, suricata_alerts_count,
                    protocol_dist_json, top_src_ips_json, top_dest_ips_json,
                    attack_dist_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                filename,
                file_type,
                file_size_bytes,
                now,
                iso_now,
                total_packets,
                total_flows,
                threats_detected,
                benign_count,
                detection_rate,
                duration_sec,
                suricata_alerts_count,
                json.dumps(protocol_dist),
                json.dumps(top_src_ips),
                json.dumps(top_dest_ips),
                json.dumps(attack_dist),
                status
            ))

            # Insert flows
            flow_rows = []
            for idx, fl in enumerate(flows):
                flow_id = fl.get("flow_id") or f"{session_id}-F{idx + 1:04d}"
                fl_ts = fl.get("timestamp") or iso_now
                cid = int(fl.get("canonical_id", 0))
                is_threat = 1 if cid != 0 else 0
                probs = fl.get("probabilities", [])
                flow_rows.append((
                    flow_id,
                    session_id,
                    idx + 1,
                    fl_ts,
                    fl.get("src_ip", "10.0.0.1"),
                    fl.get("dest_ip", "192.168.1.1"),
                    int(fl.get("src_port", 0) or 0),
                    int(fl.get("dest_port", 0) or 0),
                    int(fl.get("proto", 6) or 6),
                    int(fl.get("packet_count", 1) or 1),
                    int(fl.get("byte_count", 0) or 0),
                    fl.get("specialist", "UnifiedNIDS"),
                    cid,
                    fl.get("class_name", "Benign"),
                    float(fl.get("confidence", 0.95)),
                    fl.get("severity", "Low" if cid == 0 else "High"),
                    json.dumps(probs),
                    is_threat
                ))

            if flow_rows:
                cursor.executemany("""
                    INSERT INTO session_flows (
                        flow_id, session_id, flow_index, timestamp, src_ip, dest_ip,
                        src_port, dest_port, proto, packet_count, byte_count,
                        specialist, canonical_id, class_name, confidence, severity,
                        probabilities_json, is_threat
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, flow_rows)

            # Insert alerts
            alert_rows = []
            for idx, al in enumerate(alerts):
                alt_id = al.get("id") or al.get("alert_id") or f"ALT-{session_id}-{idx + 1:04d}"
                al_ts = al.get("timestamp") or iso_now
                cid = int(al.get("canonical_id", 1))
                alert_rows.append((
                    alt_id,
                    session_id,
                    al.get("flow_id"),
                    al_ts,
                    al.get("src_ip", "10.0.0.1"),
                    al.get("dest_ip", "192.168.1.1"),
                    int(al.get("src_port", 0) or 0),
                    int(al.get("dest_port", 0) or 0),
                    int(al.get("proto", 6) or 6),
                    al.get("attack_category", al.get("class_name", "Threat")),
                    cid,
                    al.get("engine", "Smart AI-NIDS"),
                    al.get("specialist", "UnifiedNIDS"),
                    float(al.get("confidence", 0.95)),
                    al.get("severity", "High"),
                    al.get("signature_info", "")
                ))

            if alert_rows:
                cursor.executemany("""
                    INSERT INTO session_alerts (
                        alert_id, session_id, flow_id, timestamp, src_ip, dest_ip,
                        src_port, dest_port, proto, attack_category, canonical_id,
                        engine, specialist, confidence, severity, signature_info
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, alert_rows)

            conn.commit()

        return session_id

    def list_sessions(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Return list of recent analysis sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id, filename, file_type, file_size_bytes, created_at,
                       timestamp, total_packets, total_flows, threats_detected,
                       benign_count, detection_rate, duration_sec, suricata_alerts_count, status
                FROM sessions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete session summary, all flows, and all alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            s_row = cursor.fetchone()
            if not s_row:
                return None

            session = dict(s_row)
            session["protocol_distribution"] = json.loads(session.pop("protocol_dist_json", "{}"))
            session["top_source_ips"] = json.loads(session.pop("top_src_ips_json", "[]"))
            session["top_destination_ips"] = json.loads(session.pop("top_dest_ips_json", "[]"))
            session["top_dest_ips"] = session["top_destination_ips"]
            session["attack_distribution"] = json.loads(session.pop("attack_dist_json", "{}"))
            session["attack_class_distribution"] = session["attack_distribution"]
            session["threat_flows"] = session["threats_detected"]
            session["benign_flows"] = session["benign_count"]
            session["execution_time_seconds"] = session["duration_sec"]

            # Fetch flows
            cursor.execute("""
                SELECT flow_id, flow_index, timestamp, src_ip, dest_ip, src_port, dest_port,
                       proto, packet_count, byte_count, specialist, canonical_id, class_name,
                       confidence, severity, probabilities_json, is_threat
                FROM session_flows
                WHERE session_id = ?
                ORDER BY flow_index ASC
            """, (session_id,))
            flows = []
            for r in cursor.fetchall():
                fl = dict(r)
                fl["probabilities"] = json.loads(fl.pop("probabilities_json", "[]"))
                flows.append(fl)
            session["flows"] = flows

            # Fetch alerts
            cursor.execute("""
                SELECT alert_id, session_id, flow_id, timestamp, src_ip, dest_ip, src_port, dest_port,
                       proto, attack_category, canonical_id, engine, specialist, confidence,
                       severity, signature_info
                FROM session_alerts
                WHERE session_id = ?
                ORDER BY alert_id ASC
            """, (session_id,))
            alerts = [dict(r) for r in cursor.fetchall()]
            session["alerts"] = alerts

            return session

    def get_latest_session(self) -> Optional[Dict[str, Any]]:
        """Retrieve the most recently created session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT session_id FROM sessions ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return None
            return self.get_session(row["session_id"])

    def clear_all(self):
        """Purge all sessions and associated flows/alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM session_alerts")
            cursor.execute("DELETE FROM session_flows")
            cursor.execute("DELETE FROM sessions")
            conn.commit()


_global_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Singleton provider for SessionManager."""
    global _global_session_manager
    if _global_session_manager is None:
        _global_session_manager = SessionManager()
    return _global_session_manager
