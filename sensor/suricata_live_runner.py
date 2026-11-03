"""
Suricata Live Monitoring Process Manager
Launches Suricata in live IDS mode on a local interface, tails EVE JSON in real time,
and streams signature alerts into normalized sensor events.
"""

import os
import time
import json
import shutil
import tempfile
import logging
import subprocess
import threading
from typing import Dict, Any, List, Optional, Callable

from utils.suricata_runner import find_suricata_binary, get_suricata_version
from utils.suricata_mapper import map_suricata_alert

logger = logging.getLogger("Sensor.Suricata")


class SuricataLiveRunner:
    """Manages a background Suricata live monitoring instance."""

    def __init__(
        self,
        interface: str = "lo0",
        config_path: Optional[str] = None,
        on_alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.interface = interface
        self.config_path = config_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "suricata",
            "suricata.yaml"
        )
        self.on_alert_callback = on_alert_callback

        self.binary_path = find_suricata_binary()
        self.is_available = bool(self.binary_path)

        self._process: Optional[subprocess.Popen] = None
        self._tail_thread: Optional[threading.Thread] = None
        self._is_running = False
        self._temp_dir = None

        self.stats = {
            "alerts_fired": 0,
            "flows_logged": 0,
            "events_read": 0,
            "start_time": 0.0,
            "interface": self.interface,
            "status": "STOPPED"
        }

    def start(self) -> bool:
        """Start Suricata live process and begin tailing eve.json."""
        if not self.is_available:
            logger.warning("Suricata binary not available. Live rule monitoring disabled.")
            return False

        if self._is_running:
            return True

        self._temp_dir = tempfile.mkdtemp(prefix="suricata_live_")
        eve_path = os.path.join(self._temp_dir, "eve.json")

        cmd = [
            self.binary_path,
            "-c", self.config_path,
            "-i", self.interface,
            "-l", self._temp_dir,
            "--runmode", "single"
        ]

        logger.info(f"Launching Suricata live engine: {' '.join(cmd)}")
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self._is_running = True
            self.stats["start_time"] = time.time()
            self.stats["status"] = "RUNNING"

            # Background thread to tail eve.json
            self._tail_thread = threading.Thread(target=self._tail_eve_file, args=(eve_path,), daemon=True)
            self._tail_thread.start()
            return True
        except Exception as e:
            logger.error(f"Failed to launch Suricata live engine: {e}")
            self.stats["status"] = f"ERROR: {e}"
            self._is_running = False
            return False

    def _tail_eve_file(self, eve_path: str):
        """Tail and parse generated EVE JSON lines as they are appended."""
        # Wait for file to be created
        wait_start = time.time()
        while self._is_running and not os.path.exists(eve_path):
            if time.time() - wait_start > 10.0:
                break
            time.sleep(0.5)

        if not os.path.exists(eve_path):
            return

        with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
            while self._is_running:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    event = json.loads(line_str)
                    self.stats["events_read"] += 1
                    event_type = event.get("event_type")

                    if event_type == "alert":
                        self.stats["alerts_fired"] += 1
                        mapped = map_suricata_alert(event)
                        alert_record = {
                            "engine": "Suricata Traditional NIDS",
                            "timestamp": event.get("timestamp", time.time()),
                            "src_ip": event.get("src_ip"),
                            "dest_ip": event.get("dest_ip"),
                            "src_port": event.get("src_port"),
                            "dest_port": event.get("dest_port"),
                            "proto": event.get("proto", "IP"),
                            "signature_id": event.get("alert", {}).get("signature_id"),
                            "signature": event.get("alert", {}).get("signature"),
                            "severity": event.get("alert", {}).get("severity", 2),
                            "category": event.get("alert", {}).get("category"),
                            "canonical_id": mapped["canonical_id"],
                            "canonical_class": mapped["canonical_class"],
                            "community_id": event.get("community_id", "")
                        }
                        if self.on_alert_callback:
                            self.on_alert_callback(alert_record)

                    elif event_type == "flow":
                        self.stats["flows_logged"] += 1
                except Exception:
                    continue

    def stop(self):
        """Stop Suricata live engine cleanly."""
        self._is_running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3.0)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

        self.stats["status"] = "STOPPED"
        logger.info(f"Suricata live engine stopped on '{self.interface}'. Total alerts: {self.stats['alerts_fired']}")
