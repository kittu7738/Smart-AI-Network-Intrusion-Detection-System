"""
Sensor Client Transmitter for Smart AI-NIDS
Transmits micro-batches of live sensor flows and Suricata alerts to the central FastAPI backend
over authenticated HTTPS with retry resilience and queue bounds.
"""

import time
import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

logger = logging.getLogger("Sensor.Client")


class SensorClient:
    """Manages authenticated batch transmission to central FastAPI backend."""

    def __init__(self, backend_url: str, api_key: str, sensor_id: str = "sensor-macbook-en0"):
        self.backend_url = backend_url.rstrip("/")
        self.api_key = api_key
        self.sensor_id = sensor_id
        self.session_token: Optional[str] = None
        self.is_registered = False

    def register(self, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Register the sensor with the central backend."""
        url = f"{self.backend_url}/sensor/register"
        payload = {
            "sensor_id": self.sensor_id,
            "api_key": self.api_key,
            "metadata": metadata or {}
        }
        headers = {
            "Content-Type": "application/json",
            "X-Sensor-Key": self.api_key
        }

        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status in (200, 201):
                    res_data = json.loads(response.read().decode("utf-8"))
                    self.session_token = res_data.get("session_token", self.api_key)
                    self.is_registered = True
                    logger.info(f"Sensor registered successfully: {self.sensor_id} (session: {self.session_token})")
                    return True
        except Exception as e:
            logger.warning(f"Registration failed against {url}: {e}. Will retry during transmission.")
            return False

    def transmit_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Transmit a batch of live telemetry events to /sensor/ingest."""
        if not events:
            return True

        url = f"{self.backend_url}/sensor/ingest"
        payload = {
            "sensor_id": self.sensor_id,
            "timestamp": time.time(),
            "batch_size": len(events),
            "events": events
        }
        headers = {
            "Content-Type": "application/json",
            "X-Sensor-Key": self.api_key
        }

        # Try up to 3 attempts with brief backoff
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=8) as response:
                    if response.status == 200:
                        return True
            except urllib.error.HTTPError as he:
                if he.code == 401 or he.code == 403:
                    logger.error(f"Sensor authorization rejected by backend (HTTP {he.code}). Check SENSOR_API_KEY.")
                    return False
                time.sleep(0.5 * (attempt + 1))
            except Exception as e:
                logger.warning(f"Batch transmission attempt {attempt + 1} failed: {e}")
                time.sleep(0.5 * (attempt + 1))

        return False
