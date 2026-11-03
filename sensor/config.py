"""
Configuration and Defaults for Smart AI-NIDS Local Sensor Agent
"""

import os

# Default backend connection
DEFAULT_BACKEND_URL = os.environ.get("SAI_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
DEFAULT_SENSOR_KEY = os.environ.get("SENSOR_API_KEY", "sai-sensor-secret-key-prod-2026")

# Ingestion settings
DEFAULT_BATCH_SIZE = int(os.environ.get("SENSOR_BATCH_SIZE", "20"))
DEFAULT_BATCH_INTERVAL_SEC = float(os.environ.get("SENSOR_BATCH_INTERVAL", "2.0"))
DEFAULT_FLOW_IDLE_TIMEOUT_SEC = float(os.environ.get("SENSOR_FLOW_TIMEOUT", "5.0"))
MAX_BUFFER_FLOWS = 2000
MAX_BUFFER_PACKETS = 10000

# Suricata live monitoring
SURICATA_DEFAULT_YAML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "suricata",
    "suricata.yaml"
)
