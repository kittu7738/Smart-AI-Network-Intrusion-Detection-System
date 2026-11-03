"""
Smart AI-NIDS Local Network Sensor Agent (CLI)
Executes authorized passive packet capture, real-time flow feature extraction,
concurrent Suricata live engine inspection, and authenticated telemetry streaming
to the central Smart AI-NIDS FastAPI backend.
"""

import sys
import time
import signal
import logging
import argparse
from typing import List, Dict, Any

from sensor.config import (
    DEFAULT_BACKEND_URL,
    DEFAULT_SENSOR_KEY,
    DEFAULT_BATCH_SIZE,
    DEFAULT_BATCH_INTERVAL_SEC,
    DEFAULT_FLOW_IDLE_TIMEOUT_SEC
)
from sensor.network_sniffer import NetworkSniffer
from sensor.live_feature_extractor import LiveFeatureExtractor
from sensor.suricata_live_runner import SuricataLiveRunner
from sensor.sensor_client import SensorClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("Sensor.Agent")


class SensorAgent:
    """Coordinates local passive network capture, ML feature extraction, and cloud ingestion."""

    def __init__(
        self,
        interface: str = "lo0",
        backend_url: str = DEFAULT_BACKEND_URL,
        api_key: str = DEFAULT_SENSOR_KEY,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_interval: float = DEFAULT_BATCH_INTERVAL_SEC,
        enable_suricata: bool = True
    ):
        self.interface = interface
        self.backend_url = backend_url
        self.api_key = api_key
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.enable_suricata = enable_suricata

        self.extractor = LiveFeatureExtractor(idle_timeout_sec=DEFAULT_FLOW_IDLE_TIMEOUT_SEC)
        self.pending_events: List[Dict[str, Any]] = []
        self._is_running = False

        # Initialize sniffer
        self.sniffer = NetworkSniffer(
            interface=self.interface,
            on_packet_callback=self._handle_packet
        )

        # Initialize client
        self.client = SensorClient(
            backend_url=self.backend_url,
            api_key=self.api_key,
            sensor_id=f"sensor-{self.interface}"
        )

        # Initialize Suricata live runner if requested
        self.suricata_runner = None
        if self.enable_suricata:
            self.suricata_runner = SuricataLiveRunner(
                interface=self.interface,
                on_alert_callback=self._handle_suricata_alert
            )

    def _handle_packet(self, pkt):
        """Callback from packet sniffer."""
        immediate_event = self.extractor.process_packet(pkt)
        if immediate_event:
            self.pending_events.append(immediate_event)

    def _handle_suricata_alert(self, alert: Dict[str, Any]):
        """Callback from Suricata live engine."""
        self.pending_events.append({
            "event_type": "SURICATA_ALERT",
            "timestamp": alert.get("timestamp", time.time()),
            "src_ip": alert.get("src_ip"),
            "dest_ip": alert.get("dest_ip"),
            "src_port": alert.get("src_port"),
            "dest_port": alert.get("dest_port"),
            "proto": alert.get("proto"),
            "engine": "Suricata Traditional NIDS",
            "signature_id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "severity": alert.get("severity"),
            "canonical_id": alert.get("canonical_id"),
            "canonical_class": alert.get("canonical_class")
        })

    def start(self, duration_sec: int = 0):
        """Run the sensor agent."""
        self._is_running = True
        logger.info("=" * 70)
        logger.info(f"SMART AI-NIDS LOCAL SENSOR AGENT INITIALIZING")
        logger.info(f"  Interface      : {self.interface}")
        logger.info(f"  Backend URL    : {self.backend_url}")
        logger.info(f"  Live Suricata  : {'ENABLED' if self.suricata_runner and self.suricata_runner.is_available else 'DISABLED'}")
        logger.info("=" * 70)

        # Validate interface permissions
        perm = self.sniffer.validate_permissions()
        if not perm["valid"]:
            logger.error(f"Permission validation failed: {perm.get('error')}")
            return

        # Register sensor with backend
        self.client.register({
            "interface": self.interface,
            "suricata_enabled": bool(self.suricata_runner and self.suricata_runner.is_available),
            "start_time": time.time()
        })

        # Start sniffer
        self.sniffer.start()

        # Start Suricata if available
        if self.suricata_runner and self.suricata_runner.is_available:
            self.suricata_runner.start()

        last_flush_time = time.time()
        start_time = time.time()

        try:
            while self._is_running:
                time.sleep(0.2)
                now = time.time()

                # Check duration limit
                if duration_sec > 0 and (now - start_time) >= duration_sec:
                    logger.info(f"Duration limit reached ({duration_sec}s). Stopping sensor...")
                    break

                # Flush expired flows from feature extractor
                expired = self.extractor.flush_expired_flows(current_time=now)
                if expired:
                    self.pending_events.extend(expired)

                # Batch transmission condition
                time_elapsed = now - last_flush_time
                if (len(self.pending_events) >= self.batch_size) or (time_elapsed >= self.batch_interval and self.pending_events):
                    batch_to_send = self.pending_events[:self.batch_size]
                    self.pending_events = self.pending_events[self.batch_size:]

                    ok = self.client.transmit_batch(batch_to_send)
                    if ok:
                        logger.info(f"Ingested batch of {len(batch_to_send)} events to {self.backend_url} (Pkts: {self.sniffer.stats['packets_captured']})")
                    else:
                        logger.warning(f"Failed to transmit batch of {len(batch_to_send)} events; queued for retry.")
                        self.pending_events.extend(batch_to_send)

                    last_flush_time = now

        except KeyboardInterrupt:
            logger.info("Shutdown requested by user (Ctrl+C).")
        finally:
            self.stop()

    def stop(self):
        """Clean shutdown of all monitoring threads and engines."""
        self._is_running = False
        logger.info("Stopping local network sensor...")

        if self.sniffer:
            self.sniffer.stop()

        if self.suricata_runner:
            self.suricata_runner.stop()

        # Flush any remaining events
        remaining = self.extractor.flush_expired_flows(force_all=True)
        if remaining:
            self.pending_events.extend(remaining)

        if self.pending_events:
            logger.info(f"Flushing final {len(self.pending_events)} events before exit...")
            self.client.transmit_batch(self.pending_events)
            self.pending_events.clear()

        logger.info("Sensor agent shutdown complete.")


def main():
    parser = argparse.ArgumentParser(description="Smart AI-NIDS Local Sensor Agent")
    parser.add_argument("-i", "--interface", default="lo0", help="Network interface to monitor (e.g. en0, lo0, eth0)")
    parser.add_argument("-b", "--backend", default=DEFAULT_BACKEND_URL, help="FastAPI backend URL (e.g. http://127.0.0.1:8000)")
    parser.add_argument("-k", "--api-key", default=DEFAULT_SENSOR_KEY, help="Sensor API authentication key")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Flow micro-batch size")
    parser.add_argument("--duration", type=int, default=0, help="Run duration in seconds (0 for continuous)")
    parser.add_argument("--no-suricata", action="store_true", help="Disable local Suricata live process")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")

    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = NetworkSniffer.get_available_interfaces()
        print("Available Network Interfaces:")
        for ifc in ifaces:
            print(f"  - {ifc['name']} (Loopback: {ifc['is_loopback']})")
        return

    agent = SensorAgent(
        interface=args.interface,
        backend_url=args.backend,
        api_key=args.api_key,
        batch_size=args.batch_size,
        enable_suricata=not args.no_suricata
    )

    def handle_signal(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    agent.start(duration_sec=args.duration)


if __name__ == "__main__":
    main()
