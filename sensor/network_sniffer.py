"""
Passive Network Sniffer for Smart AI-NIDS Local Sensor
Handles interface discovery, permission validation, non-blocking packet capture,
and thread-safe streaming to the LiveFeatureExtractor.
"""

import time
import socket
import logging
import threading
from typing import List, Dict, Any, Optional, Callable
import scapy.all as scapy

logger = logging.getLogger("Sensor.Sniffer")


class NetworkSniffer:
    """Manages passive packet capture on a designated network interface."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        on_packet_callback: Optional[Callable[[Any], None]] = None
    ):
        self.interface = interface or self.get_default_interface()
        self.bpf_filter = bpf_filter
        self.on_packet_callback = on_packet_callback

        self._is_running = False
        self._sniffer_thread: Optional[threading.Thread] = None
        self._async_sniffer = None

        self.stats = {
            "start_time": 0.0,
            "packets_captured": 0,
            "bytes_captured": 0,
            "capture_errors": 0,
            "interface": self.interface
        }

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, Any]]:
        """Discover and list all operational network interfaces."""
        ifaces = []
        try:
            raw_list = scapy.get_if_list()
        except Exception:
            raw_list = ["en0", "lo0", "eth0"]

        for iface in raw_list:
            ifaces.append({
                "name": iface,
                "is_loopback": "lo" in iface.lower(),
                "status": "UP"
            })
        return ifaces

    @classmethod
    def get_default_interface(cls) -> str:
        """Resolve a suitable default active interface."""
        ifaces = cls.get_available_interfaces()
        # Prefer physical eth/en interfaces over loopback
        for ifc in ifaces:
            name = ifc["name"]
            if name.startswith(("en", "eth", "wlan")) and not ifc["is_loopback"]:
                return name
        return "lo0" if any(i["name"] == "lo0" for i in ifaces) else (ifaces[0]["name"] if ifaces else "lo0")

    def validate_permissions(self) -> Dict[str, Any]:
        """Test whether packet capture is permitted on the chosen interface."""
        try:
            test_pkts = scapy.sniff(iface=self.interface, count=1, timeout=1, store=False)
            return {
                "valid": True,
                "interface": self.interface,
                "message": f"Packet sniffing permission granted on {self.interface}."
            }
        except PermissionError as pe:
            return {
                "valid": False,
                "interface": self.interface,
                "error": f"Permission Denied: Run with root/sudo or grant BPF read privileges: {str(pe)}"
            }
        except Exception as e:
            return {
                "valid": False,
                "interface": self.interface,
                "error": f"Sniffer check error on {self.interface}: {str(e)}"
            }

    def _packet_handler(self, pkt):
        """Internal callback invoked per packet."""
        self.stats["packets_captured"] += 1
        self.stats["bytes_captured"] += len(pkt)

        if self.on_packet_callback:
            try:
                self.on_packet_callback(pkt)
            except Exception as e:
                self.stats["capture_errors"] += 1

    def start(self):
        """Start passive packet sniffing in a background daemon thread."""
        if self._is_running:
            return

        self._is_running = True
        self.stats["start_time"] = time.time()
        self.stats["packets_captured"] = 0
        self.stats["bytes_captured"] = 0
        self.stats["capture_errors"] = 0

        def run_sniff():
            logger.info(f"Starting passive capture on interface '{self.interface}' (filter: '{self.bpf_filter}')")
            try:
                scapy.sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda p: not self._is_running
                )
            except Exception as e:
                logger.error(f"Sniffer terminated with exception: {e}")
                self.stats["capture_errors"] += 1
                self._is_running = False

        self._sniffer_thread = threading.Thread(target=run_sniff, daemon=True)
        self._sniffer_thread.start()

    def stop(self):
        """Signal the sniffer to gracefully stop."""
        self._is_running = False
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=2.0)
        logger.info(f"Stopped passive capture on interface '{self.interface}'. Total packets: {self.stats['packets_captured']}")

    @property
    def is_running(self) -> bool:
        return self._is_running
