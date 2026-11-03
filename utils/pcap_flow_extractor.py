"""
Network Flow Telemetry Extractor from Raw PCAP / PCAPNG for Smart AI-NIDS
Extracts bidirectional flow statistical vectors compatible with UnifiedNIDS specialist pipelines.
Uses memory-safe streaming PcapReader with zero memory bloat.
"""

import os
import math
import numpy as np
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PcapFlowExtractor:
    """Streams PCAP packets and aggregates them into statistical network flows for AI-NIDS."""

    def __init__(self, pcap_path: str, max_packets: int = 25000):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP flow extraction. Install via 'pip install scapy'.")
        self.pcap_path = pcap_path
        self.max_packets = max_packets

    def extract_flows(self) -> List[Dict[str, Any]]:
        """Stream packets from PCAP and return list of flow feature dictionaries."""
        flows: Dict[Tuple, Dict[str, Any]] = defaultdict(lambda: {
            "packets": [],
            "timestamps": [],
            "sizes": [],
            "directions": [], # 'fwd' or 'bwd'
            "flags": [],
            "dns_queries": [],
            "arp_opcodes": [],
            "src_ip": None,
            "dest_ip": None,
            "src_port": 0,
            "dest_port": 0,
            "proto": 0
        })

        packet_count = 0
        with PcapReader(self.pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                packet_count += 1
                if packet_count > self.max_packets:
                    break

                ts = float(pkt.time)
                size = len(pkt)

                # 1. ARP Handling (Layer 2)
                if ARP in pkt:
                    arp = pkt[ARP]
                    key = ("ARP", arp.psrc, arp.pdst, 0, 0)
                    f = flows[key]
                    f["timestamps"].append(ts)
                    f["sizes"].append(size)
                    f["arp_opcodes"].append(int(arp.op))
                    f["src_ip"] = arp.psrc
                    f["dest_ip"] = arp.pdst
                    f["proto"] = 2054
                    continue

                # 2. IP Handling (Layer 3 / 4)
                if IP in pkt:
                    ip = pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    proto = ip.proto
                elif IPv6 in pkt:
                    ip = pkt[IPv6]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    proto = ip.nh
                else:
                    continue

                src_port = 0
                dst_port = 0
                tcp_flags = 0

                if TCP in pkt:
                    tcp = pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_flags = int(tcp.flags)
                elif UDP in pkt:
                    udp = pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport

                # DNS Inspection
                dns_query = None
                if DNS in pkt and pkt[DNS].qd and DNSQR in pkt:
                    try:
                        q = pkt[DNSQR].qname
                        if isinstance(q, bytes):
                            dns_query = q.decode("utf-8", errors="ignore").rstrip(".")
                        else:
                            dns_query = str(q).rstrip(".")
                    except Exception:
                        pass

                # Canonical Bidirectional Flow Key
                # Normalize ordering so forward and backward packets belong to same flow
                if (src_ip, src_port) <= (dst_ip, dst_port):
                    flow_key = (proto, src_ip, src_port, dst_ip, dst_port)
                    direction = "fwd"
                else:
                    flow_key = (proto, dst_ip, dst_port, src_ip, src_port)
                    direction = "bwd"

                f = flows[flow_key]
                if f["src_ip"] is None:
                    f["src_ip"] = src_ip
                    f["dest_ip"] = dst_ip
                    f["src_port"] = src_port
                    f["dest_port"] = dst_port
                    f["proto"] = proto

                f["timestamps"].append(ts)
                f["sizes"].append(size)
                f["directions"].append(direction)
                f["flags"].append(tcp_flags)
                if dns_query:
                    f["dns_queries"].append(dns_query)

        # Reconstruct normalized statistical features matching CICIoT2023 / UnifiedNIDS
        extracted_records = []
        for key, f in flows.items():
            pts = f["timestamps"]
            sizes = f["sizes"]
            flags = f["flags"]
            n_pkts = len(pts)
            if n_pkts == 0:
                continue

            duration = max(0.0, pts[-1] - pts[0])
            tot_bytes = sum(sizes)
            rate = tot_bytes / duration if duration > 0 else float(tot_bytes)

            fwd_count = sum(1 for d in f["directions"] if d == "fwd")
            bwd_count = n_pkts - fwd_count
            srate = fwd_count / duration if duration > 0 else float(fwd_count)
            drate = bwd_count / duration if duration > 0 else float(bwd_count)

            # IAT
            if n_pkts > 1:
                iats = [pts[i] - pts[i - 1] for i in range(1, n_pkts)]
                avg_iat = float(np.mean(iats))
            else:
                avg_iat = 0.0

            # TCP Flags breakdown
            fin_count = sum(1 for fl in flags if fl & 0x01)
            syn_count = sum(1 for fl in flags if fl & 0x02)
            rst_count = sum(1 for fl in flags if fl & 0x04)
            psh_count = sum(1 for fl in flags if fl & 0x08)
            ack_count = sum(1 for fl in flags if fl & 0x10)
            urg_count = sum(1 for fl in flags if fl & 0x20)
            ece_count = sum(1 for fl in flags if fl & 0x40)
            cwr_count = sum(1 for fl in flags if fl & 0x80)

            # Protocol Indicators
            is_tcp = 1.0 if f["proto"] == 6 else 0.0
            is_udp = 1.0 if f["proto"] == 17 else 0.0
            is_icmp = 1.0 if f["proto"] == 1 else 0.0
            is_http = 1.0 if (f["src_port"] == 80 or f["dest_port"] == 80) else 0.0
            is_https = 1.0 if (f["src_port"] == 443 or f["dest_port"] == 443) else 0.0
            is_dns = 1.0 if (f["src_port"] == 53 or f["dest_port"] == 53) else 0.0
            is_ssh = 1.0 if (f["src_port"] == 22 or f["dest_port"] == 22) else 0.0
            is_telnet = 1.0 if (f["src_port"] == 23 or f["dest_port"] == 23) else 0.0
            is_smtp = 1.0 if (f["src_port"] == 25 or f["dest_port"] == 25) else 0.0
            is_arp = 1.0 if key[0] == "ARP" else 0.0

            size_min = float(min(sizes))
            size_max = float(max(sizes))
            size_avg = float(np.mean(sizes))
            size_std = float(np.std(sizes)) if n_pkts > 1 else 0.0
            size_var = float(np.var(sizes)) if n_pkts > 1 else 0.0
            magnitude = math.sqrt(size_avg ** 2 + avg_iat ** 2)

            rec = {
                # Standard 46-feature CICIoT2023 schema
                "flow_duration": duration,
                "Header_Length": 54.0,
                "Protocol Type": float(f["proto"]),
                "Duration": duration,
                "Rate": rate,
                "Srate": srate,
                "Drate": drate,
                "fin_flag_number": 1.0 if fin_count > 0 else 0.0,
                "syn_flag_number": 1.0 if syn_count > 0 else 0.0,
                "rst_flag_number": 1.0 if rst_count > 0 else 0.0,
                "psh_flag_number": 1.0 if psh_count > 0 else 0.0,
                "ack_flag_number": 1.0 if ack_count > 0 else 0.0,
                "ece_flag_number": 1.0 if ece_count > 0 else 0.0,
                "cwr_flag_number": 1.0 if cwr_count > 0 else 0.0,
                "ack_count": float(ack_count),
                "syn_count": float(syn_count),
                "fin_count": float(fin_count),
                "urg_count": float(urg_count),
                "rst_count": float(rst_count),
                "HTTP": is_http,
                "HTTPS": is_https,
                "DNS": is_dns,
                "Telnet": is_telnet,
                "SMTP": is_smtp,
                "SSH": is_ssh,
                "IRC": 0.0,
                "TCP": is_tcp,
                "UDP": is_udp,
                "DHCP": 0.0,
                "ARP": is_arp,
                "ICMP": is_icmp,
                "IPv": 1.0,
                "LLC": 1.0,
                "Tot sum": float(tot_bytes),
                "Min": size_min,
                "Max": size_max,
                "AVG": size_avg,
                "Std": size_std,
                "Tot size": size_avg,
                "IAT": avg_iat,
                "Number": float(n_pkts),
                "Magnitue": magnitude,
                "Radius": 0.0,
                "Covariance": 0.0,
                "Variance": size_var,
                "Weight": float(tot_bytes) / 1000.0,
                # Context metadata
                "_meta": {
                    "src_ip": f["src_ip"],
                    "dest_ip": f["dest_ip"],
                    "src_port": f["src_port"],
                    "dest_port": f["dest_port"],
                    "proto": f["proto"],
                    "packet_count": n_pkts,
                    "byte_count": tot_bytes,
                    "start_time": pts[0],
                    "end_time": pts[-1]
                }
            }

            # If DNS query found, include for specialized DNS tunneling model
            if f["dns_queries"]:
                rec["query"] = f["dns_queries"][0]

            # If ARP flow, include opcode
            if f["arp_opcodes"]:
                rec["arp_opcode"] = float(f["arp_opcodes"][0])
                rec["frame_number"] = float(n_pkts)

            extracted_records.append(rec)

        return extracted_records
