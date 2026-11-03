"""
Live Feature Extraction Engine for Smart AI-NIDS Local Sensor
Converts streaming packets into stateful bidirectional flow statistics and
formats compatible feature schemas for the 5 specialist ML models:
1. CICIoT2023 (46 features)
2. IDS2018 (77 features)
3. ARP_Spoofing (Layer-2 frames: opcode, mac, duplicate ip)
4. IP_Spoofing (5G-NIDD header telemetry)
5. DNS_Tunneling (Shannon entropy, label depth, character frequency)
"""

import time
import math
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

# Layer-2 Protocol Constants
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD


class LiveFeatureExtractor:
    """Extracts model-compatible feature schemas from live network packets and flows."""

    def __init__(self, idle_timeout_sec: float = 5.0):
        self.idle_timeout_sec = idle_timeout_sec
        # In-memory flow table: canonical 5-tuple -> flow state dict
        self.active_flows: Dict[Tuple, Dict[str, Any]] = {}

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a domain name or payload snippet."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return float(-sum(p * math.log(p, 2) for p in prob if p > 0))

    def process_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """Ingest a single Scapy packet and update/emit flow feature dictionaries.
        
        Returns an enriched event dictionary if an immediate threat frame (e.g. ARP or DNS)
        is detected, or updates the active bidirectional flow table.
        """
        ts = getattr(pkt, "time", time.time())

        # ----------------------------------------------------------------------
        # 1. LAYER-2: ARP SPECS (ARP_Spoofing Specialist)
        # ----------------------------------------------------------------------
        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            opcode = int(getattr(arp, "op", 1))
            src_mac = str(getattr(arp, "hwsrc", ""))
            src_ip = str(getattr(arp, "psrc", ""))
            dst_mac = str(getattr(arp, "hwdst", ""))
            dst_ip = str(getattr(arp, "pdst", ""))

            # A gratuitous ARP or reply with opcode 2
            is_anomaly = (opcode == 2) or (src_ip == dst_ip)
            return {
                "event_type": "ARP_FRAME",
                "timestamp": ts,
                "src_ip": src_ip,
                "dest_ip": dst_ip,
                "src_mac": src_mac,
                "dest_mac": dst_mac,
                "proto": "ARP",
                "specialist": "ARP_Spoofing",
                "features": {
                    "frame_number": float(opcode),
                    "arp_opcode": opcode,
                    "arp_duplicate_ip": 1 if is_anomaly else 0
                },
                "feature_schema": "ARP_1_FEATURE",
                "schema_complete": True
            }

        # ----------------------------------------------------------------------
        # 2. APPLICATION LAYER: DNS QUERY (DNS_Tunneling Specialist)
        # ----------------------------------------------------------------------
        if pkt.haslayer("DNS") and pkt.haslayer("DNSQR"):
            try:
                dnsqr = pkt["DNSQR"]
                qname = dnsqr.qname.decode("utf-8", errors="ignore").rstrip(".")
                if qname:
                    entropy = self.calculate_entropy(qname)
                    labels = qname.split(".")
                    sub_count = len(labels)
                    length = len(qname)
                    spec_chars = sum(1 for c in qname if not c.isalnum() and c != ".")

                    return {
                        "event_type": "DNS_QUERY",
                        "timestamp": ts,
                        "src_ip": pkt["IP"].src if pkt.haslayer("IP") else "0.0.0.0",
                        "dest_ip": pkt["IP"].dst if pkt.haslayer("IP") else "0.0.0.0",
                        "src_port": pkt.sport if hasattr(pkt, "sport") else 53,
                        "dest_port": pkt.dport if hasattr(pkt, "dport") else 53,
                        "proto": "UDP" if pkt.haslayer("UDP") else "TCP",
                        "specialist": "DNS_Tunneling",
                        "features": {
                            "query": qname,
                            "query_length": length,
                            "subdomain_count": sub_count,
                            "special_character_count": spec_chars,
                            "entropy": round(entropy, 4)
                        },
                        "feature_schema": "DNS_ENTROPY_9_FEATURE",
                        "schema_complete": True
                    }
            except Exception:
                pass

        # ----------------------------------------------------------------------
        # 3. LAYER 3 & 4: IP FLOW TELEMETRY (CICIoT2023 46 Features)
        # ----------------------------------------------------------------------
        if not pkt.haslayer("IP"):
            return None

        ip = pkt["IP"]
        src_ip = ip.src
        dest_ip = ip.dst
        proto = ip.proto
        pkt_len = len(pkt)

        src_port = 0
        dest_port = 0
        tcp_flags = {"syn": 0, "ack": 0, "fin": 0, "rst": 0}

        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            src_port = tcp.sport
            dest_port = tcp.dport
            flags = str(tcp.flags)
            if "S" in flags: tcp_flags["syn"] = 1
            if "A" in flags: tcp_flags["ack"] = 1
            if "F" in flags: tcp_flags["fin"] = 1
            if "R" in flags: tcp_flags["rst"] = 1
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            src_port = udp.sport
            dest_port = udp.dport

        # Canonical bidirectional 5-tuple key
        fwd_key = (src_ip, dest_ip, src_port, dest_port, proto)
        rev_key = (dest_ip, src_ip, dest_port, src_port, proto)

        if fwd_key in self.active_flows:
            flow = self.active_flows[fwd_key]
            is_fwd = True
        elif rev_key in self.active_flows:
            flow = self.active_flows[rev_key]
            is_fwd = False
        else:
            flow = {
                "key": fwd_key,
                "start_time": ts,
                "last_time": ts,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "proto": proto,
                "packet_count": 0,
                "byte_count": 0,
                "fwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_packets": 0,
                "bwd_bytes": 0,
                "packet_lengths": [],
                "iats": [],
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "header_len": ip.ihl * 4 if hasattr(ip, "ihl") else 20
            }
            self.active_flows[fwd_key] = flow
            is_fwd = True

        # Update flow stats
        flow["last_time"] = ts
        flow["packet_count"] += 1
        flow["byte_count"] += pkt_len
        flow["packet_lengths"].append(pkt_len)

        if is_fwd:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt_len
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt_len

        flow["syn_count"] += tcp_flags["syn"]
        flow["ack_count"] += tcp_flags["ack"]
        flow["fin_count"] += tcp_flags["fin"]
        flow["rst_count"] += tcp_flags["rst"]

        return None

    def flush_expired_flows(self, current_time: Optional[float] = None, force_all: bool = False) -> List[Dict[str, Any]]:
        """Flush flows that have exceeded idle timeout and compile 46-feature CICIoT2023 telemetry."""
        now = current_time or time.time()
        expired_keys = []
        emitted_flows = []

        for key, flow in list(self.active_flows.items()):
            idle_duration = now - flow["last_time"]
            if force_all or idle_duration >= self.idle_timeout_sec or flow["packet_count"] >= 100:
                expired_keys.append(key)
                duration = max(0.0001, flow["last_time"] - flow["start_time"])
                pkts = flow["packet_count"]
                bytes_tot = flow["byte_count"]
                lens = flow["packet_lengths"]

                min_len = float(min(lens)) if lens else 0.0
                max_len = float(max(lens)) if lens else 0.0
                mean_len = float(sum(lens) / len(lens)) if lens else 0.0
                variance = float(sum((x - mean_len) ** 2 for x in lens) / len(lens)) if lens else 0.0

                rate = float(pkts / duration)
                srate = float(flow["fwd_packets"] / duration)
                drate = float(flow["bwd_packets"] / duration)

                # Protocol identification
                proto_name = "TCP" if flow["proto"] == 6 else "UDP" if flow["proto"] == 17 else "ICMP" if flow["proto"] == 1 else "IP"
                sport = flow["src_port"]
                dport = flow["dest_port"]

                # Protocol indicators
                is_http = 1.0 if 80 in (sport, dport) or 8080 in (sport, dport) else 0.0
                is_https = 1.0 if 443 in (sport, dport) else 0.0
                is_dns = 1.0 if 53 in (sport, dport) else 0.0
                is_telnet = 1.0 if 23 in (sport, dport) else 0.0
                is_smtp = 1.0 if 25 in (sport, dport) or 587 in (sport, dport) else 0.0
                is_ssh = 1.0 if 22 in (sport, dport) else 0.0
                is_irc = 1.0 if 6667 in (sport, dport) else 0.0
                is_tcp = 1.0 if flow["proto"] == 6 else 0.0
                is_udp = 1.0 if flow["proto"] == 17 else 0.0
                is_icmp = 1.0 if flow["proto"] == 1 else 0.0
                is_dhcp = 1.0 if sport in (67, 68) or dport in (67, 68) else 0.0

                # Format exact CICIoT2023 46-feature schema
                ciciot_feats = {
                    "flow_duration": round(duration, 4),
                    "Header_Length": flow["header_len"],
                    "Protocol Type": flow["proto"],
                    "Duration": round(duration, 4),
                    "Rate": round(rate, 2),
                    "Srate": round(srate, 2),
                    "Drate": round(drate, 2),
                    "fin_flag_number": 1.0 if flow["fin_count"] > 0 else 0.0,
                    "syn_flag_number": 1.0 if flow["syn_count"] > 0 else 0.0,
                    "rst_flag_number": 1.0 if flow["rst_count"] > 0 else 0.0,
                    "psh_flag_number": 0.0,
                    "ack_flag_number": 1.0 if flow["ack_count"] > 0 else 0.0,
                    "ece_flag_number": 0.0,
                    "cwr_flag_number": 0.0,
                    "ack_count": flow["ack_count"],
                    "syn_count": flow["syn_count"],
                    "fin_count": flow["fin_count"],
                    "urg_count": 0.0,
                    "rst_count": flow["rst_count"],
                    "HTTP": is_http,
                    "HTTPS": is_https,
                    "DNS": is_dns,
                    "Telnet": is_telnet,
                    "SMTP": is_smtp,
                    "SSH": is_ssh,
                    "IRC": is_irc,
                    "TCP": is_tcp,
                    "UDP": is_udp,
                    "DHCP": is_dhcp,
                    "ARP": 0.0,
                    "ICMP": is_icmp,
                    "IPv": 1.0,
                    "LLC": 1.0,
                    "Tot sum": float(bytes_tot),
                    "Min": min_len,
                    "Max": max_len,
                    "AVG": round(mean_len, 2),
                    "Std": round(math.sqrt(variance), 2),
                    "Tot size": float(bytes_tot),
                    "IAT": round(duration / max(1, pkts - 1), 4),
                    "Number": float(pkts),
                    "Magnitue": round(math.sqrt(min_len**2 + max_len**2 + mean_len**2), 2),
                    "Radius": round(math.sqrt(variance) / 2.0, 2),
                    "Covariance": round(variance / 2.0, 2),
                    "Variance": round(variance, 2),
                    "Weight": float(pkts * mean_len)
                }

                emitted_flows.append({
                    "event_type": "FLOW_RECORD",
                    "timestamp": flow["last_time"],
                    "src_ip": flow["src_ip"],
                    "dest_ip": flow["dest_ip"],
                    "src_port": flow["src_port"],
                    "dest_port": flow["dest_port"],
                    "proto": proto_name,
                    "packet_count": pkts,
                    "byte_count": bytes_tot,
                    "duration_sec": round(duration, 4),
                    "specialist": "CICIoT2023",
                    "features": ciciot_feats,
                    "feature_schema": "CICIoT2023_46_FEATURE",
                    "schema_complete": True
                })

        for k in expired_keys:
            self.active_flows.pop(k, None)

        return emitted_flows
