"""
Suricata Signature to 13-Class Canonical Taxonomy Mapping Layer
Provides transparent translation between Traditional NIDS signatures and ML Canonical IDs.
"""

from typing import Dict, Any, Optional, Tuple
from utils.taxonomy import CLASS_TO_ID, ID_TO_CLASS, CLASS_NAMES


# Explicit SID-to-Canonical ID mapping for project documented rules
EXPLICIT_SID_MAP: Dict[int, int] = {
    # Class 1: DDoS
    9000010: 1, 9000011: 1, 9000012: 1,
    # Class 2: DoS
    9000020: 2, 9000021: 2, 9000022: 2,
    # Class 3: Botnet
    9000030: 3, 9000031: 3, 9000032: 3,
    # Class 4: Infiltration
    9000040: 4, 9000041: 4, 9000042: 4,
    # Class 5: Brute Force
    9000050: 5, 9000051: 5, 9000052: 5,
    # Class 6: Web Attack
    9000060: 6, 9000061: 6, 9000062: 6,
    # Class 7: DNS Spoofing
    9000070: 7, 9000071: 7,
    # Class 8: IP Spoofing
    9000080: 8, 9000081: 8, 9000082: 8,
    # Class 10: Recon / Port Scan
    9000100: 10, 9000101: 10, 9000102: 10, 9000103: 10,
    # Class 11: MITM
    9000110: 11, 9000111: 11,
    # Class 12: DNS Tunneling
    9000120: 12, 9000121: 12, 9000122: 12,
}

# Documented rule coverage status across our 13 canonical classes
RULE_COVERAGE_STATUS = {
    0: {"name": "Benign", "supported": True, "notes": "Baseline traffic with no triggered alert"},
    1: {"name": "DDoS", "supported": True, "notes": "SYN flood and amplification signatures"},
    2: {"name": "DoS", "supported": True, "notes": "Slowloris, RST flood, and ICMP flood rules"},
    3: {"name": "Botnet", "supported": True, "notes": "Mirai, Mozi, and IRC C2 signatures"},
    4: {"name": "Infiltration", "supported": True, "notes": "Metasploit and reverse shell signatures"},
    5: {"name": "Brute Force", "supported": True, "notes": "SSH, FTP, and HTTP auth threshold rules"},
    6: {"name": "Web Attack", "supported": True, "notes": "SQLi, XSS, and directory traversal signatures"},
    7: {"name": "DNS Spoofing", "supported": True, "notes": "Rogue authoritative response mismatch rules"},
    8: {"name": "IP Spoofing", "supported": True, "notes": "Land attack and bogus header rules"},
    9: {"name": "ARP Spoofing", "supported": False, "notes": "UNSUPPORTED: Suricata operates on L3/L4/L7; Layer-2 ARP is out of scope for standard rule engine"},
    10: {"name": "Recon / Port Scan", "supported": True, "notes": "Xmas, NULL, SYN-FIN, and horizontal sweep rules"},
    11: {"name": "MITM", "supported": True, "notes": "SSLStrip and certificate mismatch rules"},
    12: {"name": "DNS Tunneling", "supported": True, "notes": "Long subdomain and Base64 DNS tunnel signatures"},
}


def map_suricata_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Suricata EVE alert record to the 13-class canonical taxonomy.

    Returns:
        Augmented dictionary with:
        - canonical_id: int (0 to 12) or None if unmapped
        - canonical_class: str
        - mapping_confidence: float
        - mapping_method: 'EXPLICIT_SID' | 'SIGNATURE_KEYWORD' | 'CATEGORY_FALLBACK' | 'UNMAPPED'
    """
    sid = alert.get("sid")
    sig = str(alert.get("signature", "")).lower()
    cat = str(alert.get("category", "")).lower()

    # 1. Exact SID Lookup
    if sid and int(sid) in EXPLICIT_SID_MAP:
        cid = EXPLICIT_SID_MAP[int(sid)]
        return {
            "canonical_id": cid,
            "canonical_class": ID_TO_CLASS[cid],
            "mapping_confidence": 1.0,
            "mapping_method": "EXPLICIT_SID"
        }

    # 2. Contextual Signature Matching
    # DNS Tunneling (Class 12)
    if "dns tunnel" in sig or "iodine" in sig or "dnscat" in sig or "subdomain" in sig:
        return {"canonical_id": 12, "canonical_class": "DNS Tunneling", "mapping_confidence": 0.95, "mapping_method": "SIGNATURE_KEYWORD"}

    # DNS Spoofing (Class 7)
    if "dns spoof" in sig or "poison" in sig or "dns cache" in sig:
        return {"canonical_id": 7, "canonical_class": "DNS Spoofing", "mapping_confidence": 0.90, "mapping_method": "SIGNATURE_KEYWORD"}

    # Web Attack (Class 6)
    if any(k in sig for k in ["sqli", "sql injection", "cross-site", "xss", "traversal", "rce", "web-application-attack"]) or "web" in cat:
        return {"canonical_id": 6, "canonical_class": "Web Attack", "mapping_confidence": 0.90, "mapping_method": "SIGNATURE_KEYWORD"}

    # Brute Force (Class 5)
    if any(k in sig for k in ["brute force", "login attempt", "password spray", "credential stuffing"]):
        return {"canonical_id": 5, "canonical_class": "Brute Force", "mapping_confidence": 0.90, "mapping_method": "SIGNATURE_KEYWORD"}

    # Infiltration (Class 4)
    if any(k in sig for k in ["meterpreter", "reverse shell", "c2 beacon", "backdoor", "inbound shell", "lateral"]):
        return {"canonical_id": 4, "canonical_class": "Infiltration", "mapping_confidence": 0.85, "mapping_method": "SIGNATURE_KEYWORD"}

    # Botnet (Class 3)
    if any(k in sig for k in ["mirai", "mozi", "botnet", "c2", "command and control", "trojan"]):
        return {"canonical_id": 3, "canonical_class": "Botnet", "mapping_confidence": 0.90, "mapping_method": "SIGNATURE_KEYWORD"}

    # DDoS vs DoS (Classes 1 and 2)
    if "ddos" in sig or "amplification" in sig or "distributed" in sig:
        return {"canonical_id": 1, "canonical_class": "DDoS", "mapping_confidence": 0.90, "mapping_method": "SIGNATURE_KEYWORD"}
    if "dos" in sig or "denial of service" in sig or "denial-of-service" in cat or "slowloris" in sig:
        return {"canonical_id": 2, "canonical_class": "DoS", "mapping_confidence": 0.85, "mapping_method": "SIGNATURE_KEYWORD"}

    # Recon / Port Scan (Class 10)
    if any(k in sig for k in ["scan", "recon", "nmap", "sweep", "probe"]) or "recon" in cat:
        return {"canonical_id": 10, "canonical_class": "Recon / Port Scan", "mapping_confidence": 0.90, "mapping_method": "SIGNATURE_KEYWORD"}

    # MITM (Class 11)
    if any(k in sig for k in ["mitm", "man-in-the-middle", "sslstrip", "certificate mismatch", "arp poison"]):
        return {"canonical_id": 11, "canonical_class": "MITM", "mapping_confidence": 0.85, "mapping_method": "SIGNATURE_KEYWORD"}

    # IP Spoofing (Class 8)
    if "land attack" in sig or "spoof" in sig or "sameip" in sig:
        return {"canonical_id": 8, "canonical_class": "IP Spoofing", "mapping_confidence": 0.85, "mapping_method": "SIGNATURE_KEYWORD"}

    # Fallback to Unmapped (do not invent categories)
    return {
        "canonical_id": None,
        "canonical_class": "Unmapped Alert",
        "mapping_confidence": 0.0,
        "mapping_method": "UNMAPPED"
    }
