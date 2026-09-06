"""Central taxonomy configuration for the Smart AI NIDS project."""

TAXONOMY_VERSION = "13-class-v1"

CLASS_NAMES = [
    "Benign",
    "DDoS",
    "DoS",
    "Botnet",
    "Infiltration",
    "Brute Force",
    "Web Attack",
    "DNS Spoofing",
    "IP Spoofing",
    "ARP Spoofing",
    "Recon / Port Scan",
    "MITM",
    "DNS Tunneling",
]

CLASS_TO_ID = {
    "Benign": 0,
    "DDoS": 1,
    "DoS": 2,
    "Botnet": 3,
    "Infiltration": 4,
    "Brute Force": 5,
    "Web Attack": 6,
    "DNS Spoofing": 7,
    "IP Spoofing": 8,
    "ARP Spoofing": 9,
    "Recon / Port Scan": 10,
    "MITM": 11,
    "DNS Tunneling": 12,
}

ID_TO_CLASS = {v: k for k, v in CLASS_TO_ID.items()}
