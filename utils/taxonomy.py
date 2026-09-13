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
NUM_CLASSES = len(CLASS_NAMES)

SPECIALIST_SUB_TAXONOMIES = {
    "IDS2018": [
        "Benign", "DDoS", "DoS", "Botnet", "Infiltration", "Brute Force", "Web Attack"
    ],
    "CICIoT2023": [
        "Benign", "DDoS", "DoS", "Botnet", "Infiltration",
        "Brute Force", "Web Attack", "DNS Spoofing", "Recon / Port Scan", "MITM"
    ],
    "ARP_Spoofing": ["Benign", "ARP Spoofing", "DoS"],
    "IP_Spoofing": ["Benign", "IP Spoofing"],
    "DNS_Tunneling": ["Benign", "DNS Tunneling"],
}

SPECIALIST_LOCAL_TO_CANONICAL = {
    spec_name: {
        idx: CLASS_TO_ID[cls_name]
        for idx, cls_name in enumerate(classes)
    }
    for spec_name, classes in SPECIALIST_SUB_TAXONOMIES.items()
}

# Key feature indicators for automated schema-based routing
SPECIALIST_FEATURE_INDICATORS = {
    "DNS_Tunneling": [
        "query_length", "num_dots", "num_subdomains", "max_label_length",
        "avg_label_length", "digit_count", "alpha_count", "special_character_count", "entropy", "query"
    ],
    "ARP_Spoofing": [
        "arp_opcode", "frame_number", "frame_time_delta", "tcp_flag_fin",
        "tcp_flag_syn", "tcp_flag_rst", "tcp_flag_psh", "tcp_flag_ack"
    ],
    "IP_Spoofing": [
        "Seq", "GTP", "5G", "some_feature"
    ],
    "IDS2018": [
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts",
        "Fwd Pkt Len Max", "Bwd Pkt Len Max", "Flow Byts/s", "Flow Pkts/s"
    ],
    "CICIoT2023": [
        "Rate", "Srate", "Drate", "ack_count", "syn_count", "Header_Length",
        "Duration", "Protocol Type", "flow_duration"
    ]
}

def project_local_to_canonical_probabilities(
    y_proba,
    specialist_name: str = None,
    local_classes: list = None,
    local_id_to_canonical: dict = None,
    num_canonical_classes: int = NUM_CLASSES
):
    """Project local specialist posterior probabilities into the frozen 13-class canonical space.

    Guarantees:
    - Target dimension is always num_canonical_classes (13).
    - Unrepresented classes in the specialist sub-taxonomy strictly receive 0.0.
    - Preserves exact row sums (sum to 1.0 for valid probability distributions).
    - Supports both 1D (single instance) and 2D (batched) array inputs.
    """
    import numpy as np

    if local_id_to_canonical is None:
        if specialist_name and specialist_name in SPECIALIST_LOCAL_TO_CANONICAL:
            local_id_to_canonical = SPECIALIST_LOCAL_TO_CANONICAL[specialist_name]
        elif local_classes:
            local_id_to_canonical = {
                idx: CLASS_TO_ID[c]
                for idx, c in enumerate(local_classes)
                if c in CLASS_TO_ID
            }
        else:
            raise ValueError("Either specialist_name, local_classes, or local_id_to_canonical must be provided.")

    y_proba = np.asarray(y_proba, dtype=np.float32)
    single_sample = False
    if y_proba.ndim == 1:
        single_sample = True
        y_proba = y_proba.reshape(1, -1)

    n_samples, n_local = y_proba.shape
    canonical_proba = np.zeros((n_samples, num_canonical_classes), dtype=np.float32)

    for local_idx, canon_idx in local_id_to_canonical.items():
        if int(local_idx) < n_local and int(canon_idx) < num_canonical_classes:
            canonical_proba[:, int(canon_idx)] = y_proba[:, int(local_idx)]

    if single_sample:
        return canonical_proba[0]
    return canonical_proba

def detect_specialist_from_features(columns: list) -> str:
    """Determine the matching specialist model from an incoming feature column list.

    Returns the specialist key string (e.g. 'IDS2018', 'CICIoT2023', etc.).
    Raises ValueError if no matching schema or ambiguous schema is detected.
    """
    col_set = set(str(c) for c in columns)

    # 1. DNS Tunneling check (distinct DNS query text or statistical properties)
    dns_matches = sum(1 for f in SPECIALIST_FEATURE_INDICATORS["DNS_Tunneling"] if f in col_set)
    if dns_matches >= 2 or "query" in col_set or "query_length" in col_set:
        return "DNS_Tunneling"

    # 2. ARP Spoofing check (layer 2 / frame / ARP opcode features)
    arp_matches = sum(1 for f in SPECIALIST_FEATURE_INDICATORS["ARP_Spoofing"] if f in col_set)
    if "arp_opcode" in col_set or (arp_matches >= 2 and "Tot Fwd Pkts" not in col_set):
        return "ARP_Spoofing"

    # 3. IDS2018 check (enterprise flow features: 'Tot Fwd Pkts', 'Flow Duration' with capitalization)
    ids_matches = sum(1 for f in SPECIALIST_FEATURE_INDICATORS["IDS2018"] if f in col_set)
    if "Tot Fwd Pkts" in col_set or "Tot Bwd Pkts" in col_set or ids_matches >= 2:
        return "IDS2018"

    # 4. CICIoT2023 check (IoT abstracted metrics: 'Rate', 'Srate', 'Drate', 'ack_count', 'flow_duration')
    iot_matches = sum(1 for f in SPECIALIST_FEATURE_INDICATORS["CICIoT2023"] if f in col_set)
    if "Srate" in col_set or "Drate" in col_set or "Rate" in col_set or (iot_matches >= 2 and "Tot Fwd Pkts" not in col_set):
        return "CICIoT2023"

    # 5. 5G / IP Spoofing check
    ip_matches = sum(1 for f in SPECIALIST_FEATURE_INDICATORS["IP_Spoofing"] if f in col_set)
    if ip_matches >= 1:
        return "IP_Spoofing"

    raise ValueError(
        f"Unable to route input: provided features do not match any known specialist schema. "
        f"Available specialists: {list(SPECIALIST_SUB_TAXONOMIES.keys())}"
    )

