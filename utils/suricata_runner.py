"""
Suricata Process Execution Engine for Smart AI-NIDS
Manages offline PCAP / PCAPNG inspection, timeout containment, and output capture.
"""

import os
import shutil
import tempfile
import subprocess
import time
from typing import Dict, Any, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SURICATA_BIN_CANDIDATES = [
    "/opt/homebrew/bin/suricata",
    "/usr/local/bin/suricata",
    "/usr/bin/suricata",
    "suricata"
]
DEFAULT_CONFIG_PATH = os.path.join(REPO_ROOT, "suricata", "suricata.yaml")


def find_suricata_binary() -> Optional[str]:
    """Locate the installed Suricata executable binary."""
    for cand in SURICATA_BIN_CANDIDATES:
        found = shutil.which(cand)
        if found:
            return found
    return None


def get_suricata_version() -> Dict[str, Any]:
    """Inspect and return Suricata engine installation status and version."""
    binary = find_suricata_binary()
    if not binary:
        return {
            "available": False,
            "version": None,
            "binary_path": None,
            "error": "Suricata binary not found in system PATH."
        }
    try:
        proc = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=5)
        version_str = proc.stdout.strip() or proc.stderr.strip()
        return {
            "available": True,
            "version": version_str,
            "binary_path": binary,
            "error": None
        }
    except Exception as e:
        return {
            "available": False,
            "version": None,
            "binary_path": binary,
            "error": str(e)
        }


def validate_pcap_file(pcap_path: str) -> None:
    """Validate PCAP / PCAPNG file existence and binary magic headers."""
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    
    if os.path.getsize(pcap_path) == 0:
        raise ValueError(f"PCAP file is empty (0 bytes): {pcap_path}")

    # Check common PCAP magic numbers:
    # 0xa1b2c3d4 (standard microsecond pcap)
    # 0xa1b23c4d (nanosecond pcap)
    # 0x0a0d0d0a (pcapng section header block)
    with open(pcap_path, "rb") as f:
        magic = f.read(4)
        valid_magics = [
            b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # Standard pcap
            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap
            b"\x0a\x0d\x0d\x0a"                       # PCAPNG
        ]
        if magic not in valid_magics:
            raise ValueError(f"File {pcap_path} is not a valid PCAP or PCAPNG binary file (magic: {magic.hex()}).")


def run_suricata_pcap(
    pcap_path: str,
    config_path: str = DEFAULT_CONFIG_PATH,
    log_dir: Optional[str] = None,
    timeout_seconds: int = 60
) -> Dict[str, Any]:
    """Execute offline Suricata inspection on a validated PCAP file.

    Parameters:
        pcap_path: Path to target .pcap or .pcapng file
        config_path: Path to suricata.yaml configuration
        log_dir: Directory where eve.json and fast.log will be placed (temporary if None)
        timeout_seconds: Hard execution timeout in seconds

    Returns:
        Structured dictionary containing execution status, timings, and log paths.
    """
    suricata_bin = find_suricata_binary()
    if not suricata_bin:
        raise RuntimeError("Suricata binary not installed. Run 'brew install suricata' or use local sensor.")

    validate_pcap_file(pcap_path)
    os.makedirs("/tmp/suricata-logs", exist_ok=True)

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Suricata configuration not found at: {config_path}")

    is_temporary_dir = False
    if log_dir is None:
        log_dir = tempfile.mkdtemp(prefix="suricata_run_")
        is_temporary_dir = True
    else:
        os.makedirs(log_dir, exist_ok=True)

    cmd = [
        suricata_bin,
        "-r", os.path.abspath(pcap_path),
        "-c", os.path.abspath(config_path),
        "-l", os.path.abspath(log_dir)
    ]

    start_time = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False
        )
        duration = time.perf_counter() - start_time
        exit_code = proc.returncode

        eve_path = os.path.join(log_dir, "eve.json")
        fast_path = os.path.join(log_dir, "fast.log")

        return {
            "status": "SUCCESS" if exit_code == 0 else "ERROR",
            "exit_code": exit_code,
            "duration_seconds": round(duration, 4),
            "pcap_path": os.path.abspath(pcap_path),
            "pcap_size_bytes": os.path.getsize(pcap_path),
            "log_dir": os.path.abspath(log_dir),
            "eve_path": eve_path if os.path.exists(eve_path) else None,
            "fast_path": fast_path if os.path.exists(fast_path) else None,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "is_temporary_dir": is_temporary_dir
        }
    except subprocess.TimeoutExpired as e:
        duration = time.perf_counter() - start_time
        return {
            "status": "TIMEOUT",
            "exit_code": -1,
            "duration_seconds": round(duration, 4),
            "pcap_path": os.path.abspath(pcap_path),
            "pcap_size_bytes": os.path.getsize(pcap_path),
            "log_dir": os.path.abspath(log_dir),
            "eve_path": None,
            "fast_path": None,
            "stdout": e.stdout or "",
            "stderr": e.stderr or "Execution timed out.",
            "is_temporary_dir": is_temporary_dir
        }
