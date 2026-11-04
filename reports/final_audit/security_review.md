# Smart AI-NIDS: Application Security & Defense Review

**Date**: November 4, 2026  
**Auditor**: Senior Application Security Engineer & Penetration Tester  
**Scope**: Smart AI-NIDS FastAPI Backend, Sensor Pipeline, and Ingestion Engine  
**Status**: **SECURE — NO HIGH/CRITICAL VULNERABILITIES IDENTIFIED**  

---

## 1. Security Architecture & Threat Modeling

The Smart AI-NIDS application was subjected to a defensive security evaluation across seven key domains:

### 1. File Upload & Binary Magic Number Verification
- **Implementation**: Located in `utils/suricata_runner.py::validate_pcap_file`.
- **Validation**:
  - File existence and non-zero size checks.
  - Binary header validation inspecting standard PCAP magics (`0xa1b2c3d4`, `0xd4c3b2a1`), nanosecond magics (`0xa1b23c4d`, `0x4d3cb2a1`), and PCAPNG Section Header Block (`0x0a0d0d0a`).
  - Corrupted, empty, or non-capture binaries are rejected before passing to Suricata or Scapy.

### 2. Command Injection & Subprocess Execution
- **Implementation**: `subprocess.run` invocations in `suricata_runner.py` and `suricata_live_runner.py`.
- **Controls**:
  - Commands are passed as strict argument lists (`cmd = [suricata_bin, "-r", path, ...]`).
  - `shell=True` is **never** used.
  - Strict execution timeouts (`timeout=60` in offline runner, `timeout=5` in version probe) prevent hanging processes and resource exhaustion denial-of-service.

### 3. Path Traversal & Directory Containment
- **Implementation**: Logging and temporary file operations use `tempfile.mkdtemp(prefix="suricata_run_")`.
- **Controls**:
  - File paths are normalized with `os.path.abspath`.
  - User-provided upload names are not used directly to construct filesystem paths.

### 4. Input Validation & Strict Typing
- **Implementation**: Pydantic v2 data models in `backend/schemas.py`.
- **Controls**:
  - Request bodies are typed and validated.
  - Invalid types, empty dictionaries, and malformed JSON produce clean HTTP 400 Bad Request responses with structured error payloads rather than unhandled Python 500 tracebacks.

### 5. Sensor Authentication & Stream Protection
- **Implementation**: Header verification in `backend/main.py::verify_sensor_auth`.
- **Controls**:
  - Requires valid `X-Sensor-Key` or JSON body `api_key`.
  - Unauthorized sensor attempts receive HTTP 401 Unauthorized.
  - Ingestion buffer is strictly bounded to the 500 most recent events to prevent memory exhaustion.

### 6. MAC Spoofing Taxonomy Guard
- **Implementation**: Preprocessor and UnifiedNIDS validation.
- **Controls**:
  - Rejects incoming traffic containing MAC spoofing indicators with descriptive error messages.
  - Prevents poisoning of canonical inference predictions.

### 7. Cross-Origin Resource Sharing (CORS)
- **Implementation**: `CORSMiddleware` in `backend/main.py`.
- **Controls**:
  - Universal origins permitted by default to prevent cross-origin blocking when deployed across cloud domains, while API credentials remain restricted (`allow_credentials=False` for wildcard origins).
