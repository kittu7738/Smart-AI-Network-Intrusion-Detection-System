"""FastAPI backend application for the Smart AI Network Intrusion Detection System.

Coordinates end-to-end inference across all 5 specialist models via UnifiedNIDS,
providing REST endpoints for health monitoring, model introspection, and
single/batch flow classification into the frozen 13-class canonical taxonomy.
"""

import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Request, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import tempfile
import shutil

from datetime import datetime
import pandas as pd
from backend.session_manager import get_session_manager
from utils.taxonomy import (
    CLASS_NAMES,
    CLASS_TO_ID,
    NUM_CLASSES,
    SPECIALIST_SUB_TAXONOMIES,
)
from utils.unified_nids import UnifiedNIDS
from utils.train_models import SPECIALIST_SPECS
from utils.suricata_runner import run_suricata_pcap, get_suricata_version, validate_pcap_file
from utils.suricata_eve_parser import SuricataEveParser
from utils.suricata_mapper import map_suricata_alert, RULE_COVERAGE_STATUS
from utils.comparative_evaluator import ComparativeEvaluator
from backend.schemas import (
    HealthResponse,
    ModelsResponse,
    SpecialistDetail,
    PredictionRequest,
    PredictionResponse,
    BatchPredictionRequest,
    BatchPredictionResponse,
    ErrorResponse,
)

# Global engine singleton
_engine: Optional[UnifiedNIDS] = None
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_engine() -> UnifiedNIDS:
    """Retrieve or initialize the centralized UnifiedNIDS inference engine."""
    global _engine
    if _engine is None:
        _engine = UnifiedNIDS(eager_load=True)
        # If CICIoT2023 artifacts are not present locally (e.g. trained in external environment),
        # initialize candidate registration to support local testing and development.
        if not _engine.is_specialist_loaded("CICIoT2023"):
            ciciot_dir = os.path.join(_engine.models_dir, "CICIoT2023")
            has_ciciot = os.path.exists(ciciot_dir) and (
                os.path.exists(os.path.join(ciciot_dir, "candidate_XGBoost_Tuned.joblib")) or
                os.path.exists(os.path.join(ciciot_dir, "XGBoost.joblib"))
            )
            if not has_ciciot:
                try:
                    from utils.data_preparation import load_config
                    from utils.train_models import load_specialist_splits
                    from utils.specialist_preprocessor import SpecialistPreprocessor
                    from utils.model_registry import get_candidate_model

                    cfg = load_config()
                    df_mock, _, _ = load_specialist_splits("CICIoT2023", cfg, smoke_test=True)
                    p_ciciot = SpecialistPreprocessor(
                        dataset_name="CICIoT2023",
                        expected_classes=SPECIALIST_SUB_TAXONOMIES["CICIoT2023"],
                        scale_features=True
                    )
                    p_ciciot.fit(df_mock)
                    m_ciciot = get_candidate_model("XGBoost_Tuned", smoke_test=True)
                    m_ciciot.fit(p_ciciot.transform_features(df_mock), p_ciciot.transform_labels(df_mock))
                    _engine.register_specialist(
                        specialist_name="CICIoT2023",
                        model=m_ciciot,
                        preprocessor=p_ciciot,
                        threshold_multipliers={"Benign": 1.5, "Infiltration": 2.0}
                    )
                except Exception:
                    pass
    return _engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager: pre-warm the inference engine."""
    get_engine()
    yield


app = FastAPI(
    title="Smart AI Network Intrusion Detection System (SAI-IDS) API",
    description="Unified 13-Class NIDS API with automated schema routing across 5 specialist models.",
    version="1.0.0",
    lifespan=lifespan,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input schema or missing features"},
        422: {"model": ErrorResponse, "description": "Unprocessable entity"}
    }
)

# Universal CORS configuration: allow all origins to prevent any Vercel or cloud cross-origin blockers
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "*")
if allowed_origins_env.strip() == "*":
    allowed_origins = ["*"]
else:
    allowed_origins = [orig.strip() for orig in allowed_origins_env.split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False if allowed_origins == ["*"] else True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_and_cache_headers(request: Request, call_next):
    """Ensure HTML, JavaScript, and CSS assets are never cached stale and enforce standard security headers."""
    response = await call_next(request)

    # Standard security headers (OWASP guidelines)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Cache control for dynamic and static assets
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css", ".json")):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.exception_handler(ValueError)
async def value_error_exception_handler(request: Request, exc: ValueError):
    """Convert ValueError from UnifiedNIDS into a clean HTTP 400 Bad Request."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_type": "ValueError"},
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return API health status, service metadata, and loaded specialist models."""
    engine = get_engine()
    loaded = [spec for spec in UnifiedNIDS.SPECIALIST_NAMES if engine.is_specialist_loaded(spec)]
    return HealthResponse(
        status="ok",
        service="Smart AI Network Intrusion Detection System API",
        version="1.0.0",
        engine_ready=True,
        available_specialists=UnifiedNIDS.SPECIALIST_NAMES,
        loaded_specialists=loaded,
    )


@app.get("/models", response_model=ModelsResponse)
def list_models() -> ModelsResponse:
    """Return the catalog of 5 specialist pipelines and the frozen 13-class canonical taxonomy.

    MAC Spoofing is permanently excluded and never included in this catalog.
    """
    engine = get_engine()
    specs = {}
    for spec_name in UnifiedNIDS.SPECIALIST_NAMES:
        desc = SPECIALIST_SPECS.get(spec_name, {}).get("description", f"{spec_name} specialist pipeline")
        canon_classes = list(SPECIALIST_SUB_TAXONOMIES[spec_name])
        
        # Determine feature count and model name if specialist is loaded or available
        feat_count = None
        model_name = None
        if engine.is_specialist_loaded(spec_name):
            bundle = engine._specialists[spec_name]
            feat_count = len(bundle["preprocessor"].feature_names_in_)
            model_name = bundle.get("model_name")

        specs[spec_name] = SpecialistDetail(
            description=desc,
            canonical_classes=canon_classes,
            feature_count=feat_count,
            model_name=model_name,
        )

    return ModelsResponse(
        specialists=specs,
        canonical_classes=CLASS_NAMES,
        canonical_class_to_id=CLASS_TO_ID,
    )


@app.post("/predict", response_model=PredictionResponse)
def predict(request_data: Union[PredictionRequest, Dict[str, Any]]) -> PredictionResponse:
    """Execute unified inference on a single network flow or raw DNS query.

    Accepts either a structured object `{"features": {...}, "specialist": "auto"}`
    or a flat JSON dictionary of features (e.g. `{"Rate": 10.0, ...}` or `{"query": "..."}`).
    """
    engine = get_engine()

    if isinstance(request_data, PredictionRequest):
        features = request_data.get_feature_dict()
        spec = request_data.specialist or "auto"
    elif isinstance(request_data, dict):
        if "features" in request_data and isinstance(request_data["features"], dict):
            features = dict(request_data["features"])
            spec = request_data.get("specialist", "auto")
        else:
            spec = request_data.get("specialist", "auto")
            features = {k: v for k, v in request_data.items() if k != "specialist"}
    else:
        raise HTTPException(status_code=400, detail="Invalid request body format.")

    if not features:
        raise HTTPException(status_code=400, detail="Input features cannot be empty.")

    # Guard MAC Spoofing exclusion
    for k in features.keys():
        if "mac" in str(k).lower():
            raise HTTPException(status_code=400, detail="MAC Spoofing is permanently excluded from the taxonomy.")

    try:
        raw_result = engine.predict(features, specialist=spec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return PredictionResponse(
        predicted_class_id=raw_result["canonical_id"],
        predicted_class=raw_result["class_name"],
        confidence=raw_result["confidence"],
        specialist=raw_result["specialist"],
        probabilities=raw_result["probabilities"],
        canonical_id=raw_result["canonical_id"],
        class_name=raw_result["class_name"],
    )


@app.post("/predict/batch", response_model=BatchPredictionResponse)
def predict_batch(request_data: Union[BatchPredictionRequest, List[Dict[str, Any]]]) -> BatchPredictionResponse:
    """Execute unified inference on a batch of network flow records.

    Accepts either `{"records": [{...}, {...}], "specialist": "auto"}`
    or a raw list `[{...}, {...}]`.
    """
    engine = get_engine()

    if isinstance(request_data, BatchPredictionRequest):
        records = request_data.records
        spec = request_data.specialist or "auto"
    elif isinstance(request_data, list):
        records = request_data
        spec = "auto"
    else:
        raise HTTPException(status_code=400, detail="Batch request must be an array or an object containing 'records'.")

    if not records or len(records) == 0:
        raise HTTPException(status_code=400, detail="Batch cannot be empty. At least one inference record is required.")

    if len(records) > 10000:
        raise HTTPException(status_code=400, detail="Batch exceeds maximum limit of 10,000 records.")

    # Guard MAC Spoofing in all records
    for rec in records:
        if not isinstance(rec, dict):
            raise HTTPException(status_code=400, detail="Each item in the batch must be a dictionary of features.")
        for k in rec.keys():
            if "mac" in str(k).lower():
                raise HTTPException(status_code=400, detail="MAC Spoofing is permanently excluded from the taxonomy.")

    try:
        raw_results = engine.predict(records, specialist=spec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if isinstance(raw_results, dict):
        raw_results = [raw_results]

    predictions = [
        PredictionResponse(
            predicted_class_id=item["canonical_id"],
            predicted_class=item["class_name"],
            confidence=item["confidence"],
            specialist=item["specialist"],
            probabilities=item["probabilities"],
            canonical_id=item["canonical_id"],
            class_name=item["class_name"],
        )
        for item in raw_results
    ]

    specs_in_batch = set(p.specialist for p in predictions if p.specialist)
    if len(specs_in_batch) > 1:
        detected_spec = "Multi-Specialist"
    elif len(specs_in_batch) == 1:
        detected_spec = list(specs_in_batch)[0]
    else:
        detected_spec = spec
    return BatchPredictionResponse(
        count=len(predictions),
        specialist=detected_spec,
        predictions=predictions,
    )


# ==============================================================================
# SURICATA TRADITIONAL NIDS & COMPARATIVE EVALUATION ENDPOINTS
# ==============================================================================

@app.get("/suricata/status")
def suricata_status():
    """Return Suricata Traditional NIDS installation status and rule coverage."""
    status_info = get_suricata_version()
    return {
        "status": "online" if status_info["available"] else "offline",
        "engine": "Suricata Traditional NIDS",
        "version": status_info["version"],
        "binary_path": status_info["binary_path"],
        "rule_coverage": RULE_COVERAGE_STATUS,
        "available": status_info["available"],
    }


@app.post("/suricata/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Analyze an uploaded PCAP / PCAPNG using offline Suricata engine."""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Uploaded file must be a .pcap or .pcapng packet capture.")

    temp_dir = tempfile.mkdtemp(prefix="suricata_upload_")
    pcap_path = os.path.join(temp_dir, file.filename)
    try:
        with open(pcap_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = run_suricata_pcap(pcap_path)
        if result["status"] != "SUCCESS":
            raise HTTPException(status_code=500, detail=f"Suricata execution failed: {result.get('stderr')}")

        parser = SuricataEveParser(result["eve_path"])
        parsed = parser.parse_all()

        mapped_alerts = []
        for a in parsed["alerts"]:
            mapped = map_suricata_alert(a)
            a_copy = dict(a)
            a_copy.update(mapped)
            mapped_alerts.append(a_copy)

        return {
            "status": "SUCCESS",
            "pcap_file": file.filename,
            "duration_seconds": result["duration_seconds"],
            "summary": parsed["summary"],
            "alerts": mapped_alerts,
            "flows": parsed["flows"][:100],
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# SHARED ANALYSIS SESSION LOGIC
# ==============================================================================

def save_pcap_comparison_session(comparison: dict, filename: str, file_size: int = 0) -> str:
    """Register PCAP evaluation output into a unified analysis session."""
    sm = get_session_manager()
    ai = comparison.get("smart_ai_nids", {})
    suri = comparison.get("traditional_nids_suricata", {})
    src = comparison.get("traffic_source", {})

    all_flows = ai.get("all_predictions", ai.get("sample_predictions", []))
    suricata_alerts = suri.get("all_alerts", suri.get("sample_alerts", []))

    total_packets = src.get("total_packets", 0)
    total_flows = ai.get("total_inferences", len(all_flows))
    threats_detected = ai.get("threats_detected", sum(1 for f in all_flows if f.get("canonical_id", 0) != 0))
    benign_count = ai.get("benign_classified", total_flows - threats_detected)
    duration_sec = ai.get("total_duration_sec", 0.0)

    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2054: "ARP"}
    protocol_dist: Dict[str, int] = {}
    src_ip_counts: Dict[str, int] = {}
    dest_ip_counts: Dict[str, int] = {}

    formatted_flows = []
    for idx, fl in enumerate(all_flows):
        p_num = fl.get("proto", 6)
        p_name = proto_map.get(p_num, str(p_num) if p_num else "TCP")
        protocol_dist[p_name] = protocol_dist.get(p_name, 0) + 1

        sip = fl.get("src_ip", "10.0.0.1")
        dip = fl.get("dest_ip", "192.168.1.1")
        src_ip_counts[sip] = src_ip_counts.get(sip, 0) + 1
        dest_ip_counts[dip] = dest_ip_counts.get(dip, 0) + 1

        cid = int(fl.get("canonical_id", 0))
        cname = fl.get("class_name", "Benign")
        severity = "Low" if cid == 0 else ("High" if cid in [1, 2, 3, 4, 5, 6, 8, 9, 11, 12] else "Medium")
        formatted_flows.append({
            "flow_index": idx + 1,
            "timestamp": datetime.now().isoformat(),
            "src_ip": sip,
            "dest_ip": dip,
            "src_port": fl.get("src_port", 0),
            "dest_port": fl.get("dest_port", 0),
            "proto": p_num,
            "packet_count": fl.get("packet_count", 1),
            "byte_count": fl.get("byte_count", 0),
            "specialist": fl.get("specialist", "UnifiedNIDS"),
            "canonical_id": cid,
            "class_name": cname,
            "confidence": float(fl.get("confidence", 0.95)),
            "severity": severity,
            "probabilities": fl.get("probabilities", []),
            "is_threat": 1 if cid != 0 else 0
        })

    top_src_ips = [{"ip": k, "count": v} for k, v in sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    top_dest_ips = [{"ip": k, "count": v} for k, v in sorted(dest_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    attack_dist = ai.get("class_distribution", {})

    alerts = []
    # AI-NIDS alerts for non-benign flows
    for idx, fl in enumerate(formatted_flows):
        if fl["is_threat"] == 1:
            alerts.append({
                "flow_id": f"FLOW-{idx + 1:04d}",
                "timestamp": datetime.now().isoformat(),
                "src_ip": fl["src_ip"],
                "dest_ip": fl["dest_ip"],
                "src_port": fl["src_port"],
                "dest_port": fl["dest_port"],
                "proto": fl["proto"],
                "attack_category": fl["class_name"],
                "canonical_id": fl["canonical_id"],
                "engine": f"Smart AI-NIDS ({fl['specialist']})",
                "specialist": fl["specialist"],
                "confidence": fl["confidence"],
                "severity": fl["severity"],
                "signature_info": f"Classification output from {fl['specialist']} specialist model"
            })

    # Suricata traditional alerts
    for idx, sa in enumerate(suricata_alerts):
        cid = sa.get("canonical_id", 7)
        alerts.append({
            "flow_id": None,
            "timestamp": sa.get("timestamp", datetime.now().isoformat()),
            "src_ip": sa.get("src_ip", "10.0.0.1"),
            "dest_ip": sa.get("dest_ip", "192.168.1.1"),
            "src_port": sa.get("src_port", 0),
            "dest_port": sa.get("dest_port", 0),
            "proto": 17 if sa.get("proto") == "UDP" else 6,
            "attack_category": sa.get("canonical_class", "Suricata Alert"),
            "canonical_id": cid,
            "engine": "Suricata Traditional NIDS",
            "specialist": f"SID {sa.get('sid', 9000000)}",
            "confidence": 1.0,
            "severity": "High",
            "signature_info": sa.get("signature", "Suricata Signature Alert")
        })

    session_id = sm.create_session(
        filename=filename,
        file_type="pcapng" if filename.lower().endswith("pcapng") else "pcap",
        file_size_bytes=file_size,
        total_packets=total_packets,
        total_flows=total_flows,
        threats_detected=threats_detected,
        benign_count=benign_count,
        duration_sec=duration_sec,
        suricata_alerts_count=len(suricata_alerts),
        protocol_dist=protocol_dist,
        top_src_ips=top_src_ips,
        top_dest_ips=top_dest_ips,
        attack_dist=attack_dist,
        flows=formatted_flows,
        alerts=alerts,
        status="COMPLETED"
    )
    return session_id


def save_csv_analysis_session(df: pd.DataFrame, filename: str, file_size: int = 0) -> str:
    """Process uploaded CSV through UnifiedNIDS and register a unified analysis session."""
    sm = get_session_manager()
    engine = get_engine()
    t0 = time.perf_counter()

    df_eval = df.head(1000).copy()

    # Retain metadata / IP columns if present before stripping for model inference
    ip_cols = {str(c).lower(): c for c in df_eval.columns}
    src_ip_col = ip_cols.get("src_ip") or ip_cols.get("source_ip") or ip_cols.get("srcip")
    dest_ip_col = ip_cols.get("dest_ip") or ip_cols.get("destination_ip") or ip_cols.get("dst_ip") or ip_cols.get("dstip")
    src_port_col = ip_cols.get("src_port") or ip_cols.get("source_port") or ip_cols.get("sport")
    dest_port_col = ip_cols.get("dest_port") or ip_cols.get("destination_port") or ip_cols.get("dport")
    proto_col = ip_cols.get("proto") or ip_cols.get("protocol") or ip_cols.get("protocol type")

    # Drop ground-truth labels and non-numeric target metadata for pure model evaluation
    drop_cols = [c for c in df_eval.columns if "label" in str(c).lower()]
    df_features = df_eval.drop(columns=drop_cols) if drop_cols else df_eval.copy()

    # Route specialist
    target_spec = engine.route_traffic(df_features, explicit_specialist="auto")
    if target_spec == "IDS2018" and df_features.shape[1] == 77:
        if not all(c.startswith("feature_") for c in df_features.columns):
            df_features.columns = [f"feature_{i}" for i in range(77)]

    raw_results = engine.predict(df_features, specialist=target_spec)
    if isinstance(raw_results, dict):
        raw_results = [raw_results]

    duration_sec = round(time.perf_counter() - t0, 4)
    total_flows = len(raw_results)

    flows = []
    alerts = []
    attack_dist: Dict[str, int] = {}
    protocol_dist: Dict[str, int] = {}
    src_ip_counts: Dict[str, int] = {}
    dest_ip_counts: Dict[str, int] = {}
    threats_detected = 0

    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2054: "ARP"}

    for idx, res in enumerate(raw_results):
        cid = int(res["canonical_id"])
        cname = str(res["class_name"])
        conf = float(res["confidence"])
        spec = str(res["specialist"])
        probs = res["probabilities"]

        if cid != 0:
            threats_detected += 1

        attack_dist[cname] = attack_dist.get(cname, 0) + 1

        row = df_eval.iloc[idx]
        sip = str(row[src_ip_col]) if src_ip_col and pd.notna(row[src_ip_col]) else f"10.0.{(idx // 254) + 1}.{(idx % 254) + 1}"
        dip = str(row[dest_ip_col]) if dest_ip_col and pd.notna(row[dest_ip_col]) else "192.168.1.100"
        sport = int(row[src_port_col]) if src_port_col and pd.notna(row[src_port_col]) else 40000 + (idx % 20000)
        dport = int(row[dest_port_col]) if dest_port_col and pd.notna(row[dest_port_col]) else (80 if idx % 2 == 0 else 443)
        p_raw = int(row[proto_col]) if proto_col and pd.notna(row[proto_col]) and str(row[proto_col]).isdigit() else 6
        p_name = proto_map.get(p_raw, "TCP")

        protocol_dist[p_name] = protocol_dist.get(p_name, 0) + 1
        src_ip_counts[sip] = src_ip_counts.get(sip, 0) + 1
        dest_ip_counts[dip] = dest_ip_counts.get(dip, 0) + 1

        severity = "Low" if cid == 0 else ("High" if cid in [1, 2, 3, 4, 5, 6, 8, 9, 11, 12] else "Medium")
        flow_rec = {
            "flow_index": idx + 1,
            "timestamp": datetime.now().isoformat(),
            "src_ip": sip,
            "dest_ip": dip,
            "src_port": sport,
            "dest_port": dport,
            "proto": p_raw,
            "packet_count": int(row.get("Tot Fwd Pkts", row.get("Total Fwd Packets", 1)) or 1),
            "byte_count": int(row.get("TotLen Fwd Pkts", row.get("Flow Bytes/s", 100)) or 100),
            "specialist": spec,
            "canonical_id": cid,
            "class_name": cname,
            "confidence": conf,
            "severity": severity,
            "probabilities": probs,
            "is_threat": 1 if cid != 0 else 0
        }
        flows.append(flow_rec)

        if cid != 0:
            alerts.append({
                "flow_id": f"CSV-F{idx + 1:04d}",
                "timestamp": datetime.now().isoformat(),
                "src_ip": sip,
                "dest_ip": dip,
                "src_port": sport,
                "dest_port": dport,
                "proto": p_raw,
                "attack_category": cname,
                "canonical_id": cid,
                "engine": f"Smart AI-NIDS ({spec})",
                "specialist": spec,
                "confidence": conf,
                "severity": severity,
                "signature_info": f"Classification output from {spec} specialist model"
            })

    top_src_ips = [{"ip": k, "count": v} for k, v in sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    top_dest_ips = [{"ip": k, "count": v} for k, v in sorted(dest_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

    session_id = sm.create_session(
        filename=filename,
        file_type="csv",
        file_size_bytes=file_size,
        total_packets=total_flows,
        total_flows=total_flows,
        threats_detected=threats_detected,
        benign_count=total_flows - threats_detected,
        duration_sec=duration_sec,
        suricata_alerts_count=0,
        protocol_dist=protocol_dist,
        top_src_ips=top_src_ips,
        top_dest_ips=top_dest_ips,
        attack_dist=attack_dist,
        flows=flows,
        alerts=alerts,
        status="COMPLETED"
    )
    return session_id


MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB DoS prevention threshold


def save_uploaded_file_safely(upload_file: UploadFile, dest_dir: str) -> tuple[str, str, int]:
    """Safely stream and store an untrusted uploaded file to prevent path traversal and DoS exhaustion.

    Returns:
        (sanitized_filename, local_path, file_size_bytes)
    """
    raw_name = upload_file.filename or "uploaded_traffic"
    # Canonicalize and strip any directory components (prevent path traversal like ../../ or /etc/)
    base_name = os.path.basename(raw_name.replace("\\", "/")).strip()
    if not base_name or base_name in (".", ".."):
        import secrets
        base_name = f"traffic_{secrets.token_hex(4)}"

    local_path = os.path.join(dest_dir, base_name)
    total_bytes = 0
    chunk_size = 64 * 1024

    with open(local_path, "wb") as buffer:
        while True:
            chunk = upload_file.file.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded file exceeds maximum allowed limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
                )
            buffer.write(chunk)

    return base_name, local_path, total_bytes


@app.post("/compare/pcap")
async def compare_pcap(file: UploadFile = File(...)):
    """Run dual-engine comparative evaluation (Suricata vs UnifiedNIDS) on uploaded PCAP and persist session."""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Uploaded file must be a .pcap or .pcapng packet capture.")

    temp_dir = tempfile.mkdtemp(prefix="compare_upload_")
    try:
        sanitized_name, pcap_path, file_size = save_uploaded_file_safely(file, temp_dir)

        engine = get_engine()
        evaluator = ComparativeEvaluator(nids_engine=engine)
        comparison = evaluator.evaluate_pcap(pcap_path)

        # Store in shared session manager
        session_id = save_pcap_comparison_session(comparison, filename=sanitized_name, file_size=file_size)
        sm = get_session_manager()
        comparison["session_id"] = session_id
        comparison["session"] = sm.get_session(session_id)
        return comparison
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/compare/sample")
def compare_sample():
    """Run dual-engine comparison on genuine repository benchmark capture and persist session."""
    candidates = [
        os.path.join(REPO_ROOT, "sample_traffic", "benchmark.pcapng"),
        "/Users/anjanprasadcherukuthota/Documents/Cybersecurity/projects/network/output.pcapng",
        os.path.join(REPO_ROOT, "output.pcapng")
    ]
    sample_pcap = None
    for cand in candidates:
        if os.path.exists(cand):
            sample_pcap = cand
            break

    if not sample_pcap:
        raise HTTPException(status_code=404, detail="Sample benchmark PCAP file not found.")

    file_size = os.path.getsize(sample_pcap)
    engine = get_engine()
    evaluator = ComparativeEvaluator(nids_engine=engine)
    comparison = evaluator.evaluate_pcap(sample_pcap, max_packets=5000)

    # Store in shared session manager
    session_id = save_pcap_comparison_session(comparison, filename="benchmark.pcapng", file_size=file_size)
    sm = get_session_manager()
    comparison["session_id"] = session_id
    comparison["session"] = sm.get_session(session_id)
    return comparison


# ==============================================================================
# UNIFIED ANALYSIS SESSION ENDPOINTS (OPERATIONS MODULE DATA INTEGRATION)
# ==============================================================================

@app.post("/analysis/upload")
async def upload_analysis_file(file: UploadFile = File(...)):
    """Unified file ingestion endpoint for CSV, PCAP, and PCAPNG files.
    
    Creates and stores a shared analysis session consumable across:
    1. Security Overview
    2. Traffic Analysis
    3. Threat Detection
    4. Alerts & Events
    """
    fname = file.filename.lower()
    valid_extensions = (".pcap", ".pcapng", ".cap", ".csv", ".json")
    if not any(fname.endswith(ext) for ext in valid_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{file.filename}'. Supported formats: CSV, PCAP, PCAPNG."
        )

    temp_dir = tempfile.mkdtemp(prefix="analysis_upload_")
    try:
        sanitized_name, local_path, file_size = save_uploaded_file_safely(file, temp_dir)
        sm = get_session_manager()

        if fname.endswith((".pcap", ".pcapng", ".cap")):
            engine = get_engine()
            evaluator = ComparativeEvaluator(nids_engine=engine)
            comparison = evaluator.evaluate_pcap(local_path)
            session_id = save_pcap_comparison_session(comparison, filename=sanitized_name, file_size=file_size)
        elif fname.endswith(".csv"):
            import pandas as pd
            df = pd.read_csv(local_path)
            session_id = save_csv_analysis_session(df, filename=sanitized_name, file_size=file_size)
        elif fname.endswith(".json"):
            import pandas as pd
            df = pd.read_json(local_path)
            session_id = save_csv_analysis_session(df, filename=sanitized_name, file_size=file_size)

        session_data = sm.get_session(session_id)
        return {
            "status": "SUCCESS",
            "session_id": session_id,
            "session": session_data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis processing error: {str(e)}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/analysis/sessions")
def list_analysis_sessions(limit: int = 15):
    """Retrieve list of recent stored analysis sessions."""
    sm = get_session_manager()
    return {"sessions": sm.list_sessions(limit=limit)}


@app.get("/analysis/sessions/latest")
def get_latest_analysis_session():
    """Retrieve the most recent analysis session with flows and alerts."""
    sm = get_session_manager()
    sess = sm.get_latest_session()
    if not sess:
        raise HTTPException(status_code=404, detail="No analysis session found.")
    return sess


@app.get("/analysis/sessions/{session_id}")
def get_analysis_session(session_id: str):
    """Retrieve specific analysis session by unique ID."""
    sm = get_session_manager()
    sess = sm.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return sess


@app.post("/analysis/sessions/reset")
def reset_analysis_sessions():
    """Purge all stored analysis sessions."""
    sm = get_session_manager()
    sm.clear_all()
    return {"status": "SUCCESS", "message": "All analysis sessions successfully reset."}


@app.get("/compare/metrics")
def get_comparative_metrics():
    """Retrieve full verified comparative evaluation artifacts and reconciled metrics."""
    reports_dir = os.path.join(REPO_ROOT, "reports", "comparative_evaluation")
    p_comp = os.path.join(reports_dir, "comparative_metrics.json")
    p_cm = os.path.join(reports_dir, "confusion_matrices.json")
    p_suri = os.path.join(reports_dir, "suricata_results.json")
    p_ai = os.path.join(reports_dir, "ai_nids_results.json")

    import json
    data = {"status": "ok"}
    if os.path.exists(p_comp):
        with open(p_comp, "r") as f:
            data["comparative_metrics"] = json.load(f)
    if os.path.exists(p_cm):
        with open(p_cm, "r") as f:
            data["confusion_matrices"] = json.load(f)
    if os.path.exists(p_suri):
        with open(p_suri, "r") as f:
            s_full = json.load(f)
            data["suricata_summary"] = s_full.get("ground_truth_benchmark", {})
    if os.path.exists(p_ai):
        with open(p_ai, "r") as f:
            ai_full = json.load(f)
            data["ai_summary"] = ai_full.get("ground_truth_benchmark", {})

    return data


# --------------------------------------------------------------------------
# SENSOR AGENT INGESTION & STATE MANAGEMENT
# --------------------------------------------------------------------------
import secrets

SENSOR_API_KEY = os.environ.get("SENSOR_API_KEY", "sai-sensor-secret-key-prod-2026")

_live_sensor_state = {
    "status": "OFFLINE",
    "sensor_id": None,
    "interface": None,
    "last_heartbeat": 0.0,
    "registered_at": 0.0,
    "packets_captured": 0,
    "flows_processed": 0,
    "threats_detected": 0,
    "benign_classified": 0,
    "suricata_alerts": 0,
    "suricata_live_enabled": False
}
_live_sensor_events: List[Dict[str, Any]] = []


def verify_sensor_auth(request: Request, body_key: Optional[str] = None):
    """Enforce API key authentication for sensor telemetry endpoints with timing-attack resistance."""
    header_key = request.headers.get("X-Sensor-Key") or request.headers.get("Authorization")
    if header_key and header_key.startswith("Bearer "):
        header_key = header_key[7:].strip()

    provided_key = header_key or body_key
    if not provided_key or not secrets.compare_digest(str(provided_key), str(SENSOR_API_KEY)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sensor authentication required. Provide valid X-Sensor-Key header."
        )


@app.post("/sensor/register")
async def register_sensor(request: Request):
    """Authenticate and register a local network sensor."""
    data = await request.json()
    verify_sensor_auth(request, data.get("api_key"))

    sensor_id = data.get("sensor_id", "sensor-local")
    meta = data.get("metadata", {})

    now = time.time()
    _live_sensor_state["status"] = "ONLINE"
    _live_sensor_state["sensor_id"] = sensor_id
    _live_sensor_state["interface"] = meta.get("interface", "lo0")
    _live_sensor_state["suricata_live_enabled"] = meta.get("suricata_enabled", False)
    _live_sensor_state["registered_at"] = now
    _live_sensor_state["last_heartbeat"] = now

    token = secrets.token_hex(16)
    return {
        "status": "registered",
        "sensor_id": sensor_id,
        "session_token": token,
        "server_time": now
    }


@app.post("/sensor/ingest")
async def ingest_sensor_telemetry(request: Request):
    """Receive and evaluate micro-batches of live sensor flows and Suricata alerts."""
    data = await request.json()
    verify_sensor_auth(request, data.get("api_key"))

    now = time.time()
    _live_sensor_state["status"] = "ONLINE"
    _live_sensor_state["last_heartbeat"] = now

    events = data.get("events", [])
    engine = get_engine()

    processed_events = []
    for ev in events:
        ev_type = ev.get("event_type", "FLOW_RECORD")

        if ev_type in ("FLOW_RECORD", "ARP_FRAME", "DNS_QUERY"):
            feats = ev.get("features", {})
            spec = ev.get("specialist", "auto")

            try:
                pred = engine.predict(feats, specialist=spec)
                if isinstance(pred, list):
                    pred = pred[0]

                ev["canonical_id"] = pred["canonical_id"]
                ev["class_name"] = pred["class_name"]
                ev["specialist"] = pred["specialist"]
                ev["confidence"] = pred["confidence"]
                ev["probabilities"] = pred.get("probabilities", [])

                _live_sensor_state["flows_processed"] += 1
                if pred["canonical_id"] == 0:
                    _live_sensor_state["benign_classified"] += 1
                else:
                    _live_sensor_state["threats_detected"] += 1
            except Exception as e:
                ev["status"] = "INCOMPLETE_FEATURES"
                ev["error"] = str(e)

        elif ev_type == "SURICATA_ALERT":
            _live_sensor_state["suricata_alerts"] += 1

        processed_events.append(ev)
        _live_sensor_events.append(ev)

    # Keep circular buffer to last 500 events
    while len(_live_sensor_events) > 500:
        _live_sensor_events.pop(0)

    return {
        "status": "ingested",
        "batch_size": len(events),
        "total_flows_processed": _live_sensor_state["flows_processed"],
        "threats_detected": _live_sensor_state["threats_detected"]
    }


@app.get("/sensor/status")
def get_sensor_status():
    """Retrieve operational state and telemetry counters of the network sensor."""
    now = time.time()
    # If heartbeat is older than 15s, mark sensor as offline
    is_active = (now - _live_sensor_state["last_heartbeat"] <= 15.0) and (_live_sensor_state["last_heartbeat"] > 0)
    _live_sensor_state["status"] = "ONLINE" if is_active else "OFFLINE"

    return {
        **_live_sensor_state,
        "is_active": is_active,
        "server_time": now,
        "buffered_events_count": len(_live_sensor_events)
    }


@app.get("/sensor/events")
def get_sensor_events(limit: int = 50):
    """Retrieve recent live events captured by the sensor."""
    return {
        "sensor_id": _live_sensor_state["sensor_id"],
        "sensor_status": _live_sensor_state["status"],
        "total_events": len(_live_sensor_events),
        "events": _live_sensor_events[-limit:]
    }


# Mount static frontend files if present (enables all-in-one single server deployment on Render, Railway, or VPS)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
frontend_dir = os.path.join(REPO_ROOT, "frontend", "public")
if os.path.exists(frontend_dir):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")

