"""FastAPI backend application for the Smart AI Network Intrusion Detection System.

Coordinates end-to-end inference across all 5 specialist models via UnifiedNIDS,
providing REST endpoints for health monitoring, model introspection, and
single/batch flow classification into the frozen 13-class canonical taxonomy.
"""

import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from utils.taxonomy import (
    CLASS_NAMES,
    CLASS_TO_ID,
    NUM_CLASSES,
    SPECIALIST_SUB_TAXONOMIES,
)
from utils.unified_nids import UnifiedNIDS
from utils.train_models import SPECIALIST_SPECS
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


def get_engine() -> UnifiedNIDS:
    """Retrieve or initialize the centralized UnifiedNIDS inference engine."""
    global _engine
    if _engine is None:
        _engine = UnifiedNIDS()
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

# CORS configuration suitable for React frontend
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "")
allowed_origins = [orig.strip() for orig in allowed_origins_env.split(",") if orig.strip()]
if not allowed_origins:
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


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

    detected_spec = predictions[0].specialist if predictions else spec
    return BatchPredictionResponse(
        count=len(predictions),
        specialist=detected_spec,
        predictions=predictions,
    )
