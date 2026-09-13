"""Pydantic schemas for the Smart AI NIDS FastAPI Backend."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """API health status and model readiness."""
    status: str = "ok"
    service: str = "Smart AI Network Intrusion Detection System API"
    version: str = "1.0.0"
    engine_ready: bool = True
    available_specialists: List[str]
    loaded_specialists: List[str]


class SpecialistDetail(BaseModel):
    """Metadata describing a specialist IDS pipeline."""
    description: str
    canonical_classes: List[str]
    feature_count: Optional[int] = None
    model_name: Optional[str] = None


class ModelsResponse(BaseModel):
    """Catalog of available specialist models and canonical taxonomy."""
    specialists: Dict[str, SpecialistDetail]
    canonical_classes: List[str]
    canonical_class_to_id: Dict[str, int]


class PredictionRequest(BaseModel):
    """Inference request for a single network flow or packet."""
    features: Optional[Dict[str, Any]] = None
    specialist: Optional[str] = "auto"

    model_config = ConfigDict(extra="allow")

    def get_feature_dict(self) -> Dict[str, Any]:
        """Extract the effective feature dictionary."""
        if self.features is not None and isinstance(self.features, dict):
            return dict(self.features)
        
        # If passed flat, collect all extra fields excluding 'specialist'
        flat = {k: v for k, v in self.model_dump().items() if k not in ("features", "specialist") and v is not None}
        return flat


class PredictionResponse(BaseModel):
    """Canonical 13-class prediction result."""
    predicted_class_id: int = Field(..., description="Canonical class ID (0 to 12)")
    predicted_class: str = Field(..., description="Canonical class name")
    confidence: float = Field(..., description="Posterior confidence score [0.0, 1.0]")
    specialist: str = Field(..., description="Name of the specialist pipeline that handled the input")
    probabilities: List[float] = Field(..., description="Full 13-dimensional canonical posterior probability vector")
    canonical_id: Optional[int] = None
    class_name: Optional[str] = None


class BatchPredictionRequest(BaseModel):
    """Batch inference request for multiple network flows or packets."""
    records: List[Dict[str, Any]] = Field(..., description="List of feature dictionaries")
    specialist: Optional[str] = "auto"


class BatchPredictionResponse(BaseModel):
    """Batch inference results."""
    count: int
    specialist: str
    predictions: List[PredictionResponse]


class ErrorResponse(BaseModel):
    """Standardized error response payload."""
    detail: str
    error_type: Optional[str] = None
