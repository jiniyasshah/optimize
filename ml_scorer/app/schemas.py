from pydantic import BaseModel
from typing import Dict, Optional

class RequestData(BaseModel):
    path: str
    body: str
    length: int
    headers: Dict[str, str] = {}

class PredictionResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    attack_type: str
    trigger_content: str

class HealthResponse(BaseModel):
    status: str
    cpu: str
    memory: str
    network: str