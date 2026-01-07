from fastapi import FastAPI, HTTPException
import psutil
import time
import os
from .schemas import RequestData, PredictionResponse, HealthResponse
from .core.model import WAFModel
from .core.analyzer import dissect_payload, calculate_heuristic_score

app = FastAPI(title="WAF ML Scorer")

# Initialize Model
# We assume waf_model.pkl is in the root of ml_scorer/
waf_model = WAFModel("waf_model.pkl")

# Stats Tracking
STATS = {
    "request_count": 0,
    "start_time": time.time()
}

@app.get("/health", response_model=HealthResponse)
def health_check():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    uptime_min = (time.time() - STATS["start_time"]) / 60
    rpm = int(STATS["request_count"] / uptime_min) if uptime_min > 0 else 0
    
    return {
        "status": "online" if waf_model.model else "model_error",
        "cpu": f"{process.cpu_percent(interval=None)}%",
        "memory": f"{round(memory_info.rss / 1024 / 1024, 2)} MB",
        "network": f"{rpm} Req/min"
    }

@app.post("/predict", response_model=PredictionResponse)
def predict(data: RequestData):
    STATS["request_count"] += 1
    
    if not waf_model.model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    # 1. Dissect Payload
    inspectable_items = dissect_payload(data.path, data.body, data.headers)
    
    max_risk_score = 0.0
    is_anomaly = False
    detected_type = "Normal"
    trigger_content = ""

    # 2. Hybrid Analysis Loop
    for source, content in inspectable_items.items():
        if not content.strip() or content.strip() in ["/", "\\"]: 
            continue
        
        # Skip safe short tokens
        if len(content) < 4 and content.replace('.', '').replace('-', '').isalnum():
            continue

        # A. ML Analysis
        pred_label, confidence = waf_model.predict(content)
        
        ml_risk = confidence if pred_label != "Normal" else (1.0 - confidence)

        # B. Heuristic Analysis
        heuristic_boost = 0.0
        # Don't run heuristics on User-Agent (too many false positives with symbols)
        if "user-agent" not in source.lower():
            heuristic_boost = calculate_heuristic_score(content)

        # C. Final Score
        final_risk = min(ml_risk + heuristic_boost, 1.0)

        if final_risk > 0.75:
            is_anomaly = True
        
        if final_risk > max_risk_score:
            max_risk_score = final_risk
            trigger_content = content
            if pred_label != "Normal":
                clean_label = pred_label.replace("malicious(", "").replace(")", "").upper()
                detected_type = f"ML_{clean_label}"

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": float(max_risk_score),
        "attack_type": detected_type,
        "trigger_content": trigger_content
    }