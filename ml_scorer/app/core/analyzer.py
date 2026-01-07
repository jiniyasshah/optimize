import json
import urllib.parse
from .preprocessor import master_preprocess

def dissect_payload(path: str, body: str, headers: dict) -> dict:
    components = {}
    
    # 1. Path Analysis
    if path:
        components["URL Full"] = master_preprocess(path)
        try:
            parsed = urllib.parse.urlparse(path)
            if parsed.query:
                components["URL Raw Query"] = master_preprocess(parsed.query)
            segments = parsed.path.strip("/").split("/")
            for i, segment in enumerate(segments):
                if segment:
                    components[f"URL Segment {i+1}"] = master_preprocess(segment)
            
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for k, values in query_params.items():
                for v in values:
                    components[f"URL Param: {k}"] = master_preprocess(v)
        except Exception:
            pass

    # 2. Body Analysis
    if body:
        components["Body Raw"] = master_preprocess(body)
        try:
            # Try parsing as JSON
            json_data = json.loads(body)
            if isinstance(json_data, dict):
                def inspect_json(data, prefix="Body"):
                    for k, v in data.items():
                        if isinstance(v, dict):
                            inspect_json(v, prefix=f"{prefix}.{k}")
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int, float)):
                                    components[f"{prefix}: {k}[]"] = master_preprocess(str(item))
                        else:
                            components[f"{prefix}: {k}"] = master_preprocess(str(v))
                inspect_json(json_data)
        except Exception:
            pass
            
        try:
            # Try parsing as Form Data
            form_data = urllib.parse.parse_qs(body, keep_blank_values=True)
            if form_data:
                for k, values in form_data.items():
                    for v in values:
                        components[f"Body Form: {k}"] = master_preprocess(v)
        except Exception:
            pass

    # 3. Header Analysis
    if headers:
        skip_headers = {
            "host", "accept", "connection", "accept-encoding", 
            "accept-language", "content-length", "upgrade-insecure-requests",
            "priority", "cache-control", "pragma"
        }
        
        for k, v in headers.items():
            key_lower = k.lower()
            if key_lower in skip_headers: continue
            if key_lower.startswith("sec-ch-ua") or key_lower.startswith("sec-fetch"): continue

            components[f"Header: {k}"] = master_preprocess(v)

    return components

def calculate_heuristic_score(content: str) -> float:
    suspicious_chars = {
        "'": 0.15, '"': 0.10, "<": 0.15, ">": 0.15, ";": 0.10, "--": 0.20,
        "(": 0.05, ")": 0.05, "$": 0.10, "`": 0.10, "union": 0.30, "select": 0.20,
        "{": 0.10, "}": 0.10
    }
    score = 0.0
    content_lower = content.lower()
    for char, weight in suspicious_chars.items():
        if char in content_lower:
            score += (weight * content_lower.count(char))
    return min(score, 0.60)