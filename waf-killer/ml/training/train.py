import pandas as pd
import numpy as np
import json
import math
import sys
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import onnx
import skl2onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from datetime import datetime
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

# === Feature Extraction Logic (Must match Rust) ===

SUSPICIOUS_KEYWORDS = [
    "union", "select", "insert", "update", "delete", "drop", "exec",
    "execute", "script", "javascript", "onerror", "onload", "eval",
    "system", "shell", "cmd", "powershell", "bash", "wget", "curl",
    "../", "etc/passwd", "boot.ini", "/proc/", "<script>", "<?php"
]

def calculate_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def count_suspicious_keywords(text):
    if not text:
        return 0.0
    lower_text = text.lower()
    count = 0.0
    for kw in SUSPICIOUS_KEYWORDS:
        # Rust uses 'matches(kw).count()', creating iterator. Python just counts substrings.
        # But 'matches' in Rust usually finds non-overlapping, or overlapping? 
        # Rust's `str::matches` yields non-overlapping matches. Python `count` is also non-overlapping.
        count += lower_text.count(kw)
    return float(count)

def detect_encoding_depth(text):
    if not text:
        return 0.0
    depth = 0.0
    current = text
    for _ in range(5):
        try:
            decoded = unquote(current)
        except:
            decoded = current
        
        if decoded != current:
            depth += 1.0
            current = decoded
        else:
            break
    return depth

def extract_features_single(req):
    features = []
    
    # helper
    def get_len(val): return float(len(val)) if val else 0.0
    
    # Metadata (0-6)
    features.append(get_len(req.get("uri", ""))) # 0: url_length
    features.append(float(req.get("path", "").count('/'))) # 1: path_depth
    features.append(get_len(req.get("query_params", {}))) # 2: param_count
    headers = req.get("headers", {})
    features.append(get_len(headers)) # 3: header_count
    
    body_size = float(req.get("body_size", 0))
    features.append(body_size) # 4: body_size
    
    method = req.get("method", "GET")
    methods = {"GET": 0.0, "POST": 1.0, "PUT": 2.0, "DELETE": 3.0, "HEAD": 4.0, "OPTIONS": 5.0, "PATCH": 6.0}
    features.append(methods.get(method, 7.0)) # 5: method_numeric
    
    features.append(1.0 if body_size > 0 else 0.0) # 6: has_body
    
    # Payload (7-16)
    path = req.get("path", "")
    qs = req.get("query_string", "")
    body = req.get("body_text", "") or ""
    full_payload = path + qs + body
    
    features.append(calculate_entropy(full_payload)) # 7: entropy
    features.append(calculate_entropy(req.get("uri", ""))) # 8: url_entropy
    features.append(calculate_entropy(body)) # 9: body_entropy
    
    special_chars = set(['\'', '"', ';', '|', '&', '<', '>', '(', ')', '=', '%'])
    spec_count = 0
    digit_count = 0
    upper_count = 0
    space_count = 0
    total_len = len(full_payload)
    
    for c in full_payload:
        if c in special_chars: spec_count += 1
        if c.isdigit(): digit_count += 1
        if c.isupper(): upper_count += 1
        if c.isspace(): space_count += 1
        
    features.append(float(spec_count)) # 10: special_char_count
    features.append(float(spec_count) / total_len if total_len > 0 else 0.0) # 11: special_char_ratio
    features.append(float(digit_count) / total_len if total_len > 0 else 0.0) # 12: digit_ratio
    features.append(float(upper_count) / total_len if total_len > 0 else 0.0) # 13: uppercase_ratio
    features.append(float(space_count) / total_len if total_len > 0 else 0.0) # 14: whitespace_ratio
    
    features.append(count_suspicious_keywords(full_payload)) # 15: suspicious_keywords
    features.append(detect_encoding_depth(full_payload)) # 16: encoding_depth
    
    # Behavioral (17-22)
    tstats = req.get("traffic_stats", {})
    r_count_1 = float(tstats.get("request_count_1min", 0))
    features.append(r_count_1) # 17
    features.append(float(tstats.get("request_count_5min", 0))) # 18
    features.append(float(tstats.get("unique_paths_1min", 0))) # 19
    err_rate = float(tstats.get("error_count_1min", 0)) / r_count_1 if r_count_1 > 0 else 0.0
    features.append(err_rate) # 20: error_rate_1min
    features.append(0.0) # 21: user_agent_anomaly (todo)
    features.append(0.0) # 22: geo_distance (todo)
    
    # Protocol (23-27)
    proto = req.get("protocol", "HTTP/1.1")
    p_map = {"HTTP/1.0": 0.0, "HTTP/1.1": 1.0, "HTTP/2.0": 2.0, "h2": 2.0, "HTTP/3.0": 3.0, "h3": 3.0}
    features.append(p_map.get(proto, 1.0)) # 23
    
    is_tls = 1.0 if "https" in req.get("server_name", "") else 0.0 # simple check
    features.append(is_tls) # 24: is_tls
    features.append(0.0) # 25: content_type_anomaly (todo)
    
    accept_len = 0.0
    if headers and "accept" in headers:
         accept_val = headers["accept"]
         if isinstance(accept_val, list): accept_val = accept_val[0]
         accept_len = float(len(str(accept_val)))
    features.append(accept_len) # 26: accept_header_length
    
    features.append(float(len(req.get("cookies", {})))) # 27: cookie_count
    
    return features

# === Main Pipeline ===

def main():
    print("Generating/Loading data...")
    # Load or generate data
    # For this execution, we assume generate_dataset.py runs before this or we call it
    # We will read from stdin or files.
    
    # Just to ensure we have data, let's load from files that we assume exist or we can use the generator directly?
    # In 'real' env we read jsonl.
    
    # Let's assume the user runs:
    # python ml/training/generate_dataset.py > ml/datasets/normal.jsonl
    # python ml/training/generate_dataset.py attacks > ml/datasets/attacks.jsonl
    
    # We will enforce paths
    normal_path = "ml/datasets/normal_traffic.jsonl"
    attack_path = "ml/datasets/attack_traffic.jsonl"
    
    if not os.path.exists("ml/models"):
        os.makedirs("ml/models")
        
    normal_data = []
    if os.path.exists(normal_path):
        with open(normal_path) as f:
            for line in f:
                if line.strip(): normal_data.append(json.loads(line))
    else:
        print(f"Warning: {normal_path} not found. Returning.")
        return

    print(f"Loaded {len(normal_data)} normal samples")
    
    # Extract features
    X = [extract_features_single(r) for r in normal_data]
    X = np.array(X, dtype=np.float32)
    
    # Standardize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train
    print("Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    
    # Export to ONNX
    print("Exporting to ONNX...")
    initial_type = [('float_input', FloatTensorType([None, 28]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset={'': 12, 'ai.onnx.ml': 3}
    )
    
    onnx.save_model(onnx_model, "ml/models/anomaly_v1.onnx")
    
    # Save Metadata
    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist()
    }
    
    metadata = {
        "version": "v1",
        "training_date": datetime.now().isoformat(),
        "n_samples": len(normal_data),
        "n_features": 28,
        "detection_rate": 0.0, # Placeholder
        "false_positive_rate": 0.0, # Placeholder
        "scaler": scaler_params
    }
    
    with open("ml/models/metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
        
    print("Done. Model saved to ml/models/anomaly_v1.onnx")

if __name__ == "__main__":
    main()
