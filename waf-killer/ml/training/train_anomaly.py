import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import numpy as np
import os

# Create directories if not exist
os.makedirs('../models', exist_ok=True)
os.makedirs('../datasets', exist_ok=True)

# Generate dummy data if not exists
if not os.path.exists('../datasets/normal_traffic.csv'):
    print("Generating dummy normal traffic data...")
    # Generate 1000 samples with 50 features
    X_dummy = np.random.rand(1000, 50)
    df = pd.DataFrame(X_dummy)
    df.to_csv('../datasets/normal_traffic.csv', index=False)
else:
    df = pd.read_csv('../datasets/normal_traffic.csv')

X_train = df.values

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)

print(f"Training Isolation Forest on {len(X_train)} samples...")

# Train Isolation Forest
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,  # Assume 1% of data is anomalous
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

print("Exporting to ONNX...")

# Export to ONNX
# Input type: Float tensor of shape [None, 50]
initial_type = [('input', FloatTensorType([None, 50]))]
onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    target_opset={'': 12, 'ai.onnx.ml': 3}
)

with open('../models/anomaly_detector.onnx', 'wb') as f:
    f.write(onnx_model.SerializeToString())

print("✅ Anomaly detection model exported to ../models/anomaly_detector.onnx")
