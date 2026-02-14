import pandas as pd
import torch
import torch.nn as nn
import torch.onnx
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Create directories
os.makedirs('../models', exist_ok=True)
os.makedirs('../datasets', exist_ok=True)

# Generate dummy attack data if not exists
if not os.path.exists('../datasets/attack_samples.csv'):
    print("Generating dummy attack samples...")
    # 500 samples, 50 features + 1 label (0-5)
    X_dummy = np.random.rand(500, 50)
    y_dummy = np.random.randint(0, 6, 500)
    data = pd.DataFrame(X_dummy)
    data['attack_type'] = y_dummy
    data.to_csv('../datasets/attack_samples.csv', index=False)
else:
    data = pd.read_csv('../datasets/attack_samples.csv')

# Features and labels
X = data.drop(['attack_type'], axis=1).values
y = data['attack_type'].values

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Normalize
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Define neural network
class AttackClassifier(nn.Module):
    def __init__(self, input_dim, num_classes):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, num_classes)
        self.relu = nn.ReLU()
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        x = self.softmax(self.fc3(x))
        return x

print("Training Neural Network Classifier...")

# Train model
model = AttackClassifier(input_dim=50, num_classes=6)
criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Convert to tensors
X_tensor = torch.FloatTensor(X_train_scaled)
y_tensor = torch.LongTensor(y_train)

# Training loop
for epoch in range(100):
    optimizer.zero_grad()
    outputs = model(X_tensor)
    loss = criterion(outputs, y_tensor)
    loss.backward()
    optimizer.step()
    
    if (epoch+1) % 20 == 0:
        print(f"Epoch [{epoch+1}/100], Loss: {loss.item():.4f}")

print("Exporting to ONNX...")

# Export to ONNX
dummy_input = torch.FloatTensor(X_test_scaled[:1])
torch.onnx.export(
    model,
    dummy_input,
    '../models/attack_classifier.onnx',
    export_params=True,
    opset_version=12,
    input_names=['input'],
    output_names=['output']
)

print("✅ Attack classifier exported to ../models/attack_classifier.onnx")
