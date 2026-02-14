# ml/training/retrain.py
import os
import json
import shutil
from datetime import datetime
import subprocess

def retrain():
    print("=== Retraining Pipeline Initiated ===")
    
    base_dataset = "ml/datasets/labeled_attacks.jsonl"
    feedback_dataset = "ml/datasets/feedback_samples.jsonl"
    
    # Check if feedback exists
    if not os.path.exists(feedback_dataset):
        print("No feedback data found. Nothing to retrain.")
        return

    # Backup original model
    if os.path.exists("ml/models/classifier_v1.onnx"):
        print("Backing up existing model...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy("ml/models/classifier_v1.onnx", f"ml/models/classifier_v1_{timestamp}.onnx")

    # Merge datasets
    # We will append feedback to the training data temporarily or permanently?
    # Let's create a combined dataset.
    
    print("Merging datasets...")
    combined_data = []
    
    # 1. Load Original (or regenerate? For now load existing)
    if os.path.exists(base_dataset):
        with open(base_dataset, 'r') as f:
            for line in f:
                if line.strip(): combined_data.append(json.loads(line))
    
    # 2. Load Feedback
    new_samples_count = 0
    with open(feedback_dataset, 'r') as f:
        for line in f:
            if line.strip(): 
                combined_data.append(json.loads(line))
                new_samples_count += 1
                
    print(f"Added {new_samples_count} feedback samples. Total: {len(combined_data)}")
    
    # 3. Write combined
    # For simplicity, we overwrite the main dataset or use a temp one.
    # train_classifier.py currently reads labeled_attacks.jsonl.
    # Let's overwrite it for now (assuming base_dataset can be regenerated if needed).
    with open(base_dataset, 'w') as f:
        for sample in combined_data:
            f.write(json.dumps(sample) + "\n")
            
    # 4. Run Training
    print("Running training script...")
    subprocess.check_call(["python", "ml/training/train_classifier.py"])
    
    print("Retraining complete. New model deployed.")
    
    # 5. Archive used feedback ?
    # In a real system we would move feedback_samples.jsonl to an archive.
    # Here we just leave it or rename it.
    os.rename(feedback_dataset, f"{feedback_dataset}.processed_{timestamp}")

if __name__ == "__main__":
    retrain()
