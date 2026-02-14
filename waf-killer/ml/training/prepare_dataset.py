import pandas as pd
import numpy as np
import os

def create_dummy_datasets():
    os.makedirs('../datasets', exist_ok=True)
    
    print("Creating normal_traffic.csv...")
    X_normal = np.random.rand(1000, 50)
    df_normal = pd.DataFrame(X_normal)
    df_normal.to_csv('../datasets/normal_traffic.csv', index=False)
    
    print("Creating attack_samples.csv...")
    X_attack = np.random.rand(500, 50)
    # Add some bias to make them "attacks" (e.g., higher values)
    X_attack = X_attack + 0.5 
    y_attack = np.random.randint(0, 6, 500)
    
    df_attack = pd.DataFrame(X_attack)
    df_attack['attack_type'] = y_attack
    df_attack.to_csv('../datasets/attack_samples.csv', index=False)
    
    print("✅ Datasets prepared")

if __name__ == "__main__":
    create_dummy_datasets()
