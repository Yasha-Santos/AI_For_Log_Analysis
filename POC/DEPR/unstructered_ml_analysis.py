import json
import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline


# D:\vscode\capstone\parsed_logs_output.json

# Load logs
with open("parsed_logs_output.json") as f:
    data = json.load(f)

df = pd.DataFrame(data)


# Normalizingish(simple for poc)
def normalize_message(msg):
    if pd.isna(msg):
        return "unknown"

    msg = str(msg).lower()

    if any(x in msg for x in ["fail",  "invalid", "error"]):
        return "auth_failure"
    
    elif any(x in msg for x in ["accept", "success"]):
        return "auth_success"
    
    elif "close" in msg:
        return "connection_closed"
    
    return "other"

df["normalized_message"] = df["message"].apply(normalize_message)


# Features
# keep the hour
df["hour"] = df["timestamp"].str.split().str[2].str.split(":").str[0].astype(int)

# IP simple (simple for poc, just keeping the first number)
df["ip_prefix"] = df["source_ip"].apply(lambda x: x.split(".")[0])

# Flags
df["is_root"] = (df["user"] == "root").astype(int)
df["is_failure"] = (df["normalized_message"] == "auth_failure").astype(int)


categorical_features = ["log_type", "user", "ip_prefix", "normalized_message"]
numeric_features = ["hour", "is_root", "is_failure"]


preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
        ("num", "passthrough", numeric_features)
    ]
)

# model
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

pipeline = Pipeline([
    ("preprocessing", preprocessor),
    ("model", model)
])


# train
pipeline.fit(df)

# Predict

df["anomaly_score"] = pipeline.decision_function(df)
df["anomaly"] = pipeline.predict(df)

# ------------------------
# Output results
# ------------------------
print("\nResults:\n")
print(df[[
    "timestamp",
    "source_ip",
    "user",
    "message",
    "anomaly",
    "anomaly_score"
]])


# Showing anomalies
print("\n=== anomalies ===\n")

for _, row in df.iterrows():
    if row["anomaly"] == -1:
        print(f" anomolous log:")
        print(f"  Time: {row['timestamp']}")
        print(f"  IP: {row['source_ip']}")
        print(f"  User: {row['user']}")
        print(f"  Event: {row['message']}")
        print(f"  Score: {row['anomaly_score']:.4f}")
        print("-" * 50)

