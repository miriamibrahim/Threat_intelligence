import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# -----------------------------
# Step 1: Load and parse Suricata logs
# -----------------------------
logs = []
with open("logs/eve.json", "r") as f:  # Replace with your file path
    for line in f:
        try:
            event = json.loads(line)
            event_type = event.get("event_type")

            # Initialize default values
            flow = event.get("flow", {})
            tcp = flow.get("tcp", {})
            udp = flow.get("udp", {})

            # Determine if the event is an alert
            alerted = 1 if event_type == "alert" else 0

            # Append event
            logs.append({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "tcp_syn": tcp.get("syn", False),
                "tcp_ack": tcp.get("ack", False),
                "tcp_rst": tcp.get("rst", False),
                "udp_len": udp.get("len_invalid", 0),
                "state": flow.get("state", ""),
                "alerted": alerted,
                "event_type": event_type
            })
        except json.JSONDecodeError:
            continue

# Convert to DataFrame
df = pd.DataFrame(logs)
print("Parsed DataFrame:")
print(df.head())

# -----------------------------
# Step 2: Encode categorical features
# -----------------------------
df["proto"] = df["proto"].astype("category").cat.codes
df["state"] = df["state"].astype("category").cat.codes
df["event_type"] = df["event_type"].astype("category").cat.codes

# Features and target
X = df.drop(["timestamp", "src_ip", "dest_ip", "alerted"], axis=1)
y = df["alerted"]

# Check class distribution
print("\nClass distribution:\n", y.value_counts())

# -----------------------------
# Step 3: Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# -----------------------------
# Step 4: Train Random Forest Classifier
# -----------------------------
clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
clf.fit(X_train, y_train)

# -----------------------------
# Step 5: Predictions and Evaluation
# -----------------------------
y_pred = clf.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
