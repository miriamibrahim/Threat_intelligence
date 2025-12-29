import json
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

# Import functions/classes from your pipeline
from threat_int import (
    extract_features_from_event,
    process_event,
    load_ip_iocs,
    load_domain_iocs,
    RealTimeThreatDetector
)

# =========================
# Create test IOCs
# =========================
ip_iocs = {
    "1.1.1.1": {"confidence": 80, "last_seen": "2025-12-01", "source": "AbuseIPDB"},
    "9.9.9.9": {"confidence": 90, "last_seen": "2025-12-01", "source": "AbuseIPDB"}
}

domain_iocs = {
    "malicious.com": {"confidence": 100, "last_seen": "2025-12-01", "source": "URLHaus"}
}

# =========================
# Create synthetic events
# =========================
events = [
    {"src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "duration": 120, "tx_bytes": 5000,
     "rx_bytes": 7000, "pkts_sent": 50, "pkts_received": 60, "proto": "tcp", "dest_port": 9999, "event_type": "connection"},
   
    {"src_ip": "8.8.8.8", "dest_ip": "9.9.9.9", "duration": 5, "tx_bytes": 100,
     "rx_bytes": 200, "pkts_sent": 1, "pkts_received": 2, "proto": "udp", "dest_port": 53, "event_type": "dns",
     "dns": {"rrname": "malicious.com", "answers": [{"rdata": "10.10.10.10"}]}},
   
    {"src_ip": "3.3.3.3", "dest_ip": "4.4.4.4", "duration": 10, "tx_bytes": 50,
     "rx_bytes": 60, "pkts_sent": 1, "pkts_received": 1, "proto": "tcp", "dest_port": 80, "event_type": "connection"}
]

# =========================
# Feature extraction test
# =========================
feature_list = [extract_features_from_event(e, ip_iocs, domain_iocs) for e in events]
df = pd.DataFrame(feature_list)
df['label'] = ((df['ioc_matches'] > 0) | (df['anomaly_score'] > 0)).astype(int)
numeric_features = [c for c in df.columns if c != 'label']

print("\n[INFO] Feature extraction test:")
print(df)

# =========================
# Train ML model on synthetic data
# =========================
X = df[numeric_features].fillna(0)
y = df['label']
X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2,random_state=42, stratify=y)
print("training class distribution",    Counter(y_train))
from collections import Counter
counter = Counter(y_train)
if min(counter.values())> 1:
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.5, random_state=42, stratify=y)
    smote = SMOTE(random_state=42)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
else:
    X_train_bal, y_train_bal = X_train, y_train

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_bal)
X_val_scaled = scaler.transform(X_val)

model = RandomForestClassifier(n_estimators=50, random_state=42, class_weight='balanced')
model.fit(X_train_scaled, y_train_bal)

y_pred_proba = model.predict_proba(X_val_scaled)[:, 1]
roc_auc = roc_auc_score(y_val, y_pred_proba)
print(f"\n[INFO] ROC-AUC on synthetic validation set: {roc_auc:.4f}")

# =========================
# Test RealTimeThreatDetector
# =========================
detector = RealTimeThreatDetector(model, scaler, numeric_features)
print("\n[INFO] Real-time threat detection test:")
for event in events:
    features = extract_features_from_event(event, ip_iocs, domain_iocs)
    detected = detector.analyze_event(features)
    print(detected)

# =========================
# Verify threat log
# =========================
print("\n[INFO] Threat log:")
print(pd.DataFrame(detector.threat_log))