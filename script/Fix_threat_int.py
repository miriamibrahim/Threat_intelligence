import json
import csv
import time
import os
import requests
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, roc_curve
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import warnings

warnings.filterwarnings("ignore")

# =========================
# Config
# =========================
EVE_JSON_FILE = "logs/eve.json"
IP_IOC_FILE = "iocs/abuseipdb_iocs.json"
DOMAIN_IOC_FILE = "iocs/urlhaus_iocs.json"
RESULTS_DIR = "results"
MODEL_FILE = f"{RESULTS_DIR}/ml_model.pkl"
SCALER_FILE = f"{RESULTS_DIR}/scaler.pkl"
FEATURES_FILE = f"{RESULTS_DIR}/features.pkl"
ALERTS_FILE = f"{RESULTS_DIR}/final_alerts.csv"

MIN_CONFIDENCE = 50
THREAT_THRESHOLD = 0.7

os.makedirs(RESULTS_DIR, exist_ok=True)

# =========================
# IOC Loading
# =========================
def load_ip_iocs():
    try:
        with open(IP_IOC_FILE) as f:
            data = json.load(f)
    except:
        data = {"data": []}

    iocs = {}
    for e in data.get("data", []):
        if e.get("abuseConfidenceScore", 0) >= MIN_CONFIDENCE:
            iocs[e["ipAddress"]] = e["abuseConfidenceScore"]
    return iocs


def load_domain_iocs():
    try:
        with open(DOMAIN_IOC_FILE) as f:
            data = json.load(f)
    except:
        data = {"data": []}

    return {e["url"].lower(): 1 for e in data.get("data", []) if e.get("url")}


# =========================
# IOC Matching
# =========================
def ioc_match(event, ip_iocs, domain_iocs):
    matches = 0

    for ip_field in ["src_ip", "dest_ip"]:
        if event.get(ip_field) in ip_iocs:
            matches += 1

    if event.get("event_type") == "dns":
        q = event.get("dns", {}).get("rrname", "")
        if q.lower() in domain_iocs:
            matches += 1

    return matches


# =========================
# Feature Extraction (BEHAVIOR ONLY)
# =========================
def extract_features(event):
    f = {}

    f["is_dns"] = int(event.get("event_type") == "dns")
    f["is_udp"] = int(event.get("proto", "").lower() == "udp")
    f["dest_port"] = event.get("dest_port", 0)

    dns = event.get("dns", {})
    f["dns_answer_count"] = len(dns.get("answers", []))
    f["dns_rrtype_A"] = int(dns.get("rrtype") == "A")
    f["dns_rrtype_HTTPS"] = int(dns.get("rrtype") == "HTTPS")

    f["suspicious_port"] = int(f["dest_port"] not in [53, 80, 443])

    return f


# =========================
# Load Events
# =========================
def load_events():
    events = []
    with open(EVE_JSON_FILE) as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                continue
    return events


# =========================
# Train ML Model
# =========================
def train_model(events, ip_iocs, domain_iocs):
    rows = []

    for e in events:
        features = extract_features(e)
        label = int(ioc_match(e, ip_iocs, domain_iocs) > 0)  # IOC ONLY
        features["label"] = label
        rows.append(features)

    df = pd.DataFrame(rows).fillna(0)

    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    smote = SMOTE(random_state=42)
    X_train, y_train = smote.fit_resample(X_train, y_train)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val = scaler.transform(X_val)

    model = RandomForestClassifier(
        n_estimators=150, class_weight="balanced", random_state=42
    )
    model.fit(X_train, y_train)

    probs = model.predict_proba(X_val)[:, 1]
    auc_score = roc_auc_score(y_val, probs)
    print(f"[+] ROC-AUC: {auc_score:.4f}")

    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    joblib.dump(list(X.columns), FEATURES_FILE)

    return model, scaler, list(X.columns)


# =========================
# Real-Time Detection
# =========================
def real_time_detection(model, scaler, features, ip_iocs, domain_iocs):
    with open(ALERTS_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dest_ip", "ioc", "ml_score"])

        with open(EVE_JSON_FILE) as log:
            for line in log:
                try:
                    event = json.loads(line)
                except:
                    continue

                ioc_hits = ioc_match(event, ip_iocs, domain_iocs)

                feat = extract_features(event)
                X = pd.DataFrame([feat])[features]
                X = scaler.transform(X)
                prob = model.predict_proba(X)[0][1]

                if ioc_hits > 0 or prob > THREAT_THRESHOLD:
                    writer.writerow([
                        event.get("timestamp"),
                        event.get("src_ip"),
                        event.get("dest_ip"),
                        ioc_hits,
                        round(prob, 3)
                    ])
                    print(f"[ALERT] IOC={ioc_hits} | ML={prob:.2f}")


# =========================
# Main
# =========================
def main():
    ip_iocs = load_ip_iocs()
    domain_iocs = load_domain_iocs()

    events = load_events()

    model, scaler, features = train_model(events, ip_iocs, domain_iocs)

    real_time_detection(model, scaler, features, ip_iocs, domain_iocs)

    print("[✓] Pipeline completed successfully")


if __name__ == "__main__":
    main()
  
