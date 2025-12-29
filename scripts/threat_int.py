import json
import csv
import time
import os
import requests
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, roc_auc_score, roc_curve, auc
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
from plotly.subplots import make_subplots
import plotly.graph_objects as go
import plotly.express as px
import warnings
import joblib

warnings.filterwarnings('ignore')

# =========================
# Config
# =========================
EVE_JSON_FILE = "logs/eve.json"
IP_IOC_FILE = "iocs/abuseipdb_iocs.json"
DOMAIN_IOC_FILE = "iocs/urlhaus_iocs.json"
OUTPUT_FILE = "results/ioc_alerts.csv"
ANOMALY_OUTPUT_FILE = "results/anomalies.csv"
THREAT_CSV = "results/threats_detected.csv"
LOG_FILE = "results/pipeline_log.txt"
MIN_CONFIDENCE = 50
SLEEP_INTERVAL = 0.5
ABUSEIPDB_API_KEY = "ddb207c93f1d728e7e677e317a4273841ebb8781578032dd234de8292b1a80682f2fbeeb0bcffe69"

os.makedirs("results", exist_ok=True)

# =========================
# Logger
# =========================
def log(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

# =========================
# IOC Fetching
# =========================
def fetch_abuseipdb(api_key):
    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=50"
    headers = {"Accept": "application/json", "Key": api_key}
    try:
        r = requests.get(url, headers=headers)
        data = r.json()
        os.makedirs(os.path.dirname(IP_IOC_FILE), exist_ok=True)
        with open(IP_IOC_FILE, "w") as f:
            json.dump(data, f, indent=2)
        log(f"[+] Fetched {len(data['data'])} IP IOCs from AbuseIPDB")
    except Exception as e:
        log(f"[!] Failed to fetch AbuseIPDB: {e}")

def fetch_urlhaus():
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        r = requests.get(url)
        domains = [{"url": line.split(",")[1]} for line in r.text.splitlines() if line]
        os.makedirs(os.path.dirname(DOMAIN_IOC_FILE), exist_ok=True)
        with open(DOMAIN_IOC_FILE, "w") as f:
            json.dump({"data": domains}, f, indent=2)
        log(f"[+] Fetched {len(domains)} domain IOCs from URLHaus")
    except Exception as e:
        log(f"[!] Failed to fetch URLHaus: {e}")

# =========================
# Load IOCs
# =========================
def load_ip_iocs():
    try:
        with open(IP_IOC_FILE) as f:
            abuse_data = json.load(f)
    except FileNotFoundError:
        abuse_data = {"data": []}
    ip_iocs = {}
    for entry in abuse_data.get("data", []):
        ip = entry.get("ipAddress")
        score = entry.get("abuseConfidenceScore", 0)
        last_seen = entry.get("lastReportedAt", "")
        if ip:
            ip_iocs[ip] = {"confidence": score, "last_seen": last_seen, "source": "AbuseIPDB"}
    return ip_iocs

def load_domain_iocs():
    try:
        with open(DOMAIN_IOC_FILE) as f:
            domain_data = json.load(f)
    except FileNotFoundError:
        domain_data = {"data": []}
    domain_iocs = {}
    for entry in domain_data.get("data", []):
        domain = entry.get("url") or entry.get("domain")
        last_seen = entry.get("date_added", "")
        if domain:
            domain_iocs[domain.lower()] = {"confidence": 100, "last_seen": last_seen, "source": "URLHaus"}
    return domain_iocs

# =========================
# Tail function for real-time
# =========================
def tail_f(file):
    with open(file, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(SLEEP_INTERVAL)
                continue
            yield line.strip()

# =========================
# IOC + Anomaly processing
# =========================
def process_event(event, ip_iocs, domain_iocs):
    matched = {}
    anomaly_score = 0

    for ip_field in ["src_ip", "dest_ip", "source_ip", "dest_ip"]:
        ip = event.get(ip_field)
        if ip and ip in ip_iocs and ip_iocs[ip]["confidence"] >= MIN_CONFIDENCE:
            matched[ip] = ip_iocs[ip]
            anomaly_score += 1

    if event.get("event_type") == "dns" and "dns" in event:
        dns_info = event["dns"]
        query = dns_info.get("rrname")
        if query and query.lower() in domain_iocs:
            matched[query.lower()] = domain_iocs[query.lower()]
            anomaly_score += 1
        for ans in dns_info.get("answers", []):
            for key in ["rdata", "rrname"]:
                val = ans.get(key)
                if val and val.lower() in domain_iocs:
                    matched[val.lower()] = domain_iocs[val.lower()]
                    anomaly_score += 1

    dest_port = event.get("dest_port")
    if dest_port and dest_port not in [53, 80, 443]:
        anomaly_score += 1
    if event.get("event_type") == "dns" and len(event.get("dns", {}).get("answers", [])) > 5:
        anomaly_score += 1

    return matched, anomaly_score

# =========================
# Feature extraction
# =========================
def extract_features_from_event(event, ip_iocs, domain_iocs):
    features = {}
    features['dur'] = event.get('duration', 0)
    features['sbytes'] = event.get('tx_bytes', 0)
    features['dbytes'] = event.get('rx_bytes', 0)
    features['spkts'] = event.get('pkts_sent', 0)
    features['dpkts'] = event.get('pkts_received', 0)
    features['total_bytes'] = features['sbytes'] + features['dbytes']
    features['total_packets'] = features['spkts'] + features['dpkts']
    features['byte_per_packet'] = features['total_bytes'] / (features['total_packets'] + 1)

    proto = event.get('proto', 'tcp').lower()
    features['is_tcp'] = int(proto == 'tcp')
    features['is_udp'] = int(proto == 'udp')
    features['is_icmp'] = int(proto == 'icmp')

    features['high_byte_count'] = int(features['total_bytes'] > 10000)
    features['many_packets'] = int(features['total_packets'] > 100)
    features['long_duration'] = int(features['dur'] > 60)

    matched, anomaly_score = process_event(event, ip_iocs, domain_iocs)
    features['ioc_matches'] = len(matched)
    features['anomaly_score'] = anomaly_score

    return features

# =========================
# Real-Time Detector Class
# =========================
class RealTimeThreatDetector:
    def __init__(self, model, scaler, feature_columns):
        self.model = model
        self.scaler = scaler
        self.feature_columns = feature_columns
        self.threat_log = []
        self.threshold = 0.7
        self.malicious_ips = {}
        self.malicious_ports = {}

    def extract_features(self, network_event):
        features = {}
        for col in self.feature_columns:
            features[col] = network_event.get(col, 0)
        return pd.DataFrame([features])[self.feature_columns]

    def analyze_event(self, network_event):
        features_df = self.extract_features(network_event)
        features_scaled = self.scaler.transform(features_df)
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0][1]
        is_threat = prediction == 1 or probability > self.threshold
        network_event['ml_prediction'] = prediction
        network_event['ml_confidence'] = probability
        network_event['is_threat'] = is_threat
        if is_threat:
            self.threat_log.append({
                "source_ip": network_event.get("source_ip"),
                "dest_ip": network_event.get("dest_ip"),
                "ml_confidence": probability,
                "ioc_matches": network_event.get("ioc_matches", 0),
                "anomaly_score": network_event.get("anomaly_score", 0)
            })
            log(f"[THREAT] Event: {network_event.get('source_ip')} -> {network_event.get('dest_ip')}, Score: {probability:.2%}")
        return network_event

# =========================
# Main pipeline
# =========================
def main():
    # Step 1: Fetch IOCs
    fetch_abuseipdb(ABUSEIPDB_API_KEY)
    fetch_urlhaus()
    ip_iocs = load_ip_iocs()
    domain_iocs = load_domain_iocs()

    # Step 2: Load events
    events = []
    with open(EVE_JSON_FILE, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
            except:
                continue
            events.append(event)

    # Step 3: Extract features and labels
    feature_list = [extract_features_from_event(e, ip_iocs, domain_iocs) for e in events]
    df = pd.DataFrame(feature_list)
    df['label'] = ((df['ioc_matches'] > 0) | (df['anomaly_score'] > 0)).astype(int)
    numeric_features = [c for c in df.columns if c != 'label']

    X = df[numeric_features].fillna(0)
    y = df['label']

    # Step 4: Split, balance, scale
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    smote = SMOTE(random_state=42)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_bal)
    X_val_scaled = scaler.transform(X_val)

    # Step 5: Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train_scaled, y_train_bal)
    y_pred_proba = model.predict_proba(X_val_scaled)[:, 1]
    roc_auc = roc_auc_score(y_val, y_pred_proba)
    log(f"[MODEL] Validation ROC-AUC: {roc_auc:.4f}")

    # Step 6: Save ROC curve
    fpr, tpr, _ = roc_curve(y_val, y_pred_proba)
    plt.figure()
    plt.plot(fpr, tpr, color='blue', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0,1],[0,1], color='gray', lw=1, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend(loc="lower right")
    plt.savefig("results/roc_curve.png")
    plt.close()

    # Step 7: Feature visualization
    plt.figure(figsize=(8,6))
    plt.hist(df['anomaly_score'], bins=20, color='red', alpha=0.7)
    plt.title("Anomaly Score Distribution")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Number of Events")
    plt.savefig("results/anomaly_score_distribution.png")
    plt.close()

    fig = px.histogram(df, x="anomaly_score", title="Anomaly Score Distribution")
    fig.write_html("results/anomaly_score_distribution.html")

    # Step 8: Initialize real-time detector
    detector = RealTimeThreatDetector(model, scaler, numeric_features)
    log("[*] Starting real-time monitoring...")

    # Step 9: Real-time monitoring
    for line in tail_f(EVE_JSON_FILE):
        if not line:
            continue
        try:
            event = json.loads(line)
        except:
            continue
        features = extract_features_from_event(event, ip_iocs, domain_iocs)
        detector.analyze_event(features)

        # Save detected threats after each event
        if detector.threat_log:
            pd.DataFrame(detector.threat_log).to_csv(THREAT_CSV, index=False)

    # Step 10: Save model, scaler, features
    joblib.dump(model, 'results/threat_detection_model.pkl')
    joblib.dump(scaler, 'results/feature_scaler.pkl')
    joblib.dump(numeric_features, 'results/feature_columns.pkl')
    log("[+] Model, scaler, and feature columns saved.")
    log("[+] Pipeline completed successfully.")

if __name__ == "__main__":
    main()