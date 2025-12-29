import json
import csv
import time
import os
import signal
import requests
import pandas as pd
import numpy as np
import warnings
import joblib
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, roc_curve
from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")

# =========================
# Configuration
# =========================
EVE_JSON_FILE = "logs/eve.json"
IP_IOC_FILE = "iocs/abuseipdb_iocs.json"
DOMAIN_IOC_FILE = "iocs/urlhaus_iocs.json"
RESULTS_DIR = "results"
LOG_FILE = f"{RESULTS_DIR}/pipeline_log.txt"
THREAT_CSV = f"{RESULTS_DIR}/threats_detected.csv"

MIN_CONFIDENCE = 50
SLEEP_INTERVAL = 0.5
THREAT_THRESHOLD = 0.7
VERBOSE = True

ABUSEIPDB_API_KEY = "ddb207c93f1d728e7e677e317a4273841ebb8781578032dd234de8292b1a80682f2fbeeb0bcffe69"

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs("iocs", exist_ok=True)

RUNNING = True

# =========================
# Logger
# =========================
def log(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

# =========================
# Pretty Event Printer
# =========================
def print_event_status(event, features, prob, is_threat):
    src = event.get("src_ip", "N/A")
    dst = event.get("dest_ip", "N/A")
    etype = event.get("event_type", "unknown")

    status = "🚨 THREAT" if is_threat else "✅ OK"

    print(
        f"[EVENT] {etype.upper():6} | "
        f"{src:15} -> {dst:15} | "
        f"IOC={features['ioc_hits']} | "
        f"ANOM={features['anomaly_score']} | "
        f"ML={prob:.3f} | {status}"
    )

# =========================
# Graceful Exit
# =========================
def stop_pipeline(sig, frame):
    global RUNNING
    RUNNING = False
    log("[!] Stopping pipeline safely...")

signal.signal(signal.SIGINT, stop_pipeline)

# =========================
# IOC Fetching
# =========================
def fetch_abuseipdb():
    if not ABUSEIPDB_API_KEY:
        log("[!] ABUSEIPDB_API_KEY not set – skipping fetch.")
        return

    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=50"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        with open(IP_IOC_FILE, "w") as f:
            json.dump(data, f, indent=2)
        log(f"[+] Fetched {len(data.get('data', []))} IP IOCs")
    except Exception as e:
        log(f"[!] AbuseIPDB fetch failed: {e}")

def fetch_urlhaus():
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"

    try:
        r = requests.get(url, timeout=10)
        reader = csv.DictReader(r.text.splitlines())
        domains = [{"domain": row["url"].lower()} for row in reader if row.get("url")]

        with open(DOMAIN_IOC_FILE, "w") as f:
            json.dump({"data": domains}, f, indent=2)

        log(f"[+] Fetched {len(domains)} URLHaus IOCs")
    except Exception as e:
        log(f"[!] URLHaus fetch failed: {e}")

# =========================
# Load IOCs
# =========================
def load_ip_iocs():
    try:
        with open(IP_IOC_FILE) as f:
            data = json.load(f)
    except:
        return {}

    return {
        e["ipAddress"]: {
            "confidence": e.get("abuseConfidenceScore", 0),
            "source": "AbuseIPDB"
        }
        for e in data.get("data", [])
        if "ipAddress" in e
    }

def load_domain_iocs():
    try:
        with open(DOMAIN_IOC_FILE) as f:
            data = json.load(f)
    except:
        return {}

    return {
        e["domain"]: {"confidence": 100, "source": "URLHaus"}
        for e in data.get("data", [])
        if "domain" in e
    }

# =========================
# Tail file
# =========================
def tail_f(path):
    with open(path, "r") as f:
        f.seek(0, 2)
        while RUNNING:
            line = f.readline()
            if not line:
                time.sleep(SLEEP_INTERVAL)
                continue
            yield line.strip()

# =========================
# Event Processing
# =========================
def process_event(event, ip_iocs, domain_iocs):
    ioc_hits = 0
    anomaly_score = 0

    for field in ["src_ip", "dest_ip"]:
        ip = event.get(field)
        if ip and ip in ip_iocs and ip_iocs[ip]["confidence"] >= MIN_CONFIDENCE:
            ioc_hits += 1

    if event.get("event_type") == "dns":
        query = event.get("dns", {}).get("rrname", "").lower()
        if query in domain_iocs:
            ioc_hits += 1

    dest_port = event.get("dest_port", 0)
    if dest_port not in [53, 80, 443, 22]:
        anomaly_score += 1

    return ioc_hits, anomaly_score

# =========================
# Feature Extraction
# =========================
def extract_features(event, ip_iocs, domain_iocs):
    ioc_hits, anomaly_score = process_event(event, ip_iocs, domain_iocs)

    features = {
        "duration": event.get("duration", 0),
        "tx_bytes": event.get("tx_bytes", 0),
        "rx_bytes": event.get("rx_bytes", 0),
        "pkts_sent": event.get("pkts_sent", 0),
        "pkts_received": event.get("pkts_received", 0),
    }

    features["total_bytes"] = features["tx_bytes"] + features["rx_bytes"]
    features["total_packets"] = features["pkts_sent"] + features["pkts_received"]
    features["bytes_per_packet"] = features["total_bytes"] / (features["total_packets"] + 1)

    proto = event.get("proto", "").lower()
    features["is_tcp"] = int(proto == "tcp")
    features["is_udp"] = int(proto == "udp")
    features["is_icmp"] = int(proto == "icmp")

    features["ioc_hits"] = ioc_hits
    features["anomaly_score"] = anomaly_score

    return features

# =========================
# Real-Time Detector
# =========================
class RealTimeDetector:
    def __init__(self, model, feature_cols):
        self.model = model
        self.feature_cols = feature_cols
        self.threats = []

    def analyze(self, event, features):
        df = pd.DataFrame([features])[self.feature_cols]
        prob = self.model.predict_proba(df)[0][1]
        is_threat = prob >= THREAT_THRESHOLD

        if VERBOSE:
            print_event_status(event, features, prob, is_threat)

        if is_threat:
            threat = {
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "confidence": prob,
                "ioc_hits": features["ioc_hits"],
                "anomaly_score": features["anomaly_score"]
            }
            self.threats.append(threat)
            log(f"[THREAT] {threat}")

# =========================
# Main Pipeline
# =========================
def main():
    
    log("[*] Starting Hybrid IDS Pipeline")

    fetch_abuseipdb()
    fetch_urlhaus()

    ip_iocs = load_ip_iocs()
    domain_iocs = load_domain_iocs()

    events = []
    with open(EVE_JSON_FILE) as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                pass

    features = [extract_features(e, ip_iocs, domain_iocs) for e in events]
    df = pd.DataFrame(features)

    df["pseudo_label"] = ((df["ioc_hits"] > 0) | (df["anomaly_score"] > 0)).astype(int)

    X = df.drop(columns=["pseudo_label"])
    y = df["pseudo_label"]

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, stratify=y, test_size=0.2, random_state=42
    )

    X_train, y_train = SMOTE(random_state=42).fit_resample(X_train, y_train)

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    val_probs = model.predict_proba(X_val)[:, 1]
    roc_auc = roc_auc_score(y_val, val_probs)
    log(f"[MODEL] ROC-AUC: {roc_auc:.4f}")

    fpr, tpr, _ = roc_curve(y_val, val_probs)
    plt.plot(fpr, tpr)
    plt.savefig(f"{RESULTS_DIR}/roc_curve.png")
    plt.close()

    joblib.dump(model, f"{RESULTS_DIR}/rf_model.pkl")
    joblib.dump(list(X.columns), f"{RESULTS_DIR}/features.pkl")

    detector = RealTimeDetector(model, list(X.columns))

    log("[*] Real-time monitoring started")
    log("[*] Press Ctrl+C to stop")

    for line in tail_f(EVE_JSON_FILE):
        try:
            event = json.loads(line)
            feats = extract_features(event, ip_iocs, domain_iocs)
            detector.analyze(event, feats)

            if detector.threats:
                pd.DataFrame(detector.threats).to_csv(THREAT_CSV, index=False)
        except:
            continue

    log("[+] Pipeline stopped")

if __name__ == "__main__":
    main()
