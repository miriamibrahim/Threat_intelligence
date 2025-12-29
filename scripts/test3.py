import json
import csv
import os
import time
import ipaddress
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
import warnings
import datetime

warnings.filterwarnings("ignore")

# =========================
# Config
# =========================
EVE_JSON_FILE = "logs/eve.json"
IP_BLOCKLIST_FILE = "iocs/firehol_level1.netset"
DOMAIN_IOC_FILE = "iocs/urlhaus_iocs.json"

RESULTS_DIR = "results"
MODEL_FILE = f"{RESULTS_DIR}/ml_model.pkl"
FEATURES_FILE = f"{RESULTS_DIR}/features.pkl"

THREAT_THRESHOLD = 0.3
os.makedirs(RESULTS_DIR, exist_ok=True)

# New alerts file with timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
ALERTS_FILE = f"{RESULTS_DIR}/alerts_{timestamp}.csv"

# =========================
# Load IOCs
# =========================
def load_ip_iocs():
    nets = []
    try:
        with open(IP_BLOCKLIST_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        nets.append(ipaddress.ip_network(line))
                    except:
                        continue
    except FileNotFoundError:
        print("[!] FireHOL blocklist not found")
        return []
    print(f"[+] Loaded {len(nets)} IP/CIDR IOCs")
    return nets

def load_domain_iocs():
    domains = set()
    try:
        with open(DOMAIN_IOC_FILE) as f:
            data = json.load(f)
    except:
        data = {"data": []}

    for e in data.get("data", []):
        url = e.get("url")
        if url:
            domains.add(url.lower())

    print(f"[+] Loaded {len(domains)} domain IOCs")
    return domains

# =========================
# IOC Matching
# =========================
def ip_in_iocs(ip, nets):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in nets:
            if ip_obj in net:
                return True
    except:
        return False
    return False

def ioc_match(event, ip_iocs, domain_iocs):
    hits = 0
    for field in ["src_ip", "dest_ip"]:
        ip = event.get(field)
        if ip and ip_in_iocs(ip, ip_iocs):
            hits += 1

    if event.get("event_type") == "dns":
        q = event.get("dns", {}).get("rrname", "").lower()
        for d in domain_iocs:
            if q.endswith(d):
                hits += 1
                break
    return hits

# =========================
# Feature Extraction
# =========================
def extract_features(event):
    flow = event.get("flow", {})
    tcp = flow.get("tcp", {})
    udp = flow.get("udp", {})

    f = {}
    # Event type
    f["is_dns"] = int(event.get("event_type") == "dns")
    f["is_alert"] = int(event.get("event_type") == "alert")
    f["is_udp"] = int(str(event.get("proto", "")).lower() == "udp")

    # Flow features
    f["pkts_toserver"] = flow.get("pkts_toserver", 0)
    f["pkts_toclient"] = flow.get("pkts_toclient", 0)
    f["bytes_toserver"] = flow.get("bytes_toserver", 0)
    f["bytes_toclient"] = flow.get("bytes_toclient", 0)

    # TCP flags
    f["tcp_syn"] = int(tcp.get("syn", False))
    f["tcp_ack"] = int(tcp.get("ack", False))
    f["tcp_rst"] = int(tcp.get("rst", False))

    # UDP
    f["udp_len_invalid"] = udp.get("len_invalid", 0)

    # Ports
    f["dest_port"] = event.get("dest_port", 0)
    f["suspicious_port"] = int(f["dest_port"] not in [53, 80, 443])

    # DNS
    dns = event.get("dns", {})
    f["dns_answer_count"] = len(dns.get("answers", []))
    f["dns_rrtype_A"] = int(dns.get("rrtype") == "A")
    f["dns_rrtype_HTTPS"] = int(dns.get("rrtype") == "HTTPS")

    return f

# =========================
# Load events
# =========================
def load_events():
    events = []
    with open(EVE_JSON_FILE) as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                continue
    print(f"[+] Loaded {len(events)} events from eve.json")
    return events

# =========================
# Train ML Model
# =========================
def train_model(events, ip_iocs, domain_iocs):
    rows = []
    for e in events:
        feat = extract_features(e)
        # Hybrid label: IOC hit OR Suricata alert
        feat["label"] = int(ioc_match(e, ip_iocs, domain_iocs) > 0 or e.get("event_type") == "alert")
        rows.append(feat)

    df = pd.DataFrame(rows).fillna(0)
    X = df.drop(columns=["label"])
    y = df["label"]

    print("[+] Label distribution:")
    print(y.value_counts())

    if y.value_counts().min() < 5:
        print("[!] Not enough positives → ML disabled (IOC-only mode)")
        return None, list(X.columns)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)
    auc = roc_auc_score(y_val, model.predict_proba(X_val)[:, 1])
    print(f"[+] ROC-AUC: {auc:.4f}")

    joblib.dump(model, MODEL_FILE)
    joblib.dump(list(X.columns), FEATURES_FILE)

    return model, list(X.columns)

# =========================
# Real-time file follow
# =========================
def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

# =========================
# Real-time detection
# =========================
def real_time_detection(model, features, ip_iocs, domain_iocs):
    print("[*] REAL IDS RUNNING — LIVE TRAFFIC MODE")
    print(f"[*] Writing alerts to {ALERTS_FILE}\n")

    total, alerts = 0, 0

    with open(ALERTS_FILE, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["timestamp", "src_ip", "dest_ip", "ioc_hits", "ml_score"])

        # --- Process existing events first ---
        with open(EVE_JSON_FILE) as log:
            for line in log:
                try:
                    event = json.loads(line)
                except:
                    continue

                total += 1
                ioc_hits = ioc_match(event, ip_iocs, domain_iocs)
                ml_score = 0.0
                if model is not None:
                    feat = extract_features(event)
                    X = pd.DataFrame([feat])[features]
                    ml_score = model.predict_proba(X)[0][1]

                if ioc_hits > 0 or ml_score > THREAT_THRESHOLD:
                    alerts += 1
                    writer.writerow([
                        event.get("timestamp"),
                        event.get("src_ip"),
                        event.get("dest_ip"),
                        ioc_hits,
                        round(ml_score, 3)
                    ])
                    out.flush()
                    print(f"[ALERT] {event.get('timestamp')} | SRC={event.get('src_ip')} → DST={event.get('dest_ip')} | IOC={ioc_hits} | ML={ml_score:.2f}")

        # --- Then follow new events in real-time ---
        with open(EVE_JSON_FILE) as log:
            for line in follow(log):
                try:
                    event = json.loads(line)
                except:
                    continue

                total += 1
                ioc_hits = ioc_match(event, ip_iocs, domain_iocs)
                ml_score = 0.0
                if model is not None:
                    feat = extract_features(event)
                    X = pd.DataFrame([feat])[features]
                    ml_score = model.predict_proba(X)[0][1]

                if ioc_hits > 0 or ml_score > THREAT_THRESHOLD:
                    alerts += 1
                    writer.writerow([
                        event.get("timestamp"),
                        event.get("src_ip"),
                        event.get("dest_ip"),
                        ioc_hits,
                        round(ml_score, 3)
                    ])
                    out.flush()
                    print(f"[ALERT] {event.get('timestamp')} | SRC={event.get('src_ip')} → DST={event.get('dest_ip')} | IOC={ioc_hits} | ML={ml_score:.2f}")

                if total % 100 == 0:
                    print(f"[STATS] Events={total} | Alerts={alerts}")

# =========================
# Main
# =========================
def main():
    print("[*] Starting REAL Hybrid IDS")
    ip_iocs = load_ip_iocs()
    domain_iocs = load_domain_iocs()
    events = load_events()
    model, features = train_model(events, ip_iocs, domain_iocs)
    real_time_detection(model, features, ip_iocs, domain_iocs)

if __name__ == "__main__":
    main()
