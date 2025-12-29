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

warnings.filterwarnings("ignore")

# =========================
# Config
# =========================
EVE_JSON_FILE = "logs/eve.json"

# FireHOL blocklist (NO API LIMITS)
IP_BLOCKLIST_FILE = "iocs/firehol_level1.netset"
DOMAIN_IOC_FILE = "iocs/urlhaus_iocs.json"

RESULTS_DIR = "results"
MODEL_FILE = f"{RESULTS_DIR}/ml_model.pkl"
FEATURES_FILE = f"{RESULTS_DIR}/features.pkl"
ALERTS_FILE = f"{RESULTS_DIR}/final_alerts.csv"

THREAT_THRESHOLD = 0.3

os.makedirs(RESULTS_DIR, exist_ok=True)

# =========================
# IOC Loading
# =========================
def load_ip_iocs():
    """
    Loads FireHOL IPs and CIDR ranges
    """
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

    print(f"[+] Loaded {len(nets)} IP/CIDR IOCs from FireHOL")
    return nets


def load_domain_iocs():
    try:
        with open(DOMAIN_IOC_FILE) as f:
            data = json.load(f)
    except:
        data = {"data": []}

    domains = set()
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
# Load Historical Events
# =========================
def load_events():
    events = []
    with open(EVE_JSON_FILE) as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                continue

    print(f"[+] Loaded {len(events)} historical events")
    return events


# =========================
# Train ML Model (Weak Supervision)
# =========================
def train_model(events, ip_iocs, domain_iocs):
    rows = []

    for e in events:
        feat = extract_features(e)
        feat["label"] = int(ioc_match(e, ip_iocs, domain_iocs) > 0)
        rows.append(feat)

    df = pd.DataFrame(rows).fillna(0)

    X = df.drop(columns=["label"])
    y = df["label"]

    print("[+] Label distribution:")
    print(y.value_counts())

    if y.value_counts().min() < 5:
        print("[!] Not enough positives → ML disabled (IOC-only mode)")
        return None, None

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight={0: 1, 1: 5},
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    auc = roc_auc_score(y_val, model.predict_proba(X_val)[:, 1])
    print(f"[+] ROC-AUC (IOC-supervised): {auc:.4f}")

    joblib.dump(model, MODEL_FILE)
    joblib.dump(list(X.columns), FEATURES_FILE)

    return model, list(X.columns)


# =========================
# REAL-TIME FILE FOLLOW
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
# REAL IDS MONITORING
# =========================
def real_time_detection(model, features, ip_iocs, domain_iocs):
    print("[*] REAL IDS RUNNING — LIVE TRAFFIC MODE")
    print("[*] Tailing eve.json...\n")

    total = 0
    alerts = 0

    with open(ALERTS_FILE, "a", newline="") as out:
        writer = csv.writer(out)

        if os.stat(ALERTS_FILE).st_size == 0:
            writer.writerow(["timestamp", "src_ip", "dest_ip", "ioc_hits", "ml_score"])

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

                    print(
                        f"[ALERT] {event.get('timestamp')} | "
                        f"SRC={event.get('src_ip')} → DST={event.get('dest_ip')} | "
                        f"IOC={ioc_hits} | ML={ml_score:.2f}"
                    )

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