import json
import csv
import os
import time
import ipaddress
import pandas as pd
import joblib
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
import warnings
import datetime

warnings.filterwarnings("ignore")

# =========================
# Config
# =========================
EVE_JSON_FILE = "logs/eve.json"   # Can be real Suricata logs
RESULTS_DIR = "results"
MODEL_FILE = f"{RESULTS_DIR}/ml_model.pkl"
FEATURES_FILE = f"{RESULTS_DIR}/features.pkl"
THREAT_THRESHOLD = 0.3
os.makedirs(RESULTS_DIR, exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
ALERTS_FILE = f"{RESULTS_DIR}/alerts_{timestamp}.csv"

# =========================
# Synthetic IOC Data
# =========================
MALICIOUS_IPS = ["10.0.0.99", "192.168.1.250", "172.16.0.77"]
BENIGN_IPS = ["10.0.0.1", "192.168.1.10", "172.16.0.5"]
MALICIOUS_DOMAINS = ["malware.com", "badsite.net", "evil.org"]
BENIGN_DOMAINS = ["example.com", "goodsite.org", "mysite.net"]

# =========================
# Event generation
# =========================
NUM_EVENTS = 1000

def random_tcp_flags():
    return {"syn": random.choice([True, False]),
            "ack": random.choice([True, False]),
            "rst": random.choice([True, False])}

def random_udp_features():
    return {"len_invalid": random.randint(0,5)}

def generate_event(malicious=False):
    event_type = random.choices(["dns","alert","flow"], weights=[0.4,0.1,0.5])[0]
    proto = random.choice(["tcp","udp"])
    if malicious:
        src_ip = random.choice(MALICIOUS_IPS)
        dest_ip = random.choice(MALICIOUS_IPS)
        domain = random.choice(MALICIOUS_DOMAINS)
    else:
        src_ip = random.choice(BENIGN_IPS)
        dest_ip = random.choice(BENIGN_IPS)
        domain = random.choice(BENIGN_DOMAINS)

    dest_port = random.choice([53,80,443,1234,8080,9999])
    
    flow = {"pkts_toserver": random.randint(0,20),
            "pkts_toclient": random.randint(0,20),
            "bytes_toserver": random.randint(0,5000),
            "bytes_toclient": random.randint(0,5000),
            "tcp": random_tcp_flags() if proto=="tcp" else {},
            "udp": random_udp_features() if proto=="udp" else {}}
    
    dns = {}
    if event_type=="dns":
        dns = {"rrname": domain,
               "rrtype": random.choice(["A","AAAA","HTTPS"]),
               "answers": [domain] if random.random()<0.7 else []}
    
    return {"timestamp": datetime.datetime.now().isoformat(),
            "event_type": event_type,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "proto": proto,
            "dest_port": dest_port,
            "flow": flow,
            "dns": dns}

# Generate events with occasional malicious bursts
events = []
for _ in range(NUM_EVENTS):
    malicious = random.random() < 0.15  # 15% chance
    event = generate_event(malicious)
    events.append(event)
    # Malicious burst: 2-5 events from same host
    if malicious and random.random() < 0.3:
        for _ in range(random.randint(2,5)):
            burst_event = generate_event(malicious=True)
            burst_event["src_ip"] = event["src_ip"]
            burst_event["dest_ip"] = random.choice(MALICIOUS_IPS + BENIGN_IPS)
            events.append(burst_event)

# =========================
# Feature extraction
# =========================
def extract_features(event):
    flow = event.get("flow", {})
    tcp = flow.get("tcp", {})
    udp = flow.get("udp", {})
    f = {}
    f["is_dns"] = int(event.get("event_type")=="dns")
    f["is_alert"] = int(event.get("event_type")=="alert")
    f["is_udp"] = int(str(event.get("proto","")).lower()=="udp")
    f["pkts_toserver"] = flow.get("pkts_toserver",0)
    f["pkts_toclient"] = flow.get("pkts_toclient",0)
    f["bytes_toserver"] = flow.get("bytes_toserver",0)
    f["bytes_toclient"] = flow.get("bytes_toclient",0)
    f["tcp_syn"] = int(tcp.get("syn",False))
    f["tcp_ack"] = int(tcp.get("ack",False))
    f["tcp_rst"] = int(tcp.get("rst",False))
    f["udp_len_invalid"] = udp.get("len_invalid",0)
    f["dest_port"] = event.get("dest_port",0)
    f["suspicious_port"] = int(f["dest_port"] not in [53,80,443])
    dns = event.get("dns",{})
    f["dns_answer_count"] = len(dns.get("answers",[]))
    f["dns_rrtype_A"] = int(dns.get("rrtype")=="A")
    f["dns_rrtype_HTTPS"] = int(dns.get("rrtype")=="HTTPS")
    return f

def ioc_match(event):
    hits = 0
    for ip in [event.get("src_ip"), event.get("dest_ip")]:
        if ip in MALICIOUS_IPS:
            hits += 1
    if event.get("event_type")=="dns" and event.get("dns",{}).get("rrname","") in MALICIOUS_DOMAINS:
        hits += 1
    return hits

# =========================
# Train ML model
# =========================
rows = []
for e in events:
    f = extract_features(e)
    f["label"] = int(ioc_match(e)>0 or e.get("event_type")=="alert")
    rows.append(f)

df = pd.DataFrame(rows).fillna(0)
X = df.drop(columns=["label"])
y = df["label"]

print("[+] Synthetic label distribution:")
print(y.value_counts())

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
model = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
auc = roc_auc_score(y_test, model.predict_proba(X_test)[:,1])
print(f"[+] ROC-AUC on synthetic data: {auc:.4f}")

joblib.dump(model, MODEL_FILE)
joblib.dump(list(X.columns), FEATURES_FILE)

# =========================
# Real-time detection with suppression
# =========================
def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def real_time_detection(model, features):
    total, alerts = 0, 0
    last_alert_time = {}
    with open(ALERTS_FILE,"w",newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["timestamp","src_ip","dest_ip","ioc_hits","ml_score"])
        with open(EVE_JSON_FILE) as log:
            for line in follow(log):
                try:
                    event = json.loads(line)
                except:
                    continue
                total += 1
                hits = ioc_match(event)
                ml_score = model.predict_proba(pd.DataFrame([extract_features(event)])[features])[0][1]
                
                src = event.get("src_ip")
                now = time.time()
                suppress_interval = 5  # seconds between alerts for same src
                if src in last_alert_time and now - last_alert_time[src] < suppress_interval:
                    continue  # suppress repetitive alert
                
                if hits>0 or ml_score>THREAT_THRESHOLD:
                    alerts += 1
                    last_alert_time[src] = now
                    writer.writerow([event.get("timestamp"),src,event.get("dest_ip"),hits,round(ml_score,3)])
                    out.flush()
                    print(f"[ALERT] {event.get('timestamp')} | SRC={src} → DST={event.get('dest_ip')} | IOC={hits} | ML={ml_score:.2f}")
                
                if total%100==0:
                    print(f"[STATS] Events={total} | Alerts={alerts}")

# =========================
# Main
# =========================
if __name__=="__main__":
    print("[*] Starting REAL Hybrid IDS (synthetic + real logs)")
    real_time_detection(model, list(X.columns))
import json
import csv
import os
import time
import ipaddress
import pandas as pd
import joblib
import random
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
import warnings
import datetime

warnings.filterwarnings("ignore")

# =========================
# Config
# =========================
EVE_JSON_FILE = "logs/eve.json"   # Can be real Suricata logs
RESULTS_DIR = "results"
MODEL_FILE = f"{RESULTS_DIR}/ml_model.pkl"
FEATURES_FILE = f"{RESULTS_DIR}/features.pkl"
THREAT_THRESHOLD = 0.3
os.makedirs(RESULTS_DIR, exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
ALERTS_FILE = f"{RESULTS_DIR}/alerts_{timestamp}.csv"

# =========================
# Synthetic IOC Data
# =========================
MALICIOUS_IPS = ["10.0.0.99", "192.168.1.250", "172.16.0.77"]
BENIGN_IPS = ["10.0.0.1", "192.168.1.10", "172.16.0.5"]
MALICIOUS_DOMAINS = ["malware.com", "badsite.net", "evil.org"]
BENIGN_DOMAINS = ["example.com", "goodsite.org", "mysite.net"]

# =========================
# Event generation
# =========================
NUM_EVENTS = 1000

def random_tcp_flags():
    return {"syn": random.choice([True, False]),
            "ack": random.choice([True, False]),
            "rst": random.choice([True, False])}

def random_udp_features():
    return {"len_invalid": random.randint(0,5)}

def generate_event(malicious=False):
    event_type = random.choices(["dns","alert","flow"], weights=[0.4,0.1,0.5])[0]
    proto = random.choice(["tcp","udp"])
    if malicious:
        src_ip = random.choice(MALICIOUS_IPS)
        dest_ip = random.choice(MALICIOUS_IPS)
        domain = random.choice(MALICIOUS_DOMAINS)
    else:
        src_ip = random.choice(BENIGN_IPS)
        dest_ip = random.choice(BENIGN_IPS)
        domain = random.choice(BENIGN_DOMAINS)

    dest_port = random.choice([53,80,443,1234,8080,9999])
    
    flow = {"pkts_toserver": random.randint(0,20),
            "pkts_toclient": random.randint(0,20),
            "bytes_toserver": random.randint(0,5000),
            "bytes_toclient": random.randint(0,5000),
            "tcp": random_tcp_flags() if proto=="tcp" else {},
            "udp": random_udp_features() if proto=="udp" else {}}
    
    dns = {}
    if event_type=="dns":
        dns = {"rrname": domain,
               "rrtype": random.choice(["A","AAAA","HTTPS"]),
               "answers": [domain] if random.random()<0.7 else []}
    
    return {"timestamp": datetime.datetime.now().isoformat(),
            "event_type": event_type,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "proto": proto,
            "dest_port": dest_port,
            "flow": flow,
            "dns": dns}

# Generate events with occasional malicious bursts
events = []
for _ in range(NUM_EVENTS):
    malicious = random.random() < 0.15  # 15% chance
    event = generate_event(malicious)
    events.append(event)
    # Malicious burst: 2-5 events from same host
    if malicious and random.random() < 0.3:
        for _ in range(random.randint(2,5)):
            burst_event = generate_event(malicious=True)
            burst_event["src_ip"] = event["src_ip"]
            burst_event["dest_ip"] = random.choice(MALICIOUS_IPS + BENIGN_IPS)
            events.append(burst_event)

# =========================
# Feature extraction
# =========================
def extract_features(event):
    flow = event.get("flow", {})
    tcp = flow.get("tcp", {})
    udp = flow.get("udp", {})
    f = {}
    f["is_dns"] = int(event.get("event_type")=="dns")
    f["is_alert"] = int(event.get("event_type")=="alert")
    f["is_udp"] = int(str(event.get("proto","")).lower()=="udp")
    f["pkts_toserver"] = flow.get("pkts_toserver",0)
    f["pkts_toclient"] = flow.get("pkts_toclient",0)
    f["bytes_toserver"] = flow.get("bytes_toserver",0)
    f["bytes_toclient"] = flow.get("bytes_toclient",0)
    f["tcp_syn"] = int(tcp.get("syn",False))
    f["tcp_ack"] = int(tcp.get("ack",False))
    f["tcp_rst"] = int(tcp.get("rst",False))
    f["udp_len_invalid"] = udp.get("len_invalid",0)
    f["dest_port"] = event.get("dest_port",0)
    f["suspicious_port"] = int(f["dest_port"] not in [53,80,443])
    dns = event.get("dns",{})
    f["dns_answer_count"] = len(dns.get("answers",[]))
    f["dns_rrtype_A"] = int(dns.get("rrtype")=="A")
    f["dns_rrtype_HTTPS"] = int(dns.get("rrtype")=="HTTPS")
    return f

def ioc_match(event):
    hits = 0
    for ip in [event.get("src_ip"), event.get("dest_ip")]:
        if ip in MALICIOUS_IPS:
            hits += 1
    if event.get("event_type")=="dns" and event.get("dns",{}).get("rrname","") in MALICIOUS_DOMAINS:
        hits += 1
    return hits

# =========================
# Train ML model
# =========================
rows = []
for e in events:
    f = extract_features(e)
    f["label"] = int(ioc_match(e)>0 or e.get("event_type")=="alert")
    rows.append(f)

df = pd.DataFrame(rows).fillna(0)
X = df.drop(columns=["label"])
y = df["label"]

print("[+] Synthetic label distribution:")
print(y.value_counts())

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
model = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
auc = roc_auc_score(y_test, model.predict_proba(X_test)[:,1])
print(f"[+] ROC-AUC on synthetic data: {auc:.4f}")

joblib.dump(model, MODEL_FILE)
joblib.dump(list(X.columns), FEATURES_FILE)

# =========================
# Real-time detection with suppression
# =========================
def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def real_time_detection(model, features):
    total, alerts = 0, 0
    last_alert_time = {}
    with open(ALERTS_FILE,"w",newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["timestamp","src_ip","dest_ip","ioc_hits","ml_score"])
        with open(EVE_JSON_FILE) as log:
            for line in follow(log):
                try:
                    event = json.loads(line)
                except:
                    continue
                total += 1
                hits = ioc_match(event)
                ml_score = model.predict_proba(pd.DataFrame([extract_features(event)])[features])[0][1]
                
                src = event.get("src_ip")
                now = time.time()
                suppress_interval = 5  # seconds between alerts for same src
                if src in last_alert_time and now - last_alert_time[src] < suppress_interval:
                    continue  # suppress repetitive alert
                
                if hits>0 or ml_score>THREAT_THRESHOLD:
                    alerts += 1
                    last_alert_time[src] = now
                    writer.writerow([event.get("timestamp"),src,event.get("dest_ip"),hits,round(ml_score,3)])
                    out.flush()
                    print(f"[ALERT] {event.get('timestamp')} | SRC={src} → DST={event.get('dest_ip')} | IOC={hits} | ML={ml_score:.2f}")
                
                if total%100==0:
                    print(f"[STATS] Events={total} | Alerts={alerts}")

# =========================
# Main
# =========================
if __name__=="__main__":
    print("[*] Starting REAL Hybrid IDS (synthetic + real logs)")
    real_time_detection(model, list(X.columns))
