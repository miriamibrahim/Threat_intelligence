import subprocess
import json
import csv
import time
import datetime
import joblib
import pandas as pd

# =========================
# Config
# =========================
EVE_JSON_FILE = "/var/log/suricata/eve.json"
RESULTS_DIR = "results"
THREAT_THRESHOLD = 0.3
ALERTS_FILE = f"{RESULTS_DIR}/alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# =========================
# Load ML model
# =========================
model = joblib.load(f"{RESULTS_DIR}/ml_model.pkl")
features = joblib.load(f"{RESULTS_DIR}/features.pkl")

# =========================
# IOC Data
# =========================
MALICIOUS_IPS = ["10.0.0.99", "192.168.1.250", "172.16.0.77"]
MALICIOUS_DOMAINS = ["malware.com", "badsite.net", "evil.org"]

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
    f["is_udp"] = int(event.get("proto","").lower()=="udp")
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
# Real-time detection
# =========================
def real_time_detection():
    total, alerts = 0, 0
    last_alert_time = {}
    with open(ALERTS_FILE, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["timestamp","src_ip","dest_ip","ioc_hits","ml_score"])
        
        # Start subprocess tailing eve.json
        cmd = ["sudo", "tail", "-f", EVE_JSON_FILE]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in proc.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            total += 1
            hits = ioc_match(event)
            ml_score = model.predict_proba(pd.DataFrame([extract_features(event)])[features])[0][1]

            src = event.get("src_ip")
            now = time.time()
            suppress_interval = 5  # seconds between alerts for same src
            if src in last_alert_time and now - last_alert_time[src] < suppress_interval:
                continue

            if hits > 0 or ml_score > THREAT_THRESHOLD:
                alerts += 1
                last_alert_time[src] = now
                writer.writerow([event.get("timestamp"), src, event.get("dest_ip"), hits, round(ml_score,3)])
                out.flush()
                print(f"[ALERT] {event.get('timestamp')} | SRC={src} → DST={event.get('dest_ip')} | IOC={hits} | ML={ml_score:.2f}")

            if total % 100 == 0:
                print(f"[STATS] Events={total} | Alerts={alerts}")

# =========================
# Main
# =========================
if __name__ == "__main__":
    print("[*] Starting REAL Hybrid IDS on Suricata eve.json...")
    real_time_detection()
