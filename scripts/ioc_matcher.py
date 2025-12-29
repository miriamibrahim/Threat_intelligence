import json
import csv
import time
import requests
import os

# =========================
# Configuration
# =========================
EVE_JSON_FILE = "logs/eve.json"       # Suricata output
IP_IOC_FILE = "iocs/abuseipdb_iocs.json"
DOMAIN_IOC_FILE = "iocs/urlhaus_iocs.json"
OUTPUT_FILE = "results/ioc_alerts.csv"
ANOMALY_OUTPUT_FILE = "results/anomalies.csv"
MIN_CONFIDENCE = 50
SLEEP_INTERVAL = 0.5                  # seconds for real-time tail
ABUSEIPDB_API_KEY = "ddb207c93f1d728e7e677e317a4273841ebb8781578032dd234de8292b1a80682f2fbeeb0bcffe69"  # Replace with your AbuseIPDB key

# =========================
# Fetch IOC feeds
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
        print(f"[+] Fetched {len(data['data'])} IP IOCs from AbuseIPDB")
    except Exception as e:
        print(f"[!] Failed to fetch AbuseIPDB: {e}")

def fetch_urlhaus():
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        r = requests.get(url)
        domains = [{"url": line.split(",")[1]} for line in r.text.splitlines() if line]
        os.makedirs(os.path.dirname(DOMAIN_IOC_FILE), exist_ok=True)
        with open(DOMAIN_IOC_FILE, "w") as f:
            json.dump({"data": domains}, f, indent=2)
        print(f"[+] Fetched {len(domains)} domain IOCs from URLHaus")
    except Exception as e:
        print(f"[!] Failed to fetch URLHaus: {e}")

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
# Tail function for real-time monitoring
# =========================
def tail_f(file):
    with open(file, "r") as f:
        f.seek(0, 2)  # go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(SLEEP_INTERVAL)
                continue
            yield line.strip()

# =========================
# Process single event
# =========================
def process_event(event, ip_iocs, domain_iocs):
    matched = {}
    anomaly_score = 0

    # IP matching
    for ip_field in ["src_ip", "dest_ip"]:
        ip = event.get(ip_field)
        if ip and ip in ip_iocs and ip_iocs[ip]["confidence"] >= MIN_CONFIDENCE:
            matched[ip] = ip_iocs[ip]
            anomaly_score += 1

    # Domain matching
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

    # Simple anomaly heuristics
    dest_port = event.get("dest_port")
    if dest_port and dest_port not in [53, 80, 443]:
        anomaly_score += 1
    if event.get("event_type") == "dns" and len(event["dns"].get("answers", [])) > 5:
        anomaly_score += 1

    return matched, anomaly_score

# =========================
# Write alerts
# =========================
def write_alert(alerts):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    fieldnames = [
        "timestamp", "event_type", "src_ip", "dest_ip",
        "matched_ioc", "confidence", "last_seen", "source",
        "anomaly_score", "details"
    ]
    # Write to file
    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        for alert in alerts:
            writer.writerow(alert)

def write_anomaly(event, anomaly_score):
    os.makedirs(os.path.dirname(ANOMALY_OUTPUT_FILE), exist_ok=True)
    fieldnames = ["timestamp", "event_type", "src_ip", "dest_ip", "anomaly_score", "details"]
    if not os.path.exists(ANOMALY_OUTPUT_FILE):
        with open(ANOMALY_OUTPUT_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
    with open(ANOMALY_OUTPUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writerow({
            "timestamp": event.get("timestamp", ""),
            "event_type": event.get("event_type", ""),
            "src_ip": event.get("src_ip", ""),
            "dest_ip": event.get("dest_ip", ""),
            "anomaly_score": anomaly_score,
            "details": json.dumps(event)
        })

# =========================
# Main pipeline
# =========================
def main():
    # Step 1: Fetch IOC feeds
    fetch_abuseipdb(ABUSEIPDB_API_KEY)
    fetch_urlhaus()

    # Step 2: Load IOCs
    ip_iocs = load_ip_iocs()
    domain_iocs = load_domain_iocs()

    # Step 3: Prepare CSVs
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", newline="") as f:
            fieldnames = [
                "timestamp", "event_type", "src_ip", "dest_ip",
                "matched_ioc", "confidence", "last_seen", "source",
                "anomaly_score", "details"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
    if not os.path.exists(ANOMALY_OUTPUT_FILE):
        with open(ANOMALY_OUTPUT_FILE, "w", newline="") as f:
            fieldnames = ["timestamp", "event_type", "src_ip", "dest_ip", "anomaly_score", "details"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

    # Step 4: Process historical events (batch)
    print("[*] Processing existing Suricata logs...")
    with open(EVE_JSON_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            matched, anomaly_score = process_event(event, ip_iocs, domain_iocs)
            if matched:
                alert = {
                    "timestamp": event.get("timestamp", ""),
                    "event_type": event.get("event_type", ""),
                    "src_ip": event.get("src_ip", ""),
                    "dest_ip": event.get("dest_ip", ""),
                    "matched_ioc": ";".join(matched.keys()),
                    "confidence": ";".join(str(v["confidence"]) for v in matched.values()),
                    "last_seen": ";".join(v["last_seen"] for v in matched.values()),
                    "source": ";".join(v["source"] for v in matched.values()),
                    "anomaly_score": anomaly_score,
                    "details": json.dumps(event)
                }
                write_alert([alert])
                print(f"[!] IOC Alert: {alert['matched_ioc']} | Anomaly Score: {anomaly_score}")

            if anomaly_score > 0:
                write_anomaly(event, anomaly_score)
                print(f"[!] Anomaly detected: Score {anomaly_score} | Event: {event.get('event_type')}")

    # Step 5: Real-time monitoring
    print("[*] Starting real-time monitoring...")
    for line in tail_f(EVE_JSON_FILE):
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        matched, anomaly_score = process_event(event, ip_iocs, domain_iocs)

        if matched:
            alert = {
                "timestamp": event.get("timestamp", ""),
                "event_type": event.get("event_type", ""),
                "src_ip": event.get("src_ip", ""),
                "dest_ip": event.get("dest_ip", ""),
                "matched_ioc": ";".join(matched.keys()),
                "confidence": ";".join(str(v["confidence"]) for v in matched.values()),
                "last_seen": ";".join(v["last_seen"] for v in matched.values()),
                "source": ";".join(v["source"] for v in matched.values()),
                "anomaly_score": anomaly_score,
                "details": json.dumps(event)
            }
            write_alert([alert])
            print(f"[!] IOC Alert: {alert['matched_ioc']} | Anomaly Score: {anomaly_score}")

        if anomaly_score > 0:
            write_anomaly(event, anomaly_score)
            print(f"[!] Anomaly detected: Score {anomaly_score} | Event: {event.get('event_type')}")

if __name__ == "__main__":
    main()
