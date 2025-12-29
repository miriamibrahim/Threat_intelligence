import json, time

EVE = "/var/log/suricata/eve.json"

print("[*] Live IDS started...")

with open(EVE, "r") as f:
    f.seek(0, 2)  # jump to end
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue

        event = json.loads(line)

        if event.get("event_type") == "alert":
            alert = event["alert"]
            print("\n🚨 ALERT DETECTED")
            print("Signature:", alert["signature"])
            print("Category:", alert["category"])
            print("Severity:", alert["severity"])
