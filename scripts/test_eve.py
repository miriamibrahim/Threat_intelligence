import json
import random
from datetime import datetime, timedelta

# Generate synthetic Suricata events
events = []
num_normal = 20
num_alerts = 5

base_time = datetime.now()

# Normal events
for i in range(num_normal):
    event = {
        "timestamp": (base_time + timedelta(seconds=i)).isoformat(),
        "event_type": random.choice(["flow", "dns"]),
        "src_ip": f"10.0.0.{random.randint(1,50)}",
        "dest_ip": f"192.168.1.{random.randint(1,50)}",
        "src_port": random.randint(1024, 5000),
        "dest_port": random.randint(80, 443),
        "proto": random.choice(["TCP", "UDP"]),
        "flow": {
            "pkts_toserver": random.randint(1,10),
            "pkts_toclient": random.randint(1,10),
            "bytes_toserver": random.randint(50,500),
            "bytes_toclient": random.randint(50,500),
            "tcp": {"syn": bool(random.getrandbits(1)),
                    "ack": bool(random.getrandbits(1)),
                    "rst": bool(random.getrandbits(1))},
            "udp": {"len_invalid": 0},
            "state": "ESTABLISHED"
        }
    }
    events.append(event)

# Alert events
for i in range(num_alerts):
    event = {
        "timestamp": (base_time + timedelta(seconds=num_normal+i)).isoformat(),
        "event_type": "alert",
        "src_ip": f"10.0.0.{random.randint(1,50)}",
        "dest_ip": f"192.168.1.{random.randint(1,50)}",
        "src_port": random.randint(1024, 5000),
        "dest_port": random.randint(80, 443),
        "proto": random.choice(["TCP", "UDP"]),
        "flow": {
            "pkts_toserver": random.randint(1,10),
            "pkts_toclient": random.randint(1,10),
            "bytes_toserver": random.randint(50,500),
            "bytes_toclient": random.randint(50,500),
            "tcp": {"syn": bool(random.getrandbits(1)),
                    "ack": bool(random.getrandbits(1)),
                    "rst": bool(random.getrandbits(1))},
            "udp": {"len_invalid": 0},
            "state": "ESTABLISHED"
        },
        "alert": {
            "signature": "TEST-ALERT",
            "category": "Attempted Attack",
            "severity": 2
        }
    }
    events.append(event)

# Save to file
with open("logs/sample_eve.json", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print("Sample eve.json created with", num_normal, "normal and", num_alerts, "alert events.")
