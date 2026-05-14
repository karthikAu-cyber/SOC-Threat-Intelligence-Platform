import json
import urllib.request
from datetime import datetime, timezone

ES_URL = "http://localhost:9200"

log_files = [
    ("/var/log/nginx/access.log",   "nginx-logs",  "nginx-access"),
    ("/var/log/nginx/error.log",    "nginx-logs",  "nginx-error"),
    ("/var/log/dpkg.log",           "dpkg-logs",   "dpkg"),
    ("/var/log/apache2/access.log", "apache-logs", "apache-access"),
    ("/var/log/apache2/error.log",  "apache-logs", "apache-error"),
]

def send(index, doc):
    data = json.dumps(doc).encode()
    req = urllib.request.Request(
        f"{ES_URL}/{index}/_doc",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    urllib.request.urlopen(req)

for filepath, index, logtype in log_files:
    count = 0
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                doc = {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "message": line,
                    "type": logtype,
                    "source": filepath
                }
                send(index, doc)
                count += 1
        print(f"✓ {filepath} → {count} logs sent to [{index}]")
    except FileNotFoundError:
        print(f"✗ {filepath} not found, skipping")
    except Exception as e:
        print(f"✗ {filepath} error: {e}")

print("\nAll done! Verify with:")
print("curl http://localhost:9200/_cat/indices?v")
