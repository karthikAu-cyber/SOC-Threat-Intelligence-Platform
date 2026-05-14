import json
import re
import urllib.request
from datetime import datetime, timezone

ES_URL = "http://localhost:9200"

pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

def send(index, doc):
    data = json.dumps(doc).encode()
    req = urllib.request.Request(
        f"{ES_URL}/{index}/_doc",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    urllib.request.urlopen(req)

def classify(status):
    s = int(status)
    if s < 300: return "good"
    if s < 400: return "redirect"
    if s < 500: return "warning"
    return "critical"

count = 0
good = 0
warn = 0
crit = 0

try:
    with open("/var/log/nginx/access.log", "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if m:
                status = m.group("status")
                level = classify(status)
                if level == "good": good += 1
                elif level == "warning": warn += 1
                elif level == "critical": crit += 1
                doc = {
                    "@timestamp":  datetime.now(timezone.utc).isoformat(),
                    "ip":          m.group("ip"),
                    "method":      m.group("method"),
                    "url":         m.group("url"),
                    "status":      int(status),
                    "size":        int(m.group("size")),
                    "user_agent":  m.group("agent"),
                    "log_level":   level,
                    "message":     line
                }
                send("nginx-parsed", doc)
                count += 1
            else:
                print(f"No match: {line[:60]}")

    print(f"Total logs sent : {count}")
    print(f"Good  (2xx)     : {good}")
    print(f"Warning (4xx)   : {warn}")
    print(f"Critical (5xx)  : {crit}")
    print()
    print("Create data view nginx-parsed* in Kibana!")

except FileNotFoundError:
    print("Nginx log not found!")
except Exception as e:
    print(f"Error: {e}")
