import requests, datetime, random, time

ports = [22, 80, 443, 3389, 21, 23, 3306] # SSH, HTTP, RDP, FTP, MySQL
# Generate 5 random "Hacker" IP Addresses
ips = [f"{random.randint(11,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(5)]

print("🔥 SIMULATING NMAP PORT SCAN ATTACK AGAINST FIREWALL...")
for i in range(100):
    log = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": "BLOCKED",
        "source_ip": random.choice(ips),
        "dest_port": random.choice(ports),
        "protocol": "TCP",
        "severity": "Warning"
    }
    # Send directly to the SIEM Database
    requests.post("http://localhost:9200/firewall-logs/_doc", json=log)
    print(f"🚨 [UFW FIREWALL] Blocked connection from {log['source_ip']} trying to hack Port {log['dest_port']}")
    time.sleep(0.05)

print("\n✅ 100 Blocked Firewall logs sent to Kibana!")
