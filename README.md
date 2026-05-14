# Unified SOC Threat Intelligence Platform

## 🛡️ Project Overview
This project simulates a modern Security Operations Center (SOC) environment by combining **Active Vulnerability Assessment** (Red Team) with **Real-time SIEM Monitoring** (Blue Team). 

Instead of generating static text reports, this custom Python vulnerability scanner actively attacks a target web application (DVWA) and streams highly structured JSON telemetry directly into an **Elasticsearch** database. The data is then visualized in real-time on a **Kibana Threat Dashboard**, allowing SOC analysts to instantly prioritize critical vulnerabilities like SQL Injections and Cross-Site Scripting (XSS).

### 📖 How It Works (The Detective and the Librarian Analogy)
If you aren't familiar with how a SIEM works, think of this project like running a giant library:
1. **The Target (The House):** A deliberately vulnerable application (DVWA) acts as a house with broken locks.
2. **The Scanner (The Detective):** The Python script acts as a detective. It walks around the house pulling on door handles. When it finds an open door (like a SQL Injection), it writes a highly structured letter detailing exactly what it found.
3. **The Connection (The Walkie-Talkie):** The Python script uses a REST API (Port 9200) as a walkie-talkie to instantly transmit that letter to headquarters over the network.
4. **The SIEM (The Librarian):** Elasticsearch sits at headquarters, catches the walkie-talkie message, and files it away in a massive database.
5. **The Dashboard (Kibana):** A giant TV screen above the librarian's desk constantly reads the filing cabinet and instantly draws a giant red pie chart warning the SOC Analyst of the breached door!

---

## 🚀 Step-by-Step Execution Guide

### Phase 1: Infrastructure Setup
**1. Start the SIEM (ELK Stack)**
```bash
sudo systemctl start docker
sudo docker-compose up -d
```
*Wait 60 seconds for Elasticsearch and Kibana to fully boot.*

**2. Start the Target Application (DVWA)**
```bash
sudo docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa
```
*Initialize the database by visiting `http://localhost:8080/setup.php` and clicking "Create / Reset Database".*

### Phase 2: Vulnerability Scanning (Red Team)
**1. Setup Python & Database Mappings**
```bash
pip3 install requests beautifulsoup4 colorama
python3 utils/setup_elasticsearch.py
```

**2. Automate Target Authentication**
```bash
python3 utils/dvwa_scan.py
```
*This script bypasses DVWA's anti-CSRF protections, lowers the security level, and returns the session cookie required for the scanner.*

**3. Launch the Attack!**
Copy the command output by the previous script. It will look exactly like this:
```bash
python3 scanner/scanner.py "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie "PHPSESSID=<YOUR_COOKIE_HERE>; security=low" \
    --logstash-host localhost \
    --logstash-port 5000 \
    --output findings_sqli.json
```

### Phase 3: Defensive Log Monitoring (Blue Team)
To make this a complete SOC environment, we also simulate defensive network monitoring.

**1. Nginx Web Logs**
Run the log shipper to read standard web server traffic and send it to Kibana:
```bash
python3 utils/send_nginx.py
```

**2. Firewall Block Logs Simulator**
Run this script to simulate an aggressive Nmap Port Scan from random IP addresses hitting your firewall:
```bash
python3 utils/firewall_sim.py
```

### Phase 4: Visualize the Threat in Kibana
1. Open your browser and go to `http://localhost:5601`.
2. Navigate to **☰ Menu → Stack Management → Data Views**.
3. Create Data Views for `vuln-findings-*`, `nginx-logs*`, and `firewall-logs*`. Make sure the Time Field is set to `timestamp`.
4. Navigate to **☰ Menu → Dashboards** and create a new dashboard using the Lens builder.
5. Drag and drop fields like `severity`, `vuln_type`, and `timestamp` to instantly build Donut charts, Bar graphs, and timelines.
6. Set your time filter to **"Today"** and watch your attack data populate!

---

## 🛠️ Offline Reporting
If you need to generate a static HTML report for management or offline viewing, run the report generator tool against the local backup JSON file:
```bash
python3 utils/report_generator.py findings_sqli.json report.html
```

## 📜 Skills Demonstrated
- **SIEM Engineering:** Docker deployment, Elasticsearch Index Mapping, Kibana Data Visualization.
- **Offensive Security:** Automated SQL Injection, XSS detection, CSRF token bypassing.
- **Defensive Monitoring:** Nginx web server log ingestion, Firewall port scan monitoring.
- **Python Development:** Object-Oriented Programming, API Integration, Web Scraping (`BeautifulSoup`).
