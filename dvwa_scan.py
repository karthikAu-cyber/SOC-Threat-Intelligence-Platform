import requests
from bs4 import BeautifulSoup

# Step 1: Login to DVWA automatically
s = requests.Session()
login_page = s.get("http://localhost:8080/login.php")
soup = BeautifulSoup(login_page.text, "html.parser")
token = soup.find("input", {"name": "user_token"})["value"]

s.post("http://localhost:8080/login.php", data={
    "username": "admin", "password": "password",
    "Login": "Login", "user_token": token
})

# Step 2: Set security to Low
s.cookies.set("security", "low")

# Step 3: Verify login works
r = s.get("http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit")
print(f"Status: {r.status_code}")
print(f"Logged in: {'First name' in r.text}")

# Step 4: Test SQLi manually
r2 = s.get("http://localhost:8080/vulnerabilities/sqli/?id=1'&Submit=Submit")
print(f"\nSQLi test response length: {len(r2.text)}")
if "sql" in r2.text.lower() or "error" in r2.text.lower():
    print("✓ SQL ERROR DETECTED! DVWA is vulnerable")
else:
    print("✗ No SQL error found")
    
# Step 5: Print the working cookie for scanner
phpsessid = s.cookies.get("PHPSESSID")
print(f"\nWorking cookie: PHPSESSID={phpsessid}; security=low")
print(f"\nRun scanner with:")
print(f'python3 scanner/scanner.py "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie "PHPSESSID={phpsessid}; security=low" --logstash-host localhost --logstash-port 5000 --output findings_sqli.json')
