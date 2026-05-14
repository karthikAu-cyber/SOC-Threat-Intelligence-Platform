#!/usr/bin/env python3
"""
VulnSec - Automated Web Vulnerability Scanner v4
Works on ANY target — crawls, finds forms & params, tests SQLi/XSS/Headers/CORS.
Optimised for DVWA and similar local vulnerable apps.
"""

import requests
import json
import time
import socket
import logging
import argparse
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from colorama import Fore, Style, init

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vulnsec")

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "mysql_fetch", "mysql_num_rows",
    "unclosed quotation mark", "quoted string not properly terminated",
    "supplied argument is not a valid mysql", "pg::syntaxerror",
    "ora-01756", "microsoft ole db", "odbc microsoft access",
    "invalid query", "sql syntax", "mysqli_", "mysql error",
    "division by zero", "syntax error", "unknown column",
    "table doesn't exist", "column not found",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "<body onload=alert(1)>",
    "';alert(1)//",
]

SQLI_GET_PAYLOADS = [
    ("'",                               "error"),
    ("1'",                              "error"),
    ("''",                              "error"),
    ("1 OR 1=1--",                      "boolean"),
    ("' OR '1'='1'--",                  "boolean"),
    ("1 AND 1=2--",                     "boolean_false"),
    ("' AND '1'='2'--",                 "boolean_false"),
    ("1 UNION SELECT NULL--",           "union"),
    ("1 UNION SELECT NULL,NULL--",      "union"),
    ("1 UNION SELECT NULL,NULL,NULL--", "union"),
]

SQLI_POST_PAYLOADS = [
    "'",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT user(),NULL--",
]

SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


# ── Senders ──────────────────────────────────────────────────
class LogstashSender:
    def __init__(self, host="localhost", port=5000):
        self.host, self.port, self.enabled = host, port, False
        try:
            s = socket.create_connection((host, port), timeout=2); s.close()
            self.enabled = True
            logger.info(f"{Fore.GREEN}[+] Logstash → {host}:{port}")
        except Exception:
            logger.warning(f"{Fore.YELLOW}[!] Logstash unreachable — ES direct mode")

    def send(self, f):
        if not self.enabled: return
        try:
            with socket.create_connection((self.host, self.port), timeout=5) as s:
                s.sendall((json.dumps(f) + "\n").encode())
        except Exception: pass


class ESSender:
    def __init__(self, host="http://localhost:9200"):
        self.host, self.enabled = host.rstrip("/"), False
        try:
            r = requests.get(f"{self.host}/_cluster/health", timeout=3)
            if r.status_code == 200:
                self.enabled = True
                logger.info(f"{Fore.GREEN}[+] Elasticsearch → {host} [{r.json().get('status','?')}]")
        except Exception:
            logger.warning(f"{Fore.YELLOW}[!] Elasticsearch unreachable")

    def send(self, f):
        if not self.enabled: return
        try:
            today = datetime.now().strftime("%Y.%m.%d")
            date_index = f"vuln-findings-{today}"
            fixed_index = "vuln-findings-000001"
            sent = False
            for index in [date_index, fixed_index]:
                r = requests.post(f"{self.host}/{index}/_doc",
                    json=f, headers={"Content-Type": "application/json"}, timeout=5)
                if r.status_code in (200, 201):
                    sent = True
                    break
            if not sent:
                # Create new index and post
                requests.put(f"{self.host}/{date_index}")
                requests.post(f"{self.host}/{date_index}/_doc",
                    json=f, headers={"Content-Type": "application/json"}, timeout=5)
        except Exception: pass


# ── Scanner ───────────────────────────────────────────────────
class VulnScanner:
    def __init__(self, target, logstash_host="localhost", logstash_port=5000,
                 es_host="http://localhost:9200", auth_cookie=None, output_file="findings.json"):
        self.target = target.rstrip("/")
        self.base_netloc = urlparse(self.target).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        })
        self.visited_urls = set()
        self.findings = []
        self.output_file = output_file
        self.logstash = LogstashSender(logstash_host, logstash_port)
        self.es = ESSender(es_host)
        self._header_checked = set()
        self._tested = set()   # (url, param, test_type) dedup

        if auth_cookie:
            for part in auth_cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

    # ── Crawl ────────────────────────────────────
    SKIP_PATTERNS = ["logout", "signout", "sign_out", "log_out", "setup.php", "phpinfo"]

    def crawl(self, url, depth=3):
        if depth == 0 or url in self.visited_urls:
            return
        if urlparse(url).netloc != self.base_netloc:
            return
        # Skip URLs that destroy sessions
        url_lower = url.lower()
        if any(skip in url_lower for skip in self.SKIP_PATTERNS):
            return
        self.visited_urls.add(url)
        try:
            r = self.session.get(url, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href") or tag.get("action") or ""
                if href and not href.startswith(("mailto:", "javascript:", "#", "tel:")):
                    full = urljoin(url, href)
                    if full not in self.visited_urls:
                        self.crawl(full, depth - 1)
        except Exception as e:
            logger.debug(f"Crawl {url}: {e}")

    def collect_forms(self, url):
        """Return list of (action_url, method, {field: value}) for all forms."""
        forms = []
        try:
            r = self.session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "get").lower()
                fields = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        fields[name] = inp.get("value") or "test"
                if fields:
                    forms.append((action, method, fields))
        except Exception:
            pass
        return forms

    # ── Record ───────────────────────────────────
    def record(self, vuln_type, url, param, payload, evidence, severity, cvss, description):
        key = (vuln_type, url, param)
        if key in self._tested:
            return
        self._tested.add(key)

        finding = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": "VulnSec",
            "vuln_type": vuln_type,
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence[:300],
            "severity": severity,
            "cvss_score": cvss,
            "description": description,
            "owasp_category": {
                "SQL Injection": "A03:2021-Injection",
                "XSS":           "A03:2021-Injection",
                "SSRF":          "A10:2021-SSRF",
                "Open Redirect": "A01:2021-Broken Access Control",
                "CORS Misconfiguration":    "A05:2021-Security Misconfiguration",
                "Missing Security Headers": "A05:2021-Security Misconfiguration",
            }.get(vuln_type, "A05:2021-Security Misconfiguration"),
        }
        self.findings.append(finding)
        self.logstash.send(finding)
        self.es.send(finding)

        c = {"CRITICAL":Fore.RED,"HIGH":Fore.YELLOW,"MEDIUM":Fore.CYAN,"LOW":Fore.GREEN}.get(severity, Fore.WHITE)
        print(f"\n{c}  ✦ [{severity}] {vuln_type}{Style.RESET_ALL}")
        print(f"    URL      : {url}")
        print(f"    Param    : {param}")
        print(f"    Payload  : {payload[:80]}")
        print(f"    Evidence : {evidence[:100]}")
        print(f"    CVSS     : {cvss}")

    def _get(self, url, timeout=10):
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=True)
        except Exception:
            return None

    def _post(self, url, data, timeout=10):
        try:
            return self.session.post(url, data=data, timeout=timeout, allow_redirects=True)
        except Exception:
            return None

    def _inject_get(self, url, param, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in params.items()})))

    # ── SQLi GET ─────────────────────────────────
    def test_sqli_get(self, url, param):
        baseline = self._get(url)
        if not baseline:
            return
        baseline_body = baseline.text.lower()
        baseline_len  = len(baseline.text)

        for payload, ptype in SQLI_GET_PAYLOADS:
            resp = self._get(self._inject_get(url, param, payload), timeout=10)
            if not resp:
                continue
            body = resp.text.lower()

            for err in SQLI_ERRORS:
                if err in body and err not in baseline_body:
                    self.record("SQL Injection", url, param, payload,
                        f"DB error: '{err}'", "CRITICAL", 9.8,
                        "Error-based SQLi — database error string in response.")
                    return

            if ptype == "boolean_false":
                diff = abs(len(resp.text) - baseline_len)
                if diff > 20:
                    self.record("SQL Injection", url, param, payload,
                        f"Boolean-based: content diff {diff} bytes",
                        "HIGH", 8.1, "Boolean-based blind SQLi.")
                    return

            if ptype == "union" and len(resp.text) > baseline_len + 10:
                self.record("SQL Injection", url, param, payload,
                    f"UNION: response grew {len(resp.text)-baseline_len} bytes",
                    "CRITICAL", 9.8, "UNION-based SQLi — extra rows returned.")
                return

    # ── SQLi POST ────────────────────────────────
    def test_sqli_post(self, action, fields):
        for target_field in fields:
            baseline_data = dict(fields)
            baseline = self._post(action, baseline_data)
            if not baseline:
                continue
            baseline_body = baseline.text.lower()

            for payload in SQLI_POST_PAYLOADS:
                data = dict(fields)
                data[target_field] = payload
                resp = self._post(action, data)
                if not resp:
                    continue
                body = resp.text.lower()

                for err in SQLI_ERRORS:
                    if err in body and err not in baseline_body:
                        self.record("SQL Injection", action, target_field, payload,
                            f"DB error in POST response: '{err}'",
                            "CRITICAL", 9.8, "Error-based SQLi via POST form field.")
                        break

    # ── XSS GET ──────────────────────────────────
    def test_xss_get(self, url, param):
        for payload in XSS_PAYLOADS:
            resp = self._get(self._inject_get(url, param, payload))
            if resp and payload in resp.text:
                self.record("XSS", url, param, payload,
                    "Payload reflected unencoded in response",
                    "HIGH", 7.4, "Reflected XSS.")
                return

    # ── XSS POST ─────────────────────────────────
    def test_xss_post(self, action, fields):
        for target_field in fields:
            for payload in XSS_PAYLOADS:
                data = dict(fields)
                data[target_field] = payload
                resp = self._post(action, data)
                if resp and payload in resp.text:
                    self.record("XSS", action, target_field, payload,
                        "XSS payload reflected in POST response",
                        "HIGH", 7.4, "Reflected XSS via POST.")
                    break

    # ── Security Headers ─────────────────────────
    def test_headers(self, url):
        host = urlparse(url).netloc
        if host in self._header_checked:
            return
        self._header_checked.add(host)
        try:
            resp = self.session.get(url, timeout=10)
            for h in SECURITY_HEADERS:
                if h not in resp.headers:
                    sev = "HIGH" if h in ["Content-Security-Policy","Strict-Transport-Security"] else "MEDIUM"
                    self.record("Missing Security Headers", url, h, "N/A",
                        f"Header '{h}' missing", sev,
                        6.1 if sev=="HIGH" else 5.3, f"Missing {h}.")
            # Cookie flags
            sc = resp.headers.get("Set-Cookie","")
            if sc and "HttpOnly" not in sc:
                self.record("Missing Security Headers", url, "Set-Cookie(HttpOnly)", "N/A",
                    "Cookie without HttpOnly flag", "HIGH", 6.8,
                    "Session cookie accessible via JS.")
            if sc and "Secure" not in sc:
                self.record("Missing Security Headers", url, "Set-Cookie(Secure)", "N/A",
                    "Cookie without Secure flag", "MEDIUM", 5.9,
                    "Cookie transmitted over HTTP.")
            # CORS
            r2 = self.session.get(url, timeout=8, headers={"Origin":"https://evil.com"})
            acao = r2.headers.get("Access-Control-Allow-Origin","")
            if "evil.com" in acao or acao == "*":
                self.record("CORS Misconfiguration", url, "Origin", "https://evil.com",
                    f"ACAO: {acao}", "HIGH", 7.5, "CORS misconfiguration.")
        except Exception as e:
            logger.debug(f"Headers error: {e}")

    def save(self):
        with open(self.output_file, "w") as f:
            json.dump(self.findings, f, indent=2)
        logger.info(f"{Fore.GREEN}[+] {len(self.findings)} findings saved → {self.output_file}")

    # ── Main ─────────────────────────────────────
    def run(self):
        print(f"\n{Fore.CYAN}{'='*62}")
        print(f"  VulnSec v4  |  {self.target}")
        print(f"{'='*62}{Style.RESET_ALL}\n")

        # Step 1: crawl
        print(f"{Fore.BLUE}[1/3] Crawling...{Style.RESET_ALL}")
        self.crawl(self.target, depth=3)
        print(f"      Found {len(self.visited_urls)} URLs\n")

        # Step 2: header checks
        print(f"{Fore.BLUE}[2/3] Security header checks...{Style.RESET_ALL}")
        self.test_headers(self.target)

        # Step 3: test every URL and form
        print(f"\n{Fore.BLUE}[3/3] Injecting payloads...{Style.RESET_ALL}")

        all_urls = list(self.visited_urls) or [self.target]

        for url in all_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Test GET params
            if params:
                print(f"\n  {Fore.WHITE}{url}{Style.RESET_ALL}")
                for param in params:
                    print(f"    GET param [{param}]:", end=" ", flush=True)
                    self.test_sqli_get(url, param)
                    self.test_xss_get(url, param)
                    print("  done")

            # Test forms on each page
            forms = self.collect_forms(url)
            for action, method, fields in forms:
                print(f"\n  {Fore.WHITE}FORM {method.upper()} → {action}{Style.RESET_ALL}")
                print(f"    Fields: {list(fields.keys())}")
                if method == "post":
                    self.test_sqli_post(action, fields)
                    self.test_xss_post(action, fields)
                else:
                    for param in fields:
                        test_url = self._inject_get(action, param, fields[param])
                        self.test_sqli_get(test_url, param)
                        self.test_xss_get(test_url, param)

        # Summary
        print(f"\n{Fore.CYAN}{'='*62}")
        print(f"  SCAN COMPLETE  |  {len(self.findings)} findings")
        sev_counts = {}
        for f in self.findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if sev in sev_counts:
                c = {"CRITICAL":Fore.RED,"HIGH":Fore.YELLOW,
                     "MEDIUM":Fore.CYAN,"LOW":Fore.GREEN}.get(sev, Fore.WHITE)
                print(f"  {c}{sev}: {sev_counts[sev]}{Style.RESET_ALL}")
        print(f"{'='*62}{Style.RESET_ALL}\n")
        self.save()

        if self.findings:
            print(f"{Fore.GREEN}[+] Open Kibana → http://localhost:5601{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Generate HTML report:{Style.RESET_ALL}")
            print(f"    python utils\\report_generator.py findings.json report.html")
        return self.findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnSec Web Vulnerability Scanner v4")
    parser.add_argument("target", help="Target URL e.g. http://localhost:8080")
    parser.add_argument("--logstash-host", default="localhost")
    parser.add_argument("--logstash-port", type=int, default=5000)
    parser.add_argument("--es-host", default="http://localhost:9200")
    parser.add_argument("--cookie", default=None, help="Auth cookie e.g. 'PHPSESSID=abc123'")
    parser.add_argument("--output", default="findings.json")
    args = parser.parse_args()

    VulnScanner(
        target=args.target,
        logstash_host=args.logstash_host,
        logstash_port=args.logstash_port,
        es_host=args.es_host,
        auth_cookie=args.cookie,
        output_file=args.output,
    ).run()