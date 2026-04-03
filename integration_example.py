#!/usr/bin/env python3
"""
ZEVS v2.0 - Integration Example
Demonstrates how to use all new modules together
"""

import sys
import time
from datetime import datetime

# Import all v2.0 modules
from cvss_calculator import CVSSCalculator
from interactsh_client import InteractshClient
from rate_limiter import SmartRateLimiter, WAFDetector
from html_report_generator import HTMLReportGenerator
from jwt_attacker import JWTAttacker
from graphql_tester import GraphQLTester
from oauth_tester import OAuthTester
from plugin_system import PluginManager


class ZevsV2Scanner:
    """ZEVS v2.0 Scanner with all new features"""

    def __init__(self, target: str, rps: float = 5.0):
        self.target = target
        self.findings = []
        self.start_time = time.time()
        self.request_count = 0

        # Initialize modules
        self.rate_limiter = SmartRateLimiter(requests_per_second=rps, jitter=0.3)
        self.oob_client = InteractshClient()
        self.plugin_manager = PluginManager("plugins")

        print(f"[*] ZEVS v2.0 Scanner initialized")
        print(f"[*] Target: {target}")
        print(f"[*] Rate limit: {rps} req/s with jitter")
        print(f"[*] OOB detection: Enabled (via {self.oob_client.server})")
        print(f"[*] Plugins loaded: {len(self.plugin_manager.plugins)}")
        print()

    def add_finding(
        self,
        vuln_type: str,
        url: str,
        description: str,
        evidence: str,
        payload: str,
        **kwargs,
    ):
        """Add finding with automatic CVSS scoring"""

        # Calculate CVSS score
        cvss = CVSSCalculator.calculate_for_vuln(vuln_type)

        finding = {
            "type": vuln_type,
            "severity": cvss["severity"],
            "cvss_score": cvss["score"],
            "cvss_vector": cvss["vector"],
            "url": url,
            "description": description,
            "evidence": evidence,
            "payload": payload,
            "method": kwargs.get("method", "GET"),
            "headers": kwargs.get("headers", {}),
            "remediation": kwargs.get("remediation", "Consult security best practices"),
        }

        self.findings.append(finding)

        print(f"[{cvss['severity']}] {vuln_type} found at {url}")
        print(f"  CVSS: {cvss['score']} | Evidence: {evidence[:80]}...")
        print()

    def test_blind_sqli_with_oob(self, url: str, param: str):
        """Test blind SQLi using OOB detection"""

        print(f"[*] Testing blind SQLi on {param} parameter...")

        # Generate OOB payload
        payload, callback = self.oob_client.test_blind_sqli(url, param)

        # Simulate sending request (in real implementation, use curl/requests)
        print(f"[*] Payload: {payload[:80]}...")
        print(f"[*] Callback: {callback}")
        print(f"[*] Waiting 5 seconds for DNS callback...")

        # Check for interactions
        interactions = self.oob_client.check_interactions(callback, timeout=5)

        if interactions:
            self.add_finding(
                "Blind SQL Injection",
                url,
                "Blind SQL injection confirmed via DNS callback",
                f"DNS query received from {callback}",
                payload,
                remediation="Use parameterized queries or prepared statements",
            )
            return True
        else:
            print(f"[-] No callback received")
            return False

    def test_jwt_vulnerabilities(self, token: str):
        """Test JWT for vulnerabilities"""

        print(f"[*] Testing JWT token...")

        # Decode JWT
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            print(f"[-] Invalid JWT token")
            return

        print(f"[*] Algorithm: {decoded['header'].get('alg')}")
        print(f"[*] Payload: {decoded['payload']}")

        # Test weak secret
        weak_results = JWTAttacker.weak_secret_attack(token)
        if weak_results:
            secret, forged_token = weak_results[0]
            self.add_finding(
                "JWT Attack",
                self.target,
                f"JWT signed with weak secret: '{secret}'",
                f"Successfully forged admin token",
                forged_token[:80] + "...",
                remediation="Use strong random secrets (256+ bits)",
            )

        # Test none algorithm
        none_payloads = JWTAttacker.none_algorithm_attack(token)
        if none_payloads:
            print(f"[*] Generated {len(none_payloads)} none algorithm bypass payloads")

    def test_graphql_endpoint(self, graphql_url: str):
        """Test GraphQL endpoint"""

        print(f"[*] Testing GraphQL endpoint...")

        # Try introspection
        introspection = GraphQLTester.introspection_query()
        print(f"[*] Attempting introspection query...")

        # In real implementation, send query and check response
        # If introspection is enabled:
        self.add_finding(
            "GraphQL",
            graphql_url,
            "GraphQL introspection is enabled",
            "Full schema exposed via __schema query",
            introspection[:100] + "...",
            remediation="Disable introspection in production",
        )

        # Generate depth attack
        depth_attack = GraphQLTester.generate_depth_attack(50)
        print(f"[*] Generated depth attack (50 levels)")

    def test_oauth_flow(self, oauth_url: str, redirect_uri: str):
        """Test OAuth implementation"""

        print(f"[*] Testing OAuth flow...")

        # Test redirect URI bypass
        bypass_payloads = OAuthTester.redirect_uri_bypass_payloads(redirect_uri)
        print(f"[*] Generated {len(bypass_payloads)} redirect URI bypass payloads")

        # Test state parameter
        state_attacks = OAuthTester.state_parameter_attacks()
        print(f"[*] Testing {len(state_attacks)} state parameter scenarios")

    def detect_waf(self, response_headers: dict, response_body: str = ""):
        """Detect and adapt to WAF"""

        waf = WAFDetector.detect(response_headers, response_body)

        if waf:
            print(f"[!] WAF detected: {waf}")

            # Get stealth config
            config = WAFDetector.get_stealth_config(waf)
            print(f"[*] Adjusting to stealth mode:")
            print(f"    RPS: {config['rps']}")
            print(f"    Jitter: {config['jitter']}")
            print(f"    Delay: {config['delay']}s")

            # Update rate limiter
            self.rate_limiter = SmartRateLimiter(
                requests_per_second=config["rps"], jitter=config["jitter"]
            )

    def generate_report(self, output_file: str = "zevs_v2_report.html"):
        """Generate professional HTML report"""

        duration = time.time() - self.start_time
        mins, secs = divmod(int(duration), 60)

        scan_stats = {
            "total_requests": self.request_count,
            "duration": f"{mins}m {secs}s",
        }

        print(f"[*] Generating HTML report...")

        html = HTMLReportGenerator.generate_report(
            self.target, self.findings, scan_stats
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] Report saved: {output_file}")
        print(f"[+] Total findings: {len(self.findings)}")

        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            sev = finding["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print(f"[+] Severity breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                print(f"    {sev}: {count}")


def main():
    """Example usage"""

    print("=" * 70)
    print("ZEVS v2.0 - Integration Example")
    print("=" * 70)
    print()

    # Initialize scanner
    scanner = ZevsV2Scanner("https://example.com", rps=5.0)

    # Example 1: Test blind SQLi with OOB
    print("=" * 70)
    print("Example 1: Blind SQLi with OOB Detection")
    print("=" * 70)
    scanner.test_blind_sqli_with_oob("https://example.com/api/users", "id")

    # Example 2: Test JWT
    print("=" * 70)
    print("Example 2: JWT Vulnerability Testing")
    print("=" * 70)
    example_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCIsInJvbGUiOiJ1c2VyIn0.test"
    scanner.test_jwt_vulnerabilities(example_jwt)

    # Example 3: Test GraphQL
    print("=" * 70)
    print("Example 3: GraphQL Testing")
    print("=" * 70)
    scanner.test_graphql_endpoint("https://example.com/graphql")

    # Example 4: Test OAuth
    print("=" * 70)
    print("Example 4: OAuth Flow Testing")
    print("=" * 70)
    scanner.test_oauth_flow(
        "https://oauth.example.com/authorize", "https://example.com/callback"
    )

    # Example 5: WAF Detection
    print("=" * 70)
    print("Example 5: WAF Detection and Adaptation")
    print("=" * 70)
    example_headers = {"server": "cloudflare", "cf-ray": "abc123"}
    scanner.detect_waf(example_headers)

    # Generate report
    print()
    print("=" * 70)
    print("Generating Report")
    print("=" * 70)
    scanner.generate_report("example_report.html")

    print()
    print("=" * 70)
    print("Scan Complete!")
    print("=" * 70)
    print()
    print("This example demonstrates:")
    print("  [+] OOB detection for blind vulnerabilities")
    print("  [+] Automatic CVSS scoring")
    print("  [+] JWT vulnerability testing")
    print("  [+] GraphQL security testing")
    print("  [+] OAuth flow testing")
    print("  [+] WAF detection and adaptation")
    print("  [+] Professional HTML report generation")
    print()
    print("To use in production:")
    print("  1. Add actual HTTP request logic (curl/requests)")
    print("  2. Integrate with existing scanner modules")
    print("  3. Add CLI argument parsing")
    print("  4. Implement authentication handling")
    print()


if __name__ == "__main__":
    main()
