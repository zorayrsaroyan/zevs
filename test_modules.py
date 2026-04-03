#!/usr/bin/env python3
"""
ZEVS v2.0 - Module Test Suite
Tests all new modules to ensure they work correctly
"""

import sys


def test_cvss_calculator():
    """Test CVSS calculator"""
    print("\n[1/8] Testing CVSS Calculator...")
    try:
        from cvss_calculator import CVSSCalculator

        result = CVSSCalculator.calculate_for_vuln("SQL Injection")
        assert result["score"] == 10.0
        assert result["severity"] == "CRITICAL"

        print("  [OK] CVSS calculation works")
        print(f"  [OK] SQL Injection: {result['score']} ({result['severity']})")
        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_interactsh_client():
    """Test Interactsh client"""
    print("\n[2/8] Testing Interactsh Client...")
    try:
        from interactsh_client import InteractshClient

        client = InteractshClient()
        callback = client.generate_payload("test")

        assert ".oast.pro" in callback or ".interact.sh" in callback

        print("  [OK] Callback generation works")
        print(f"  [OK] Generated: {callback}")

        # Test payload generation
        sqli_payload, sqli_callback = client.test_blind_sqli(
            "https://example.com", "id"
        )
        print(f"  [OK] Blind SQLi payload generated")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_rate_limiter():
    """Test rate limiter"""
    print("\n[3/8] Testing Rate Limiter...")
    try:
        from rate_limiter import SmartRateLimiter, WAFDetector

        limiter = SmartRateLimiter(requests_per_second=10.0, jitter=0.3)

        assert limiter.base_delay == 0.1
        assert limiter.get_current_rps() == 10.0

        print("  [OK] Rate limiter initialized")
        print(f"  [OK] Current RPS: {limiter.get_current_rps()}")

        # Test WAF detection
        headers = {"server": "cloudflare", "cf-ray": "abc123"}
        waf = WAFDetector.detect(headers)
        assert waf == "Cloudflare"

        print(f"  [OK] WAF detection works: {waf}")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_html_report():
    """Test HTML report generator"""
    print("\n[4/8] Testing HTML Report Generator...")
    try:
        from html_report_generator import HTMLReportGenerator

        test_findings = [
            {
                "type": "SQL Injection",
                "severity": "CRITICAL",
                "url": "https://example.com/api?id=1",
                "description": "SQL injection found",
                "evidence": "MySQL error detected",
                "payload": "id=1' OR '1'='1",
                "method": "GET",
                "headers": {"User-Agent": "ZEVS/2.0"},
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "remediation": "Use parameterized queries",
            }
        ]

        scan_stats = {"total_requests": 100, "duration": "1m 30s"}

        html = HTMLReportGenerator.generate_report(
            "https://example.com", test_findings, scan_stats
        )

        assert "ZEVS v2.0 PRO" in html
        assert "SQL Injection" in html
        assert "curl" in html

        print("  [OK] HTML report generation works")
        print(f"  [OK] Report size: {len(html)} bytes")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_jwt_attacker():
    """Test JWT attacker"""
    print("\n[5/8] Testing JWT Attacker...")
    try:
        from jwt_attacker import JWTAttacker
        import json
        import base64
        import hmac
        import hashlib

        # Create test JWT
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test", "role": "user"}

        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )

        signature = hmac.new(
            b"secret", f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        test_token = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Test decoding
        decoded = JWTAttacker.decode_jwt(test_token)
        assert decoded is not None
        assert decoded["header"]["alg"] == "HS256"

        print("  [OK] JWT decoding works")

        # Test none algorithm attack
        none_payloads = JWTAttacker.none_algorithm_attack(test_token)
        assert len(none_payloads) > 0

        print(f"  [OK] None algorithm attack: {len(none_payloads)} payloads")

        # Test weak secret attack
        weak_results = JWTAttacker.weak_secret_attack(test_token)
        assert len(weak_results) > 0

        print(f"  [OK] Weak secret cracked: '{weak_results[0][0]}'")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_graphql_tester():
    """Test GraphQL tester"""
    print("\n[6/8] Testing GraphQL Tester...")
    try:
        from graphql_tester import GraphQLTester

        # Test introspection
        introspection = GraphQLTester.introspection_query()
        assert "__schema" in introspection

        print("  [OK] Introspection query generated")

        # Test depth attack
        depth_attack = GraphQLTester.generate_depth_attack(10)
        assert "user" in depth_attack

        print("  [OK] Depth attack generated (10 levels)")

        # Test batch attack
        batch_attack = GraphQLTester.generate_batch_attack(5)
        assert "query0" in batch_attack

        print("  [OK] Batch attack generated (5 queries)")

        # Test all attacks
        all_attacks = GraphQLTester.generate_all_attacks()
        assert len(all_attacks) > 0

        print(f"  [OK] Total attack types: {len(all_attacks)}")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_oauth_tester():
    """Test OAuth tester"""
    print("\n[7/8] Testing OAuth Tester...")
    try:
        from oauth_tester import OAuthTester

        # Test redirect URI bypass
        bypass_payloads = OAuthTester.redirect_uri_bypass_payloads(
            "https://example.com/callback"
        )
        assert len(bypass_payloads) > 0

        print(f"  [OK] Redirect URI bypass: {len(bypass_payloads)} payloads")

        # Test state attacks
        state_attacks = OAuthTester.state_parameter_attacks()
        assert len(state_attacks) > 0

        print(f"  [OK] State parameter attacks: {len(state_attacks)} scenarios")

        # Test scope escalation
        scope_payloads = OAuthTester.scope_escalation_payloads()
        assert len(scope_payloads) > 0

        print(f"  [OK] Scope escalation: {len(scope_payloads)} payloads")

        # Test complete suite
        test_suite = OAuthTester.generate_oauth_test_suite(
            "https://oauth.example.com",
            "https://app.example.com/callback",
            "client_123",
        )

        print(f"  [OK] Complete test suite: {len(test_suite)} categories")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_plugin_system():
    """Test plugin system"""
    print("\n[8/8] Testing Plugin System...")
    try:
        from plugin_system import PluginManager, VulnerabilityPlugin

        # Create plugin manager
        manager = PluginManager("plugins")

        print("  [OK] Plugin manager initialized")

        # List plugins
        plugins = manager.list_plugins()

        print(f"  [OK] Loaded plugins: {len(plugins)}")

        # Test plugin interface
        class TestPlugin(VulnerabilityPlugin):
            @property
            def name(self):
                return "Test Plugin"

            @property
            def description(self):
                return "Test plugin"

            @property
            def severity(self):
                return "HIGH"

            def scan(self, target, **kwargs):
                return []

        test_plugin = TestPlugin()
        assert test_plugin.name == "Test Plugin"

        print("  [OK] Plugin interface works")

        return True
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 70)
    print("ZEVS v2.0 - Module Test Suite")
    print("=" * 70)

    tests = [
        test_cvss_calculator,
        test_interactsh_client,
        test_rate_limiter,
        test_html_report,
        test_jwt_attacker,
        test_graphql_tester,
        test_oauth_tester,
        test_plugin_system,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"\n  [FAIL] Test failed: {e}")
            results.append(False)

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(results)
    total = len(results)

    print(f"\nPassed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")

    if passed == total:
        print("\n[SUCCESS] All modules working correctly!")
        print("\n ZEVS v2.0 is ready for bug bounty hunting!")
        return 0
    else:
        print("\n  Some modules need attention")
        return 1


if __name__ == "__main__":
    sys.exit(main())
