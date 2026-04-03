#!/usr/bin/env python3
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
if __name__ == "__main__":
    print("Testing Smart Rate Limiter...\n")

    limiter = SmartRateLimiter(requests_per_second=5.0, jitter=0.3)

    print(f"Base delay: {limiter.base_delay:.3f}s")
    print(f"Current RPS: {limiter.get_current_rps():.2f}\n")

    # Simulate requests
    print("Simulating 10 requests with jitter:")
    for i in range(10):
        start = time.time()
        limiter.wait()
        elapsed = time.time() - start
        print(f"Request {i + 1}: waited {elapsed:.3f}s")

        # Simulate occasional rate limit
        if i == 5:
            print("  -> Simulating 429 rate limit error")
            limiter.on_error(429)
        else:
            limiter.on_success()

    print(f"\nFinal RPS: {limiter.get_current_rps():.2f}")
    print(f"Throttled: {limiter.is_throttled()}")

    # Test WAF detection
    print("\n\nTesting WAF Detection:")
    test_headers = {"server": "cloudflare", "cf-ray": "abc123"}
    waf = WAFDetector.detect(test_headers)
    print(f"Detected WAF: {waf}")

    config = WAFDetector.get_stealth_config(waf)
    print(f"Recommended config: {config}")
