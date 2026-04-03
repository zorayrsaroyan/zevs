#!/usr/bin/env python3
"""
ZEVS v2.0 - Professional Web Vulnerability Scanner
Fixed and working version

Author: Z3VS Team
GitHub: https://github.com/zorayrsaroyan/zevs
"""

import sys
import json
import time
import hashlib
import hmac
import base64
import subprocess
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Dict, Optional

# Try requests, fallback to curl
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    USE_REQUESTS = True
except:
    USE_REQUESTS = False


class CVSSCalculator:
    """CVSS v3.1 Calculator"""
    SCORES = {
        "SQL Injection": {"score": 9.8, "severity": "CRITICAL"},
        "XSS": {"score": 6.1, "severity": "MEDIUM"},
        "IDOR": {"score": 8.1, "severity": "HIGH"},
        "JWT": {"score": 8.5, "severity": "HIGH"},
    }
    
    @staticmethod
    def calculate(vuln_type: str) -> Dict:
        return CVSSCalculator.SCORES.get(vuln_type, {"score": 5.0, "severity": "MEDIUM"})


class HTTPClient:
    """HTTP Client with requests or curl"""
    def __init__(self):
        self.session = requests.Session() if USE_REQUESTS else None
    
    def get(self, url: str) -> Dict:
        if USE_REQUESTS:
            try:
                r = self.session.get(url, timeout=10, verify=False)
                return {"status": r.status_code, "body": r.text, "ok": True}
            except:
                return {"status": 0, "body": "", "ok": False}
        else:
            try:
                result = subprocess.run(["curl", "-s", "-k", url], capture_output=True, text=True, timeout=15)
                return {"status": 200, "body": result.stdout, "ok": True}
            except:
                return {"status": 0, "body": "", "ok": False}


class JWTAttacker:
    """JWT Testing - FIXED hmac"""
    SECRETS = ["secret", "password", "123456", "admin"]
    
    @staticmethod
    def test_weak_secret(token: str) -> Optional[str]:
        try:
            parts = token.split('.')
            message = f"{parts[0]}.{parts[1]}".encode()
            orig_sig = parts[2]
            
            for secret in JWTAttacker.SECRETS:
                # FIXED: Correct hmac usage
                sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
                if sig_b64 == orig_sig:
                    return secret
        except:
            pass
        return None


class ZevsScanner:
    """Main Scanner - INTEGRATED"""
    def __init__(self, target: str):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target
        self.findings = []
        self.http = HTTPClient()
        self.cvss = CVSSCalculator()
        self.jwt = JWTAttacker()
    
    def log(self, msg: str, level="INFO"):
        colors = {"INFO": "\033[94m[*]\033[0m", "VULN": "\033[91m[!]\033[0m"}
        print(f"{colors.get(level, '[*]')} {msg}")
    
    def add_finding(self, vuln_type: str, url: str, desc: str, evidence: str = ""):
        cvss = self.cvss.calculate(vuln_type)
        self.findings.append({
            "type": vuln_type,
            "severity": cvss["severity"],
            "cvss_score": cvss["score"],
            "url": url,
            "description": desc,
            "evidence": evidence[:200]
        })
        self.log(f"{cvss['severity']} (CVSS {cvss['score']}): {vuln_type} at {url}", "VULN")
    
    def test_sqli(self):
        self.log("Testing SQL Injection...")
        for param in ["id", "user", "q"]:
            for payload in ["'", "' OR '1'='1"]:
                url = f"{self.target}?{param}={payload}"
                resp = self.http.get(url)
                if resp["ok"] and any(e in resp["body"].lower() for e in ["sql", "mysql", "syntax"]):
                    self.add_finding("SQL Injection", url, f"SQL error with: {payload}", resp["body"])
                    return True
        return False
    
    def test_xss(self):
        self.log("Testing XSS...")
        for param in ["q", "search"]:
            payload = "<script>alert(1)</script>"
            url = f"{self.target}?{param}={payload}"
            resp = self.http.get(url)
            if resp["ok"] and payload in resp["body"]:
                self.add_finding("XSS", url, f"Reflected XSS", resp["body"])
                return True
        return False
    
    def test_jwt_token(self, token: str):
        self.log("Testing JWT...")
        secret = self.jwt.test_weak_secret(token)
        if secret:
            self.add_finding("JWT", self.target, f"Weak secret: {secret}", f"Can forge tokens")
            return True
        return False
    
    def scan(self, jwt_token: str = None):
        self.log(f"ZEVS v2.0 - Scanning {self.target}")
        self.log(f"HTTP: {'requests' if USE_REQUESTS else 'curl'}")
        
        self.test_sqli()
        self.test_xss()
        
        if jwt_token:
            self.test_jwt_token(jwt_token)
        
        if self.findings:
            with open("zevs_report.json", "w") as f:
                json.dump({"target": self.target, "findings": self.findings}, f, indent=2)
            self.log(f"Found {len(self.findings)} vulnerabilities - Report: zevs_report.json")
        else:
            self.log("No vulnerabilities found")
        
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
ZEVS v2.0 - Professional Vulnerability Scanner

Usage: python zevs.py <target> [--jwt TOKEN]

Examples:
  python zevs.py example.com
  python zevs.py example.com --jwt eyJhbGc...

Features:
  [+] SQL Injection (FIXED)
  [+] XSS Detection
  [+] JWT Testing (FIXED hmac)
  [+] CVSS v3.1 Scoring
  [+] requests or curl

Install: pip install requests
        """)
        sys.exit(1)
    
    target = sys.argv[1]
    jwt_token = sys.argv[sys.argv.index("--jwt") + 1] if "--jwt" in sys.argv else None
    
    scanner = ZevsScanner(target)
    scanner.scan(jwt_token)
