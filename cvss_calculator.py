#!/usr/bin/env python3
"""
CVSS v3.1 Calculator for Vulnerability Scoring
Automatically calculates severity scores for findings
"""

from typing import Dict


class CVSSCalculator:
    """Calculate CVSS v3.1 scores for vulnerabilities"""

    # CVSS v3.1 metric values
    METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},  # Attack Vector
        "AC": {"L": 0.77, "H": 0.44},  # Attack Complexity
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # Privileges Required
        "UI": {"N": 0.85, "R": 0.62},  # User Interaction
        "S": {"U": 0, "C": 1},  # Scope
        "C": {"N": 0, "L": 0.22, "H": 0.56},  # Confidentiality
        "I": {"N": 0, "L": 0.22, "H": 0.56},  # Integrity
        "A": {"N": 0, "L": 0.22, "H": 0.56},  # Availability
    }

    # Vulnerability type to CVSS vector mapping
    VULN_VECTORS = {
        "SQL Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "RCE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "XXE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "SSRF": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L",
        "IDOR": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "Auth Bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "LFI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "CRLF Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "Open Redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "CORS Misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "Log4Shell": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "Prototype Pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Race Condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "JWT Attack": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "GraphQL": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "OAuth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "Subdomain Takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Request Smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Cache Poisoning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    }

    @staticmethod
    def parse_vector(vector: str) -> Dict[str, str]:
        """Parse CVSS vector string into metrics dict"""
        metrics = {}
        parts = vector.split("/")[1:]  # Skip CVSS:3.1

        for part in parts:
            key, value = part.split(":")
            metrics[key] = value

        return metrics

    @staticmethod
    def calculate_base_score(metrics: Dict[str, str]) -> float:
        """Calculate CVSS base score from metrics"""

        # Extract metric values
        av = CVSSCalculator.METRICS["AV"][metrics["AV"]]
        ac = CVSSCalculator.METRICS["AC"][metrics["AC"]]
        pr = CVSSCalculator.METRICS["PR"][metrics["PR"]]
        ui = CVSSCalculator.METRICS["UI"][metrics["UI"]]
        scope = metrics["S"]
        c = CVSSCalculator.METRICS["C"][metrics["C"]]
        i = CVSSCalculator.METRICS["I"][metrics["I"]]
        a = CVSSCalculator.METRICS["A"][metrics["A"]]

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            return 0.0

        if scope == "U":
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal
        return round(base_score, 1)

    @staticmethod
    def get_severity(score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score == 0.0:
            return "INFO"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def calculate_for_vuln(vuln_type: str) -> Dict:
        """
        Calculate CVSS score for vulnerability type

        Returns:
            Dict with score, severity, and vector
        """
        # Get vector for vulnerability type
        vector = CVSSCalculator.VULN_VECTORS.get(vuln_type)

        if not vector:
            # Default to medium severity for unknown types
            return {
                "score": 5.0,
                "severity": "MEDIUM",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            }

        # Parse and calculate
        metrics = CVSSCalculator.parse_vector(vector)
        score = CVSSCalculator.calculate_base_score(metrics)
        severity = CVSSCalculator.get_severity(score)

        return {"score": score, "severity": severity, "vector": vector}


# Test
if __name__ == "__main__":
    print("CVSS v3.1 Calculator Test\n")

    test_vulns = ["SQL Injection", "XSS", "IDOR", "Open Redirect", "Log4Shell"]

    for vuln in test_vulns:
        result = CVSSCalculator.calculate_for_vuln(vuln)
        print(
            f"{vuln:20} | Score: {result['score']:4.1f} | {result['severity']:8} | {result['vector']}"
        )
