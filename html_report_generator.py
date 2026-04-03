#!/usr/bin/env python3
"""
HTML Report Generator with curl PoC Commands
Professional vulnerability reports for bug bounty submissions
"""

from datetime import datetime
from typing import List, Dict
import html


class HTMLReportGenerator:
    """Generate professional HTML reports with curl PoCs"""

    @staticmethod
    def generate_curl_command(finding: Dict) -> str:
        """
        Generate curl command to reproduce vulnerability

        Args:
            finding: Vulnerability finding dict

        Returns:
            curl command string
        """
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        headers = finding.get("headers", {})
        body = finding.get("body", "")
        payload = finding.get("payload", "")

        # Build curl command
        cmd = f"curl -X {method}"

        # Add headers
        for key, value in headers.items():
            cmd += f" \\\n  -H '{key}: {value}'"

        # Add body if POST/PUT
        if body and method in ["POST", "PUT", "PATCH"]:
            cmd += f" \\\n  -d '{body}'"

        # Add URL with payload
        if payload and method == "GET":
            separator = "&" if "?" in url else "?"
            cmd += f" \\\n  '{url}{separator}{payload}'"
        else:
            cmd += f" \\\n  '{url}'"

        return cmd

    @staticmethod
    def generate_report(target: str, findings: List[Dict], scan_stats: Dict) -> str:
        """
        Generate complete HTML report

        Args:
            target: Target URL
            findings: List of vulnerability findings
            scan_stats: Scan statistics

        Returns:
            HTML report string
        """

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings, key=lambda x: severity_order.get(x.get("severity", "INFO"), 5)
        )

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Generate HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZEVS v2.0 - Vulnerability Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: white;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            color: white;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: #1a1f3a;
            padding: 25px;
            border-radius: 8px;
            border-left: 4px solid;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }}
        
        .stat-card.critical {{ border-color: #dc2626; }}
        .stat-card.high {{ border-color: #ea580c; }}
        .stat-card.medium {{ border-color: #f59e0b; }}
        .stat-card.low {{ border-color: #3b82f6; }}
        .stat-card.info {{ border-color: #6b7280; }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card.critical .number {{ color: #dc2626; }}
        .stat-card.high .number {{ color: #ea580c; }}
        .stat-card.medium .number {{ color: #f59e0b; }}
        .stat-card.low .number {{ color: #3b82f6; }}
        .stat-card.info .number {{ color: #6b7280; }}
        
        .stat-card .label {{
            font-size: 0.9em;
            text-transform: uppercase;
            opacity: 0.7;
        }}
        
        .finding {{
            background: #1a1f3a;
            margin-bottom: 25px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
            border-left: 5px solid;
        }}
        
        .finding.critical {{ border-color: #dc2626; }}
        .finding.high {{ border-color: #ea580c; }}
        .finding.medium {{ border-color: #f59e0b; }}
        .finding.low {{ border-color: #3b82f6; }}
        .finding.info {{ border-color: #6b7280; }}
        
        .finding-header {{
            padding: 25px;
            background: rgba(255,255,255,0.03);
            cursor: pointer;
            transition: background 0.2s;
        }}
        
        .finding-header:hover {{
            background: rgba(255,255,255,0.05);
        }}
        
        .finding-title {{
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.7em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: #dc2626; color: white; }}
        .severity-badge.high {{ background: #ea580c; color: white; }}
        .severity-badge.medium {{ background: #f59e0b; color: white; }}
        .severity-badge.low {{ background: #3b82f6; color: white; }}
        .severity-badge.info {{ background: #6b7280; color: white; }}
        
        .cvss-score {{
            display: inline-block;
            padding: 5px 12px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            font-size: 0.7em;
            font-weight: bold;
        }}
        
        .finding-url {{
            color: #60a5fa;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .finding-body {{
            padding: 25px;
            display: none;
        }}
        
        .finding-body.active {{
            display: block;
        }}
        
        .section {{
            margin-bottom: 25px;
        }}
        
        .section-title {{
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 10px;
            color: #a78bfa;
        }}
        
        .code-block {{
            background: #0f1419;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            border: 1px solid #2d3748;
        }}
        
        .code-block pre {{
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e0e0e0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .evidence {{
            background: rgba(239, 68, 68, 0.1);
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #ef4444;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .copy-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            margin-top: 10px;
            transition: background 0.2s;
        }}
        
        .copy-btn:hover {{
            background: #5568d3;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            margin-top: 50px;
            opacity: 0.6;
            font-size: 0.9em;
        }}
        
        .scan-info {{
            background: #1a1f3a;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .scan-info-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .scan-info-label {{
            font-size: 0.85em;
            opacity: 0.7;
            margin-bottom: 5px;
        }}
        
        .scan-info-value {{
            font-size: 1.1em;
            font-weight: 600;
            color: #60a5fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ZEVS v2.0 PRO</h1>
            <div class="subtitle">Professional Vulnerability Assessment Report</div>
        </div>
        
        <div class="scan-info">
            <div class="scan-info-item">
                <div class="scan-info-label">Target</div>
                <div class="scan-info-value">{html.escape(target)}</div>
            </div>
            <div class="scan-info-item">
                <div class="scan-info-label">Scan Date</div>
                <div class="scan-info-value">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            </div>
            <div class="scan-info-item">
                <div class="scan-info-label">Total Requests</div>
                <div class="scan-info-value">{scan_stats.get("total_requests", 0)}</div>
            </div>
            <div class="scan-info-item">
                <div class="scan-info-label">Scan Duration</div>
                <div class="scan-info-value">{scan_stats.get("duration", "0s")}</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="number">{severity_counts["CRITICAL"]}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{severity_counts["HIGH"]}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{severity_counts["MEDIUM"]}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{severity_counts["LOW"]}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="number">{severity_counts["INFO"]}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px; color: #a78bfa;">Findings ({len(findings)})</h2>
"""

        # Add findings
        for idx, finding in enumerate(sorted_findings, 1):
            severity = finding.get("severity", "INFO").lower()
            vuln_type = html.escape(finding.get("type", "Unknown"))
            url = html.escape(finding.get("url", ""))
            description = html.escape(finding.get("description", ""))
            evidence = html.escape(finding.get("evidence", ""))
            payload = html.escape(finding.get("payload", ""))
            cvss_score = finding.get("cvss_score", "N/A")
            cvss_vector = finding.get("cvss_vector", "")

            # Generate curl command
            curl_cmd = HTMLReportGenerator.generate_curl_command(finding)
            curl_cmd_escaped = html.escape(curl_cmd)

            html_content += f"""
        <div class="finding {severity}">
            <div class="finding-header" onclick="toggleFinding({idx})">
                <div class="finding-title">
                    <span>#{idx}</span>
                    <span>{vuln_type}</span>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                    <span class="cvss-score">CVSS {cvss_score}</span>
                </div>
                <div class="finding-url">{url}</div>
            </div>
            <div class="finding-body" id="finding-{idx}">
                <div class="section">
                    <div class="section-title">Description</div>
                    <p>{description}</p>
                </div>
                
                <div class="section">
                    <div class="section-title">Evidence</div>
                    <div class="evidence">{evidence}</div>
                </div>
                
                <div class="section">
                    <div class="section-title">Payload</div>
                    <div class="code-block">
                        <pre>{payload}</pre>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Proof of Concept (curl)</div>
                    <div class="code-block">
                        <pre id="curl-{idx}">{curl_cmd_escaped}</pre>
                    </div>
                    <button class="copy-btn" onclick="copyCurl({idx})">📋 Copy curl Command</button>
                </div>
                
                <div class="section">
                    <div class="section-title">CVSS v3.1 Vector</div>
                    <div class="code-block">
                        <pre>{html.escape(cvss_vector)}</pre>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">Remediation</div>
                    <p>{html.escape(finding.get("remediation", "Consult security best practices for this vulnerability type."))}</p>
                </div>
            </div>
        </div>
"""

        html_content += """
        <div class="footer">
            <p>Generated by ZEVS v2.0 PRO - Professional Vulnerability Scanner</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
    
    <script>
        function toggleFinding(id) {
            const body = document.getElementById('finding-' + id);
            body.classList.toggle('active');
        }
        
        function copyCurl(id) {
            const curlText = document.getElementById('curl-' + id).textContent;
            navigator.clipboard.writeText(curlText).then(() => {
                alert('curl command copied to clipboard!');
            });
        }
        
        // Auto-expand first critical/high finding
        document.addEventListener('DOMContentLoaded', () => {
            const firstFinding = document.querySelector('.finding.critical, .finding.high');
            if (firstFinding) {
                const body = firstFinding.querySelector('.finding-body');
                if (body) body.classList.add('active');
            }
        });
    </script>
</body>
</html>
"""

        return html_content


# Test
if __name__ == "__main__":
    # Sample findings
    test_findings = [
        {
            "type": "SQL Injection",
            "severity": "CRITICAL",
            "url": "https://example.com/api/users?id=1",
            "description": "SQL injection vulnerability allows unauthorized database access",
            "evidence": "MySQL error: You have an error in your SQL syntax",
            "payload": "id=1' OR '1'='1",
            "method": "GET",
            "headers": {"User-Agent": "ZEVS/2.0"},
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "remediation": "Use parameterized queries or prepared statements",
        },
        {
            "type": "XSS",
            "severity": "MEDIUM",
            "url": "https://example.com/search?q=test",
            "description": "Reflected XSS allows script injection",
            "evidence": "<script>alert(1)</script> reflected in response",
            "payload": "q=<script>alert(1)</script>",
            "method": "GET",
            "headers": {"User-Agent": "ZEVS/2.0"},
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "remediation": "Implement proper output encoding and Content-Security-Policy",
        },
    ]

    scan_stats = {"total_requests": 1523, "duration": "5m 32s"}

    html_report = HTMLReportGenerator.generate_report(
        "https://example.com", test_findings, scan_stats
    )

    # Save test report
    with open("test_report.html", "w", encoding="utf-8") as f:
        f.write(html_report)

    print("Test report generated: test_report.html")
