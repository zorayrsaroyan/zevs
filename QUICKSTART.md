# ZEVS v3.0 - Quick Start Guide

## Installation (30 seconds)

```bash
# Install dependencies
pip install httpx rich

# Verify installation
python zevs_v3.py --help
```

## Basic Usage

### 1. Simple Scan
```bash
python zevs_v3.py https://example.com
```

This will:
- Crawl the target (max 200 URLs)
- Run all 12 vulnerability tests
- Generate HTML + JSON reports
- Rate limit at 5 req/sec

### 2. Fast Scan (Bug Bounty)
```bash
python zevs_v3.py https://example.com --threads 20 --rate 10
```

### 3. Stealth Scan (Evade Detection)
```bash
python zevs_v3.py https://example.com --stealth
```

This sets:
- 1 request/second
- 1 concurrent thread
- High jitter

### 4. Custom Output Directory
```bash
python zevs_v3.py https://example.com --output ./reports
```

## Understanding Output

### Console Output
```
🕷️  Step 1: Crawling https://example.com
✓ Found 47 URLs, 23 parameters

🔍 Step 2: Vulnerability Scanning
→ Testing SQL Injection
→ Testing XSS
...

📊 Step 3: Processing Results
✓ Found 12 unique vulnerabilities

📝 Step 4: Generating Reports
✓ HTML report: ./zevs_report_example.com_20260403_195628.html
✓ JSON report: ./zevs_report_example.com_20260403_195628.json
```

### HTML Report
Open the HTML file in your browser to see:
- Summary dashboard (CRITICAL/HIGH/MEDIUM/LOW counts)
- Detailed findings with CVSS scores
- curl PoC commands
- Remediation guidance

### JSON Report
Machine-readable format for automation:
```json
{
  "target": "https://example.com",
  "findings": [
    {
      "type": "SQL Injection",
      "url": "https://example.com/search?q=test",
      "param": "q",
      "payload": "' OR '1'='1",
      "evidence": "mysql syntax error...",
      "cvss_score": 10.0,
      "severity": "CRITICAL",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    }
  ],
  "stats": {
    "urls_crawled": 47,
    "vulns_found": 12
  }
}
```

## Common Scenarios

### Testing a Login Page
```bash
python zevs_v3.py https://example.com/login
```

### Testing an API
```bash
python zevs_v3.py https://api.example.com
```

### Testing with JWT Token
```bash
python zevs_v3.py https://example.com --jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## What Gets Tested?

### 1. SQL Injection
- Error-based: `' OR '1'='1`
- Time-based: `' AND SLEEP(5)--`

### 2. XSS
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`

### 3. SSRF
- AWS metadata: `http://169.254.169.254/latest/meta-data/`
- GCP metadata: `http://metadata.google.internal/`

### 4. XXE
- File read via DOCTYPE injection

### 5. IDOR
- Numeric ID enumeration (1, 2, 100, 999)

### 6. LFI
- `../../../etc/passwd`
- `..\..\..\windows\win.ini`

### 7. Open Redirect
- `https://evil.com`
- `//evil.com`

### 8. CORS
- Origin reflection check

### 9. GraphQL
- Introspection query

### 10. JWT
- None algorithm bypass
- Weak secret bruteforce
- kid injection

### 11. Security Headers
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options

### 12. Exposed Secrets
- `/.env`
- `/.git/config`
- `/api-docs`
- `/swagger.json`

## Tips

### Avoid Getting Blocked
```bash
# Use stealth mode
python zevs_v3.py https://example.com --stealth

# Or manually set low rate
python zevs_v3.py https://example.com --rate 2 --threads 3
```

### Focus on Specific Modules
```bash
python zevs_v3.py https://example.com --modules sqli,xss,ssrf
```

### Resume Interrupted Scan
```bash
python zevs_v3.py https://example.com --resume
```

## Troubleshooting

### "Connection refused"
- Target may be down
- Check firewall/VPN settings

### "Too many requests (429)"
- Reduce rate: `--rate 1`
- Use stealth mode: `--stealth`

### "SSL verification failed"
- ZEVS disables SSL verification by default (for testing)
- This is normal for security scanners

### No vulnerabilities found
- Target may be well-secured
- Try increasing crawl depth (edit max_depth in code)
- Check if target requires authentication

## Legal Reminder

**ONLY scan systems you own or have written permission to test.**

Unauthorized scanning is illegal and unethical.

## Next Steps

1. Read full documentation: `README_v3.md`
2. Review the code: `zevs_v3.py` (well-commented)
3. Customize for your needs
4. Report bugs/features on GitHub

## Support

- GitHub: https://github.com/zorayrsaroyan/zevs
- Issues: Report bugs via GitHub Issues
- License: MIT

---

Built with ❤️ by ZEVS Team | 2026-04-03
