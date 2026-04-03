# ZEVS v3.0 - Professional Web Vulnerability Scanner

Production-ready async vulnerability scanner built with Python 3.10+, httpx, and rich UI.

## Features

- **Full CVSS v3.1 Calculator** - Real mathematical scoring, not lookup tables
- **Smart Rate Limiting** - Adaptive throttling with WAF detection
- **Async Crawler** - Fast URL and parameter discovery
- **JWT Security Testing** - None algorithm, weak secrets, kid injection
- **12 Vulnerability Modules**:
  - SQL Injection (error-based + time-based)
  - XSS (reflected)
  - SSRF (cloud metadata)
  - XXE (file read)
  - IDOR (ID enumeration)
  - LFI (path traversal)
  - Open Redirect
  - CORS misconfiguration
  - GraphQL introspection
  - JWT vulnerabilities
  - Missing security headers
  - Exposed secrets (.env, .git, etc)
- **Professional HTML Reports** - Dark theme, collapsible findings, curl PoCs
- **JSON Export** - Machine-readable output

## Installation

```bash
pip install httpx rich
```

## Usage

### Basic Scan
```bash
python zevs_v3.py https://example.com
```

### Advanced Options
```bash
# High-speed scan
python zevs_v3.py https://example.com --threads 20 --rate 10

# Stealth mode (slow, evades detection)
python zevs_v3.py https://example.com --stealth

# Custom output directory
python zevs_v3.py https://example.com --output ./reports

# Test specific JWT
python zevs_v3.py https://example.com --jwt eyJhbGc...
```

### CLI Options

```
positional arguments:
  target             Target URL (e.g., https://example.com)

options:
  --threads N        Concurrent requests (default: 10)
  --rate N           Requests per second (default: 5)
  --jwt TOKEN        Test specific JWT token
  --stealth          Ultra-slow mode (1 req/sec)
  --output DIR       Output directory (default: current)
  --modules LIST     Comma-separated modules (default: all)
  --resume           Resume from checkpoint
```

## Architecture

### 1. CVSSCalculator
Full CVSS v3.1 implementation with presets for common vulnerabilities.

```python
score, severity, vector = CVSSCalculator.calculate_for_vuln("SQL Injection")
# Returns: (10.0, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
```

### 2. SmartRateLimiter
Adaptive rate limiting with exponential backoff on 429/503 responses.

- Random jitter (±30%)
- WAF detection (Cloudflare, Imperva, Akamai, AWS WAF)
- Gradual recovery on success

### 3. Crawler
Async URL discovery with form and parameter extraction.

- Respects robots.txt
- Max depth: 2
- Max URLs: 200
- Extracts all links, forms, and query parameters

### 4. JWTAttacker
Complete JWT security testing suite.

- Decode without verification
- None algorithm bypass (6 variants)
- Weak secret bruteforce (100+ common secrets)
- kid injection (path traversal, SQLi, /dev/null)
- Token forgery with found secrets

### 5. VulnModules
12 async vulnerability testing modules using real parameters from crawler.

All tests use discovered parameters - no hardcoded `?id=` or `?q=`.

### 6. HTMLReportGenerator
Professional dark-theme HTML reports with:

- Severity badges (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- CVSS scores per finding
- Collapsible sections
- curl PoC one-liners
- Remediation guidance

### 7. ZevsScanner
Main orchestrator coordinating all components.

## Output Files

After scan completion, you'll find:

```
zevs_report_example.com_20260403_195500.html  # HTML report
zevs_report_example.com_20260403_195500.json  # JSON export
zevs_example.com_20260403_195500.log          # Request log
```

## Legal Disclaimer

**This tool is for AUTHORIZED security testing ONLY.**

Unauthorized access to computer systems is ILLEGAL. By using this tool, you agree to:

- Test only systems you own
- Have written permission for all targets
- Comply with all applicable laws
- Accept full responsibility for your actions

The authors are not responsible for misuse or damage caused by this tool.

## Example Output

```
═══════════════════════════════════════════════════════════════
                    ZEVS v3.0 - LEGAL DISCLAIMER
═══════════════════════════════════════════════════════════════

This tool is for AUTHORIZED security testing ONLY.
Unauthorized access to computer systems is ILLEGAL.

🕷️  Step 1: Crawling https://example.com
✓ Found 47 URLs, 23 parameters

🔍 Step 2: Vulnerability Scanning
→ Testing SQL Injection
→ Testing XSS
→ Testing SSRF
...

📊 Step 3: Processing Results
✓ Found 12 unique vulnerabilities

📝 Step 4: Generating Reports
✓ HTML report: ./zevs_report_example.com_20260403_195500.html
✓ JSON report: ./zevs_report_example.com_20260403_195500.json

═══════════════════════════════════════════════════════════════
Scan Complete!
  URLs Crawled: 47
  Vulnerabilities: 12
═══════════════════════════════════════════════════════════════
```

## Technical Details

- **Language**: Python 3.10+
- **HTTP Client**: httpx (async)
- **Concurrency**: asyncio
- **UI**: rich library
- **File Size**: ~1400 lines, single file
- **Dependencies**: httpx, rich

## CVSS Scoring

All findings include accurate CVSS v3.1 scores calculated using the full formula:

- **CRITICAL**: 9.0-10.0
- **HIGH**: 7.0-8.9
- **MEDIUM**: 4.0-6.9
- **LOW**: 0.1-3.9
- **INFO**: 0.0

## Contributing

This is a single-file tool designed for simplicity. To modify:

1. Edit `zevs_v3.py`
2. Test with `python -m py_compile zevs_v3.py`
3. Run against test targets

## Version History

- **v3.0** (2026-04-03) - Complete rewrite with async, httpx, CVSS v3.1
- **v2.0** - Previous version with requests library
- **v1.0** - Initial release

## Author

ZEVS Team - Professional security tools for authorized testing

## License

MIT License - See LICENSE file for details
