# ZEVS v4.0 - Professional Web Vulnerability Scanner with WAF Bypass

Production-ready async vulnerability scanner with WAF-aware bypass payload system.

## What's New in v4.0

### WAF-Aware Bypass Payload System
- **Enhanced WAF Detection**: Detects 11 different WAFs from headers and response body
- **Automatic Payload Selection**: Loads WAF-specific bypass techniques automatically
- **Smart Rate Limiting**: Auto-adjusts request rate based on detected WAF
- **Comprehensive Coverage**: Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5 BIG-IP, Sucuri, Azure WAF, Wordfence, Fortiweb, Barracuda

### New Features
- **RCE Testing**: New Remote Code Execution vulnerability test with WAF bypass
- **WAF Info in Reports**: Shows detected WAF and bypass status in HTML reports
- **13 Vulnerability Tests**: Added RCE to existing 12 tests

## Installation

```bash
pip install httpx rich urllib3
```

## Quick Start

```bash
# Basic scan with automatic WAF detection
python zevs_v4.py https://example.com

# Fast scan
python zevs_v4.py https://example.com --threads 20 --rate 10

# Stealth mode
python zevs_v4.py https://example.com --stealth
```

## How It Works

1. **Crawl**: Discovers URLs and parameters
2. **WAF Detection**: Automatically detects WAF (Step 1.5)
3. **Payload Selection**: Loads WAF-specific bypass payloads
4. **Vulnerability Testing**: Tests 13 vulnerability types with bypass techniques
5. **Reporting**: Generates HTML + JSON reports with WAF information

## Vulnerability Tests (13)

| Test | WAF Bypass | CVSS |
|------|-----------|------|
| SQL Injection | ✓ | 10.0 CRITICAL |
| XSS | ✓ | 6.0 MEDIUM |
| SSRF | ✓ | 8.1 HIGH |
| RCE | ✓ | 10.0 CRITICAL |
| XXE | - | 10.0 CRITICAL |
| IDOR | - | 7.1 HIGH |
| LFI | ✓ | 7.5 HIGH |
| Open Redirect | - | 4.7 MEDIUM |
| CORS | - | 6.5 MEDIUM |
| GraphQL | - | 7.1 HIGH |
| JWT | - | 8.8 HIGH |
| Security Headers | - | 3.1 LOW |
| Exposed Secrets | - | 8.8 HIGH |

## WAF Bypass Examples

### SQL Injection
- **Cloudflare**: `/*!50000UNION*/+/*!50000SELECT*/+1,2,3--`
- **Akamai**: `-1' UNION%23%0ASELECT 1,2,3--`
- **AWS WAF**: `-1' OR 1.e(1)`
- **ModSecurity**: `' UNION%0ASELECT%0A1,2,3--`

### XSS
- **Cloudflare**: `<svg/onload=alert(1)>`
- **Sucuri**: `<script>alert(String.fromCharCode(88,83,83))</script>`
- **Wordfence**: `<script>alert\`1\`</script>`

### RCE
- **Cloudflare**: `;cat${IFS}/etc/passwd`
- **ModSecurity**: `/???/??t /???/passwd`
- **AWS WAF**: `;cat$IFS/etc$IFS/passwd`

### LFI
- **Cloudflare**: `..%2F..%2F..%2Fetc%2Fpasswd`
- **Akamai**: `..%252F..%252Fetc%252Fpasswd`
- **ModSecurity**: `..;/../etc/passwd`

## Example Output

```
🛡️  Step 1.5: WAF Detection
⚠️  WAF detected: Cloudflare
   Loading Cloudflare-specific bypass payloads

🔍 Step 2: Vulnerability Scanning
→ Testing SQL Injection (with Cloudflare bypasses)
→ Testing XSS (with Cloudflare bypasses)
→ Testing RCE (with Cloudflare bypasses)
...

📊 Step 3: Processing Results
✓ Found 8 unique vulnerabilities

📝 Step 4: Generating Reports
✓ HTML report: ./zevs_report_example.com_20260405_170400.html
✓ JSON report: ./zevs_report_example.com_20260405_170400.json
```

## HTML Report Features

- **WAF Detection**: Shows detected WAF in report header
- **Bypass Status**: Each finding shows "WAF Bypassed: [WAF Name]"
- **CVSS Scores**: Full CVSS v3.1 scoring for each finding
- **curl PoCs**: One-liner curl commands for reproduction
- **Dark Theme**: Professional dark-themed interface
- **Collapsible Findings**: Click to expand/collapse details

## CLI Options

```
usage: zevs_v4.py [-h] [--threads THREADS] [--rate RATE] [--jwt JWT]
                  [--stealth] [--output OUTPUT] [--modules MODULES] [--resume]
                  target

options:
  --threads N        Concurrent requests (default: 10)
  --rate N           Requests per second (default: 5)
  --jwt TOKEN        Test specific JWT token
  --stealth          Ultra-slow mode (1 req/sec)
  --output DIR       Output directory (default: current)
  --modules LIST     Comma-separated modules to run
  --resume           Resume from checkpoint
```

## Architecture

### Components
1. **CVSSCalculator** - Full CVSS v3.1 mathematical scoring
2. **WAFDetector** - Enhanced WAF detection (11 signatures)
3. **WAFPayloads** - WAF-specific bypass payload database
4. **SmartRateLimiter** - Adaptive rate limiting with WAF awareness
5. **Crawler** - Async URL and parameter discovery
6. **JWTAttacker** - Complete JWT security testing
7. **VulnModules** - 13 async vulnerability tests
8. **HTMLReportGenerator** - Professional report generation
9. **ZevsScanner** - Main orchestrator

### WAFPayloads Class

```python
# Automatic payload selection
payloads = WAFPayloads.get("sqli", detected_waf)
# Returns WAF-specific payloads first, then generic fallbacks

# Supported vulnerability types:
# - sqli, xss, rce, lfi, ssrf
```

## Supported WAFs

| WAF | Detection Method | Bypass Payloads |
|-----|-----------------|-----------------|
| Cloudflare | cf-ray header | SQLi, XSS, RCE, LFI |
| Akamai | x-akamai header | SQLi, LFI |
| AWS WAF | x-amzn header | SQLi, RCE |
| ModSecurity | Body signature | SQLi, RCE, LFI |
| Imperva | incap_ses cookie | SQLi |
| F5 BIG-IP | bigipserver header | SQLi, LFI |
| Sucuri | x-sucuri-id header | SQLi, XSS, LFI |
| Azure WAF | x-azure-ref header | SQLi, SSRF |
| Wordfence | wfvl header | SQLi, XSS, LFI |
| Fortiweb | fortiwafsid header | SQLi |
| Barracuda | bni cookie | SQLi, SSRF |

## Legal Disclaimer

**This tool is for AUTHORIZED security testing ONLY.**

- Only scan systems you own or have written permission to test
- Unauthorized access to computer systems is ILLEGAL
- You accept full responsibility for your actions
- The authors are not responsible for misuse

## Technical Details

- **Language**: Python 3.10+
- **HTTP Client**: httpx (async)
- **Concurrency**: asyncio
- **UI**: rich library
- **File Size**: 54 KB (1615 lines)
- **Dependencies**: httpx, rich, urllib3

## Version History

- **v4.0** (2026-04-05) - WAF-aware bypass payload system, RCE testing
- **v3.0** (2026-04-03) - Complete rewrite with async, httpx, CVSS v3.1
- **v2.0** - Previous version with requests library
- **v1.0** - Initial release

## Contributing

This is a single-file tool designed for simplicity. To modify:

1. Edit `zevs_v4.py`
2. Test with `python -m py_compile zevs_v4.py`
3. Run against test targets

## Author

ZEVS Team - Professional security tools for authorized testing

## License

MIT License
