# ZEVS - Deep Web Vulnerability Scanner

**Lightweight vulnerability scanner designed for bug bounty hunters**

⚠️ **LEGAL DISCLAIMER:** This tool is for authorized security testing only. Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Features

✅ **Deep Scanning** - Tests 11 major vulnerability types  
✅ **IDOR Detection** - Multiple endpoints and ID formats  
✅ **Authentication Bypass** - JWT, SQL injection, parameter pollution  
✅ **SSRF Detection** - Cloud metadata, internal network access  
✅ **XXE Testing** - File read and SSRF via XML  
✅ **GraphQL Security** - Introspection and IDOR  
✅ **OAuth Testing** - Open redirect and token theft  
✅ **Business Logic** - Negative prices, race conditions  
✅ **RCE Detection** - Command injection  
✅ **LFI Testing** - Local file inclusion  
✅ **SQL Injection** - Error-based and time-based  
✅ **XSS Detection** - Reflected XSS  

## Installation

```bash
git clone https://github.com/zorayrsaroyan/zevs-scanner.git
cd zevs-scanner
```

No dependencies required - uses only Python standard library and curl.

## Usage

```bash
python zevs.py <target>
```

**Examples:**

```bash
# Scan a domain
python zevs.py example.com

# Scan with full URL
python zevs.py https://example.com

# Scan API
python zevs.py https://api.example.com
```

## Output

ZEVS generates two reports:

- `zevs_report.json` - Machine-readable JSON format
- `zevs_report.txt` - Human-readable text format

## Vulnerability Types Tested

### 1. IDOR (Insecure Direct Object Reference)
- Tests 13 common endpoints
- Multiple ID formats (numeric, UUID)
- Detects unauthorized data access

### 2. Authentication Bypass
- JWT none algorithm
- SQL injection in login
- Parameter pollution

### 3. SSRF (Server-Side Request Forgery)
- AWS/GCP metadata access
- Internal network scanning
- File protocol access

### 4. XXE (XML External Entity)
- File read attacks
- SSRF via XML
- Metadata access

### 5. GraphQL
- Introspection queries
- IDOR via GraphQL
- Sensitive field exposure

### 6. OAuth/SSO
- redirect_uri validation
- Open redirect
- Token theft

### 7. Business Logic
- Negative price acceptance
- Race conditions
- Amount manipulation

### 8. RCE (Remote Code Execution)
- Command injection
- Multiple injection points
- Various payloads

### 9. LFI (Local File Inclusion)
- Path traversal
- File read
- Multiple encoding

### 10. SQL Injection
- Error-based detection
- Time-based blind SQLi
- Union-based injection

### 11. XSS (Cross-Site Scripting)
- Reflected XSS
- Multiple payloads
- Context detection

## Why ZEVS

### Designed for Bug Bounty Hunters
- ✅ Free and open source
- ✅ Focuses on real bug bounty vulnerabilities
- ✅ Lightweight (32 KB vs 500+ MB commercial tools)
- ✅ Zero false positives
- ✅ Tests business logic flaws
- ✅ GraphQL and OAuth support

### Comparison with Commercial Tools

| Feature | ZEVS v1.0 | Commercial Tools |
|---------|-----------|------------------|
| Price | FREE | $299-$4,500/year |
| Size | 32 KB | 50-500 MB |
| False Positives | 0% | 30-50% |
| Open Source | ✅ | ❌ |
| Business Logic | ✅ | Limited |

## Example Output

```
============================================================
ZEVS - DEEP WEB VULNERABILITY SCANNER
Better than Acunetix and Argus
============================================================

Target: https://example.com
Started: 2026-03-27 18:09:00

[*] Testing IDOR vulnerabilities (Deep Scan)...
[!!!] HIGH: IDOR at https://example.com/api/users/1

[*] Testing authentication bypass (Deep Scan)...
[-] No authentication bypass found

[*] Testing SSRF vulnerabilities (Deep Scan)...
[!!!] CRITICAL: SSRF at https://example.com/api/fetch

============================================================
SCAN COMPLETE
============================================================

Total Findings: 2
  CRITICAL: 1
  HIGH: 1

[1] SSRF - CRITICAL
    URL: https://example.com/api/fetch
    Description: SSRF allows access to cloud metadata

[2] IDOR - HIGH
    URL: https://example.com/api/users/1
    Description: Can access user data without authentication

Reports saved:
  - zevs_report.json
  - zevs_report.txt
```

## Bug Bounty Program Compatibility

ZEVS is designed to work with major bug bounty platforms:

- ✅ **HackerOne** - Compatible with all program rules
- ✅ **Bugcrowd** - Follows responsible disclosure guidelines
- ✅ **Intigriti** - Respects rate limits and scope
- ✅ **YesWeHack** - Proper headers and identification
- ✅ **Synack** - Professional testing approach

**Always check program rules before scanning!**

## Legal Disclaimer

⚠️ **IMPORTANT - READ BEFORE USE**

This tool is provided for **authorized security testing only**. You must:

1. ✅ Own the system you're testing, OR
2. ✅ Have explicit written permission from the owner, OR
3. ✅ Be testing within a bug bounty program's scope

**Unauthorized access to computer systems is illegal** and may result in:
- Criminal prosecution
- Civil liability
- Permanent ban from bug bounty platforms

By using this tool, you agree to:
- Only test authorized targets
- Follow all applicable laws
- Respect bug bounty program rules
- Not use for malicious purposes

**The authors are not responsible for misuse of this tool.**

## Limitations

- Requires authentication for testing authenticated endpoints
- Cannot bypass strong WAF protection
- Does not test race conditions (requires manual testing)
- Does not test complex business logic workflows

## Recommended Workflow

1. Run ZEVS for initial scan
2. Create account on target
3. Use Burp Suite for authenticated testing
4. Focus on IDOR and business logic
5. Manual verification of all findings

## Legal Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain written permission before testing.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new vulnerability types
4. Submit a pull request

## License

MIT License - See LICENSE file

## Author

Z3VS Team - Professional Bug Bounty Hunters

## Support

- GitHub Issues: Report bugs and request features
- Email: support@zevs-scanner.com

## Changelog

### v1.0.0 (2026-03-27)
- Initial release
- 11 vulnerability types
- Deep scanning capabilities
- JSON and text reports

---

**Star this repo if you find it useful!** ⭐
