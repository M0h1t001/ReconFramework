# ReconFramework

**Automated Bug Bounty & Reconnaissance Framework** — a modular Python toolkit that automates the recon phase of bug bounty hunting: subdomain enumeration, port scanning, technology fingerprinting, security header/SSL auditing, JS secret scanning, CORS misconfiguration checks, subdomain takeover detection, historical URL harvesting, and OSINT gathering.

```
======================================================
   AUTOMATED BUG BOUNTY & RECONNAISSANCE FRAMEWORK   
======================================================
```

## ⚠️ Legal Disclaimer

This tool is intended **strictly for authorized security testing** — targets you own, or targets where you have **explicit written permission** (e.g. an active bug bounty program with the domain in scope on HackerOne/Bugcrowd/Intigriti, or a signed penetration testing agreement).

Running this tool against domains without authorization is **illegal** in most jurisdictions (e.g. under the Computer Fraud and Abuse Act in the US, the IT Act 2000 in India, and equivalent laws elsewhere) and may violate the target's Terms of Service, even for passive-looking checks. The author takes no responsibility for misuse. **Always confirm scope before scanning.**

## Features

| Module | What it does |
|---|---|
| `subdomains.py` | Aggregates subdomains via crt.sh, HackerTarget, AlienVault OTX + wordlist brute-force, resolves DNS live |
| `ports.py` | Multithreaded scan of common service ports |
| `server_info.py` | Resolves IP, grabs HTTP headers/banners |
| `tech_detect.py` | Fingerprints CMS/frameworks (WordPress, Laravel, Spring Boot, etc.) |
| `headers_audit.py` | Flags missing security headers (HSTS, CSP, X-Frame-Options, etc.) |
| `ssl_audit.py` | Checks certificate expiry, issuer, and weak TLS protocol versions |
| `cors.py` | Detects CORS misconfigurations (reflected origin + credentials allowed) |
| `takeover.py` | Detects dangling CNAMEs vulnerable to subdomain takeover |
| `fuzzer.py` | Probes for common sensitive/hidden endpoints |
| `wayback.py` | Harvests historical parameterized URLs from the Wayback Machine |
| `js_scraper.py` + `secrets_scanner.py` | Scrapes JS assets and scans them for leaked API keys/tokens (AWS, Google, Slack, Stripe, JWTs, etc.) |
| `osint.py` | WHOIS lookup + public email harvesting |
| `reporter.py` | Saves the full aggregated scan as a JSON report *(currently disabled in `main.py` — enable by uncommenting the import/call if you want persistent reports)* |

## Installation

```bash
git clone https://github.com/M0h1t001/ReconFramework.git
cd ReconFramework

python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

```bash
python main.py -d target.com
```

Optional flags:

```bash
python main.py -d target.com -t 30 -w /path/to/custom_wordlist.txt
```

| Flag | Description | Default |
|---|---|---|
| `-d`, `--domain` | Target domain (required) | — |
| `-t`, `--threads` | Threads for subdomain resolution | `20` |
| `-w`, `--wordlist` | Custom subdomain wordlist file | built-in list |

## Sample Output

```
[*] [SUBDOMAIN ENGINE] Aggregating Passive DNS & Threat Intelligence for: target.com
  [+] HackerTarget: 50 | AlienVault: 12 | crt.sh: 318
[*] Resolving DNS for 413 gathered subdomains using 20 threads...
  [LIVE] api.target.com -> 142.251.127.100
...
[*] [SECURITY HEADERS AUDIT] Checking response headers on: target.com
[-] Missing HSTS — site vulnerable to SSL-stripping / downgrade attacks
```

## Roadmap

- [ ] HTML/PDF report export
- [ ] Nuclei template integration for automated vuln validation
- [ ] Screenshot capture of live subdomains
- [ ] Multi-domain batch scanning (`-l targets.txt`)
- [ ] Rate-limiting / delay controls between requests

## Contributing

Pull requests are welcome. Please open an issue first for major changes.

## License

Distributed under the MIT License — see [LICENSE](LICENSE) for details.
