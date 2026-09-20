import argparse
from datetime import datetime
from subdomains import enumerate_subdomains
from server_info import analyze_target_host
from osint import run_osint_analysis
from ports import scan_target_ports
from takeover import scan_subdomain_takeovers
from fuzzer import fuzz_hidden_files
from wayback import harvest_wayback_urls
from cors import audit_cors_misconfiguration
from tech_detect import detect_technologies
from headers_audit import audit_security_headers
from ssl_audit import audit_ssl_certificate
from js_scraper import scrape_js_and_secrets
from secrets_scanner import scan_js_for_secrets
from utils import header
# from reporter import save_report_as_json   # <-- file save intentionally disabled, kept for later use

def main():
    print(header("AUTOMATED BUG BOUNTY & RECONNAISSANCE FRAMEWORK"))
    parser = argparse.ArgumentParser(description="Automated Bug Bounty & Active Recon Framework")
    parser.add_argument("-d", "--domain", required=True, help="Target domain name (e.g., target.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (Default: 20)")
    parser.add_argument("-w", "--wordlist", default=None, help="Optional custom subdomain wordlist file")

    args = parser.parse_args()
    target_domain = args.domain.strip()

    print(f"[*] Starting Bug Bounty Recon Scan on: {target_domain}")
    start_time = datetime.now()

    # 1. Host Analysis & Open Ports
    host_data = analyze_target_host(target_domain)
    if host_data.get('ip'):
        host_data['open_ports'] = scan_target_ports(host_data['ip'])

    # 2. Technology & Framework Fingerprinting
    detect_technologies(target_domain)

    # 3. Security Headers Audit
    audit_security_headers(target_domain)

    # 4. SSL/TLS Certificate Audit
    audit_ssl_certificate(target_domain)

    # 5. Directory & Sensitive Endpoint Fuzzing
    fuzz_hidden_files(target_domain)

    # 6. Historical URLs & Parameter Scraping (Wayback)
    harvest_wayback_urls(target_domain)

    # 7. JS File Scraping + Secret Scanning (NEW - the standout feature)
    js_data = scrape_js_and_secrets(target_domain)
    js_files = js_data.get('js_files', [])
    if js_files:
        scan_js_for_secrets(js_files)

    # 8. Subdomain Enumeration
    subdomains_info = enumerate_subdomains(target_domain, threads=args.threads, wordlist_path=args.wordlist)
    live_subdomains = [item['subdomain'] for item in subdomains_info]

    # 9. CORS Misconfiguration Audit + Takeover check on Live Subdomains
    if live_subdomains:
        audit_cors_misconfiguration(live_subdomains[:15])
        scan_subdomain_takeovers(live_subdomains)

    # 10. OSINT Analysis
    run_osint_analysis(target_domain)

    duration = datetime.now() - start_time
    print(f"\n[*] Full Bug Bounty Recon Scan completed in: {duration.total_seconds():.2f} seconds.")

if __name__ == "__main__":
    main()
