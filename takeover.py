import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

TAKEOVER_SIGNATURES = {
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "AWS S3 Bucket": "The specified bucket does not exist",
    "Heroku": "Heroku | No such app",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "Whatever you were looking for doesn't currently exist",
    "WordPress": "Do you want to register"
}

def check_subdomain_takeover(subdomain: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Check if a subdomain CNAME points to a vulnerable dangling service."""
    result = {'subdomain': subdomain, 'vulnerable': False, 'service': None}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(subdomain, 'CNAME')
    except Exception:
        # No CNAME record at all -> definitely not a takeover candidate, skip HTTP entirely
        return result

    for rdata in answers:
        cname = str(rdata.target).rstrip('.')
        for protocol in ['https://', 'http://']:
            try:
                resp = requests.get(f"{protocol}{subdomain}", timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
                for service, signature in TAKEOVER_SIGNATURES.items():
                    if signature in resp.text:
                        print(f"  [CRITICAL] Subdomain Takeover Vulnerability Identified! -> {subdomain} ({service})")
                        result.update({'vulnerable': True, 'service': service, 'cname': cname})
                        return result
            except Exception:
                continue
    return result

def scan_subdomain_takeovers(subdomains: List[str], threads: int = 25) -> List[Dict[str, Any]]:
    """Scan list of live subdomains for subdomain takeover vulnerabilities — threaded for speed."""
    print(f"\n[*] Auditing {len(subdomains)} subdomains for Subdomain Takeover vulnerabilities (threaded)...")
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_subdomain_takeover, subdomains)
        for res in results:
            if res['vulnerable']:
                vulnerabilities.append(res)

    if not vulnerabilities:
        print("  [+] No Subdomain Takeover vulnerabilities detected.")
    return vulnerabilities
