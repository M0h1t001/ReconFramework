import re
import requests
import whois
from typing import Dict, Any, List

def fetch_whois_data(domain: str) -> Dict[str, Any]:
    """Retrieve WHOIS registration details and ownership metadata."""
    print(f"\n[*] Fetching WHOIS data for: {domain}")
    whois_info = {}
    try:
        w = whois.whois(domain)
        whois_info['registrar'] = w.registrar
        whois_info['creation_date'] = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
        whois_info['expiration_date'] = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date)
        whois_info['emails'] = w.emails if w.emails else []
        
        print(f"  [+] Registrar: {whois_info['registrar']}")
        print(f"  [+] Creation Date: {whois_info['creation_date']}")
        print(f"  [+] Expiry Date: {whois_info['expiration_date']}")
    except Exception as e:
        print(f"  [-] WHOIS lookup failed: {e}")
        whois_info['error'] = str(e)

    return whois_info

def harvest_emails_from_web(url: str, timeout: int = 5) -> List[str]:
    """Scrape public emails with HTTP/HTTPS protocol fallback."""
    print(f"\n[*] Scraping public contact emails from: {url}")
    found_emails = set()
    
    protocols = [f"http://{url}", f"https://{url}"] if not url.startswith('http') else [url]

    for target_url in protocols:
        try:
            response = requests.get(target_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                matches = re.findall(email_pattern, response.text)
                
                for email in matches:
                    if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.js', '.css')):
                        found_emails.add(email)

                print(f"  [+] Identified {len(found_emails)} public email address(es)")
                for email in found_emails:
                    print(f"    -> {email}")
                break
        except Exception:
            continue

    return list(found_emails)

def run_osint_analysis(domain: str) -> Dict[str, Any]:
    """Execute WHOIS lookup and email harvesting modules."""
    whois_data = fetch_whois_data(domain)
    emails = harvest_emails_from_web(domain)
    
    return {
        'domain': domain,
        'whois': whois_data,
        'harvested_emails': emails
    }

if __name__ == "__main__":
    target = input("Enter target domain for OSINT analysis (e.g., example.com): ").strip()
    if target:
        run_osint_analysis(target)
