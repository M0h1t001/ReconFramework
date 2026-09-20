import re
import requests
import random
from typing import List, Dict, Any
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"
]

def scrape_js_and_secrets(domain: str) -> Dict[str, Any]:
    print(f"\n[*] [JS & OSINT SCRAPER] Scraping JavaScript Files & Endpoints for: {domain}")
    found_js = set()
    protocols = [f"http://{domain}", f"https://{domain}"]
    
    for base in protocols:
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            resp = requests.get(base, timeout=10, headers=headers, verify=False)
            if resp.status_code == 200:
                js_files = re.findall(r'src=["\'](.*?\.js)["\']', resp.text)
                for js in js_files:
                    if not js.startswith('http'):
                        js = f"{base.rstrip('/')}/{js.lstrip('/')}"
                    found_js.add(js)
                    
                print(f"  [+] Discovered {len(found_js)} JavaScript Assets")
                for js in list(found_js)[:5]:
                    print(f"    -> {js}")
                break
        except Exception:
            continue

    return {'js_files': list(found_js)}
