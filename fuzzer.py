import requests
import random
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_PATHS = [
    "admin/", "login.php", "admin.php", "robots.txt", "sitemap.xml",
    "artists.php", "cart.php", "categories.php", "disclaimer.php",
    "guestbook.php", "userinfo.php", "AJAX/", "pictures/", "search.php",
    ".env", ".git/HEAD", "config.php", "phpinfo.php", "backup.sql"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0"
]

def check_single_path(domain: str, path: str, timeout: int = 8) -> tuple[str, int, int]:
    protocols = [f"http://{domain}", f"https://{domain}"]
    
    for base in protocols:
        target_endpoint = f"{base.rstrip('/')}/{path}"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        try:
            # allow_redirects=False keeps 301/302 from polluting results with main domain redirects
            response = requests.get(target_endpoint, timeout=timeout, allow_redirects=False, headers=headers, verify=False)
            
            # Only record if 200 OK or 403 Forbidden (Actual endpoint existing)
            if response.status_code in [200, 403, 401]:
                return (target_endpoint, response.status_code, len(response.content))
        except Exception:
            continue
    return ("", 0, 0)

def fuzz_hidden_files(domain: str, threads: int = 15) -> List[Dict[str, Any]]:
    print(f"\n[*] [ACTIVE FUZZER ENGINE] Fuzzing Valid Endpoints (Excluding Dummy Redirects) for: {domain}")
    discovered_files = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_single_path, domain, path) for path in TARGET_PATHS]
        for future in futures:
            url, status_code, length = future.result()
            if status_code > 0:
                indicator = "[DISCOVERED ENDPOINT]"
                if any(x in url for x in ['admin', 'login', 'userinfo', 'config', '.env', '.git']):
                    indicator = "[HIGH-VALUE TARGET]"
                    
                print(f"  {indicator} Status: {status_code} | Size: {length} bytes -> {url}")
                discovered_files.append({'url': url, 'status_code': status_code, 'size': length})

    if not discovered_files:
        print("  [-] No direct/exposed sensitive endpoints identified.")
        
    return discovered_files
