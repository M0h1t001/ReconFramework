import requests
import socket
import ssl
import random
from typing import Dict, Any, Optional
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/123.0"
]

def get_ip_address(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def inspect_http_headers(url: str, timeout: int = 12) -> Dict[str, Any]:
    header_data = {'status_code': None, 'server': 'Unknown', 'tech_stack': 'Unknown', 'headers': {}}
    protocols = [f"http://{url}", f"https://{url}"] if not url.startswith('http') else [url]

    for target_url in protocols:
        try:
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': '*/*'
            }
            response = requests.get(target_url, timeout=timeout, allow_redirects=True, headers=headers, verify=False)
            header_data['status_code'] = response.status_code
            header_data['headers'] = dict(response.headers)
            
            if 'Server' in response.headers:
                header_data['server'] = response.headers['Server']
            if 'X-Powered-By' in response.headers:
                header_data['tech_stack'] = response.headers['X-Powered-By']
            
            if response.status_code:
                break
        except requests.RequestException:
            continue

    return header_data

def analyze_target_host(domain: str) -> Dict[str, Any]:
    print(f"\n[*] [ADVANCED HOST INSPECTION] Analyzing Target: {domain}")
    ip_addr = get_ip_address(domain)
    print(f"  [+] Resolved IP Address: {ip_addr if ip_addr else 'Failed'}")
    
    http_info = inspect_http_headers(domain)
    print(f"  [+] HTTP Response Status: {http_info.get('status_code')}")
    print(f"  [+] Web Server Banner: {http_info.get('server')}")
    print(f"  [+] Tech Stack Identifier: {http_info.get('tech_stack')}")

    return {'domain': domain, 'ip': ip_addr, 'http': http_info}
