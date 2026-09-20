import requests
import dns.resolver
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

DEFAULT_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "corp", "cloud", "app", "mobile", "shop", "db", "auth", "git",
    "jira", "jenkins", "vault", "internal", "s3", "m", "cpanel", "beta",
    "demo", "api-dev", "api-staging", "cdn", "static", "assets", "img",
    "files", "docs", "support", "help", "status", "monitor", "grafana",
    "kibana", "elastic", "redis", "mysql", "postgres", "backend", "gateway"
]

def load_wordlist(path: Optional[str]) -> List[str]:
    """Load subdomain wordlist from file if provided, else use built-in default list."""
    if path and os.path.exists(path):
        with open(path, 'r', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"  [+] Loaded {len(words)} entries from custom wordlist: {path}")
        return words
    return DEFAULT_SUBDOMAINS

def get_hackertarget_subdomains(domain: str) -> List[str]:
    """HackerTarget Subdomain Engine."""
    subdomains = set()
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if sub and domain in sub:
                        subdomains.add(sub)
    except Exception as e:
        print(f"  [-] HackerTarget lookup failed: {e}")
    return list(subdomains)

def get_alienvault_subdomains(domain: str) -> List[str]:
    """AlienVault OTX Threat Intelligence Subdomain Engine."""
    subdomains = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname')
                if hostname and domain in hostname:
                    subdomains.add(hostname)
    except Exception as e:
        print(f"  [-] AlienVault OTX lookup failed: {e}")
    return list(subdomains)

def get_crtsh_subdomains(domain: str) -> List[str]:
    """crt.sh Certificate Transparency log lookup — usually gives the most subdomains."""
    subdomains = set()
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                for line in name.split('\n'):
                    line = line.strip().lstrip('*.')
                    if line and domain in line:
                        subdomains.add(line)
    except Exception as e:
        print(f"  [-] crt.sh lookup failed: {e}")
    return list(subdomains)

def check_dns_live(subdomain: str, retries: int = 2, timeout: float = 4.0) -> tuple[str, bool, List[str]]:
    """DNS Resolution with retry — checks A record, falls back to CNAME chain."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for attempt in range(retries):
        try:
            answers = resolver.resolve(subdomain, 'A')
            ip_list = [ip.address for ip in answers]
            return (subdomain, True, ip_list)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return (subdomain, False, [])  # definitive - don't retry
        except Exception:
            continue  # timeout/temp error - retry
    return (subdomain, False, [])

def enumerate_subdomains(domain: str, threads: int = 25, wordlist_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Aggregate Threat Intelligence APIs + Wordlist Brute-Force."""
    print(f"\n[*] [SUBDOMAIN ENGINE] Aggregating Passive DNS & Threat Intelligence for: {domain}")

    ht_subs = get_hackertarget_subdomains(domain)
    otx_subs = get_alienvault_subdomains(domain)
    crtsh_subs = get_crtsh_subdomains(domain)
    print(f"  [+] HackerTarget: {len(ht_subs)} | AlienVault: {len(otx_subs)} | crt.sh: {len(crtsh_subs)}")

    raw_subdomains = set(ht_subs + otx_subs + crtsh_subs)

    wordlist = load_wordlist(wordlist_path)
    for word in wordlist:
        raw_subdomains.add(f"{word}.{domain}")

    print(f"[*] Resolving DNS for {len(raw_subdomains)} gathered subdomains using {threads} threads...")
    live_results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(check_dns_live, list(raw_subdomains))
        for sub, is_live, ips in results:
            if is_live:
                print(f"  [LIVE] {sub} -> {', '.join(ips)}")
                live_results.append({'subdomain': sub, 'ips': ips})

    print(f"[+] Total Active Subdomains Identified: {len(live_results)}")
    return live_results
