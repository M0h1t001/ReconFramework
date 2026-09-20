import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def audit_cors_misconfiguration(subdomains: list) -> list:
    """Audit subdomains for CORS Misconfigurations allowing arbitrary origin reflection."""
    print(f"\n[*] [CORS AUDITOR] Auditing {len(subdomains)} live targets for CORS Misconfigurations...")
    vulnerable_targets = []
    fake_origin = "https://evil-attacker.com"

    for sub in subdomains:
        protocols = [f"https://{sub}", f"http://{sub}"]
        for target_url in protocols:
            try:
                headers = {'Origin': fake_origin, 'User-Agent': 'Mozilla/5.0'}
                res = requests.get(target_url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                
                acao = res.headers.get('Access-Control-Allow-Origin', '')
                acac = res.headers.get('Access-Control-Allow-Credentials', '')

                # Critical Check: Reflected Origin + Credentials Allowed
                if acao == fake_origin or acao == 'null':
                    if acac.lower() == 'true':
                        print(f"  [CRITICAL VULNERABILITY] CORS Misconfiguration Identified! -> {target_url}")
                        print(f"    -> Access-Control-Allow-Origin: {acao}")
                        print(f"    -> Access-Control-Allow-Credentials: {acac}")
                        vulnerable_targets.append({'url': target_url, 'origin': acao, 'credentials': acac})
                        break
            except Exception:
                continue

    if not vulnerable_targets:
        print("  [+] No high-severity CORS misconfigurations identified.")
        
    return vulnerable_targets
