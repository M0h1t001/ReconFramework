import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TECH_SIGNATURES = {
    'WordPress': ['/wp-content/', '/wp-includes/', 'wp-embed.js'],
    'Jenkins': ['X-Jenkins', 'X-Hudson'],
    'Laravel': ['laravel_session', 'X-Powered-By: PHP'],
    'Spring Boot': ['Whitelabel Error Page', 'X-Application-Context'],
    'GraphQL': ['/graphql', 'GraphQL Playground'],
    'React': ['data-reactroot', 'react-dom'],
    'Grafana': ['Grafana', 'grafana_session']
}

def detect_technologies(domain: str) -> list:
    """Fingerprint underlying web technologies, frameworks, and CMS — tries HTTPS then HTTP."""
    print(f"\n[*] [TECH FINGERPRINTER] Auditing Tech Stack & Framework Signatures on: {domain}")
    detected_tech = set()

    for scheme in ["https", "http"]:  # HTTPS first now, most sites redirect/force it
        target_url = f"{scheme}://{domain}"
        try:
            res = requests.get(target_url, timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            headers_str = str(res.headers)
            body_str = res.text

            for tech, sigs in TECH_SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in headers_str.lower() or sig.lower() in body_str.lower():
                        detected_tech.add(tech)

            if res.status_code:
                break  # got a response, no need to try the other scheme
        except Exception as e:
            print(f"  [-] {scheme.upper()} probe failed: {e}")
            continue

    if detected_tech:
        print(f"  [+] Identified Technologies / CMS: {', '.join(detected_tech)}")
    else:
        print("  [-] No specific CMS or vulnerable framework signatures matched.")

    return list(detected_tech)
