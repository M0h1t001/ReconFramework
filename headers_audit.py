import requests
import urllib3
from typing import Dict, Any, List
from utils import info, success, warning, critical

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Headers that should be present on any hardened web app.
# Each maps to a short explanation of the risk if missing.
REQUIRED_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS — site vulnerable to SSL-stripping / downgrade attacks",
    "X-Frame-Options": "Missing X-Frame-Options — site vulnerable to Clickjacking",
    "X-Content-Type-Options": "Missing X-Content-Type-Options — vulnerable to MIME-sniffing attacks",
    "Content-Security-Policy": "Missing CSP — reduced protection against XSS/data-injection",
    "Referrer-Policy": "Missing Referrer-Policy — may leak full URL/path to third parties",
    "Permissions-Policy": "Missing Permissions-Policy — no restriction on browser feature access (camera/mic/geo)"
}

# Headers that leak information about the stack (not a vuln by itself, but useful recon)
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

def audit_security_headers(domain: str) -> Dict[str, Any]:
    """Check a target for missing security headers and info-disclosure headers."""
    print(info(f"[SECURITY HEADERS AUDIT] Checking response headers on: {domain}"))
    result = {"missing_headers": [], "info_disclosure": [], "checked_url": None}

    for scheme in ["https", "http"]:
        target_url = f"{scheme}://{domain}"
        try:
            res = requests.get(target_url, timeout=10, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
            result["checked_url"] = target_url
            present_headers = {h.lower(): v for h, v in res.headers.items()}

            for required, risk_msg in REQUIRED_HEADERS.items():
                if required.lower() not in present_headers:
                    print(warning(risk_msg))
                    result["missing_headers"].append({"header": required, "risk": risk_msg})

            for leak_header in INFO_LEAK_HEADERS:
                if leak_header.lower() in present_headers:
                    value = present_headers[leak_header.lower()]
                    print(warning(f"Info disclosure: {leak_header}: {value}"))
                    result["info_disclosure"].append({"header": leak_header, "value": value})

            break  # got a response, stop trying schemes
        except Exception:
            continue

    if not result["missing_headers"] and result["checked_url"]:
        print(success("All key security headers are present."))
    elif not result["checked_url"]:
        print(warning("Could not reach target to audit headers."))

    return result

