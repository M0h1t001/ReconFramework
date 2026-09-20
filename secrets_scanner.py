import re
import requests
from typing import List, Dict, Any
from utils import info, success, warning, critical

# Regex signatures for commonly leaked secrets in frontend JS files.
# Each finding is flagged with a severity so you know what to prioritize.
SECRET_PATTERNS = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "AWS Secret Key": (r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Firebase Database URL": (r"[a-z0-9-]+\.firebaseio\.com", "MEDIUM"),
    "Slack Token": (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "CRITICAL"),
    "Stripe API Key": (r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "Generic Bearer Token": (r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}", "MEDIUM"),
    "JWT Token": (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "MEDIUM"),
    "Private Key Block": (r"-----BEGIN (RSA|EC|DSA|OPENSSH)? ?PRIVATE KEY-----", "CRITICAL"),
    "Generic API Key Assignment": (r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]", "HIGH"),
    "Basic Auth Credentials in URL": (r"https?://[a-zA-Z0-9._%-]+:[a-zA-Z0-9._%-]+@", "HIGH"),
}

def scan_js_for_secrets(js_urls: List[str], timeout: int = 8) -> List[Dict[str, Any]]:
    """Download each JS file and scan its content for leaked secrets/tokens."""
    print(info(f"[SECRET SCANNER] Scanning {len(js_urls)} JavaScript files for leaked secrets..."))
    findings = []

    for js_url in js_urls:
        try:
            resp = requests.get(js_url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            if resp.status_code != 200:
                continue
            content = resp.text

            for secret_name, (pattern, severity) in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    # Mask the match so we don't print full raw secrets to the terminal/logs
                    sample = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    masked = sample[:6] + "..." + sample[-4:] if len(sample) > 12 else "***"

                    log_line = f"{secret_name} found in {js_url} -> {masked}"
                    if severity == "CRITICAL":
                        print(critical(log_line))
                    elif severity == "HIGH":
                        print(warning(log_line))
                    else:
                        print(info(log_line))

                    findings.append({
                        "type": secret_name,
                        "severity": severity,
                        "source_file": js_url,
                        "match_preview": masked,
                        "count": len(matches)
                    })
        except Exception:
            continue

    if not findings:
        print(success("No obvious secrets/tokens found in scanned JS files."))
    else:
        print(warning(f"Total potential secret leaks found: {len(findings)} — manually verify each before reporting."))

    return findings
