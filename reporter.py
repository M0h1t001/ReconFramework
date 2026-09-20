import json
import os
from datetime import datetime
from typing import Dict, Any

def save_report_as_json(data: Dict[str, Any], domain: str) -> str:
    """Save aggregated reconnaissance data into a formatted JSON report."""
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{reports_dir}/{domain}_{timestamp}.json"

    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n[+] Reconnaissance report successfully generated: {filename}")
        return filename
    except Exception as e:
        print(f"[-] Failed to write JSON report: {e}")
        return ""
