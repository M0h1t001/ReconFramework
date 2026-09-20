import requests
from typing import List, Set

def harvest_wayback_urls(domain: str, limit: int = 25) -> Set[str]:
    """Fetch historical endpoints and parametrized URLs from Wayback Machine archive."""
    print(f"\n[*] [WAYBACK ARCHIVE] Harvesting Historical URLs & Parameters for: {domain}")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    parameterized_urls = set()

    try:
        response = requests.get(url, timeout=30)  # 120s was too long, 30 is enough + fails faster
        if response.status_code == 200 and response.text.strip():
            try:
                urls = response.json()
            except ValueError:
                print("  [-] Wayback returned non-JSON / empty response (likely no archived data).")
                return parameterized_urls

            if isinstance(urls, list) and len(urls) > 1:
                for u in urls[1:]:  # Skip header row
                    full_url = u[0]
                    if '?' in full_url and '=' in full_url:
                        parameterized_urls.add(full_url)

                print(f"  [+] Discovered {len(parameterized_urls)} Parameterized Endpoint URLs for Vulnerability Testing")
                for link in list(parameterized_urls)[:limit]:
                    print(f"    [PARAM URL] -> {link}")
            else:
                print("  [-] No archived URLs found for this domain.")
        else:
            print(f"  [-] Wayback returned status {response.status_code} or empty body.")
    except requests.exceptions.Timeout:
        print("  [-] Wayback Archive request timed out.")
    except Exception as e:
        print(f"  [-] Wayback Archive Retrieval Error: {e}")

    return parameterized_urls

