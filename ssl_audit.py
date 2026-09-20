import ssl
import socket
from datetime import datetime
from typing import Dict, Any
from utils import info, success, warning, critical

def audit_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """Check SSL/TLS certificate validity, expiry, and issuer info."""
    print(info(f"[SSL/TLS AUDIT] Inspecting certificate for: {domain}"))
    result = {"valid": False}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days

                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                result.update({
                    "valid": True,
                    "protocol": protocol,
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "subject": subject.get('commonName', domain),
                    "expires": cert['notAfter'],
                    "days_until_expiry": days_left
                })

                print(success(f"Issuer: {result['issuer']} | Protocol: {protocol}"))

                if days_left < 0:
                    print(critical(f"Certificate EXPIRED {abs(days_left)} days ago!"))
                elif days_left < 15:
                    print(warning(f"Certificate expires soon — only {days_left} days left."))
                else:
                    print(success(f"Certificate valid for {days_left} more days."))

                if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    print(critical(f"Weak/outdated protocol in use: {protocol}"))
                    result["weak_protocol"] = True

    except ssl.SSLCertVerificationError as e:
        print(critical(f"Certificate verification FAILED: {e}"))
        result["error"] = str(e)
    except Exception as e:
        print(warning(f"Could not establish SSL connection: {e}"))
        result["error"] = str(e)

    return result

