import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 443: 'HTTPS', 3306: 'MySQL',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
}

def scan_single_port(ip: str, port: int, timeout: float = 3.0) -> tuple[int, bool, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return (port, True, COMMON_PORTS.get(port, 'Unknown'))
    except Exception:
        pass
    return (port, False, '')

def scan_target_ports(ip: str, threads: int = 10) -> List[Dict[str, Any]]:
    print(f"\n[*] [PORT SCANNER] Auditing Open Ports for IP: {ip}")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_single_port, ip, port) for port in COMMON_PORTS.keys()]
        for future in futures:
            port, is_open, service = future.result()
            if is_open:
                print(f"  [OPEN PORT IDENTIFIED] {port}/tcp -> Service: {service}")
                open_ports.append({'port': port, 'service': service})
                
    if not open_ports:
        print("  [-] No standard open ports identified on initial probe.")
        
    return open_ports
