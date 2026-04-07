# ...existing code...
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
from typing import Optional, Dict, List

logging.getLogger("urllib3").setLevel(logging.WARNING)


def resolve_target(target: str) -> Optional[str]:
    """Resolve hostname or return IP string. Returns None on failure."""
    try:
        # If user passed a URL, extract hostname
        if "://" in target:
            from urllib.parse import urlparse
            target = urlparse(target).hostname or target
        ip = socket.gethostbyname(target)
        return ip
    except Exception as e:
        logging.error(f"Could not resolve target '{target}': {e}")
        return None


def tcp_connect(target_ip: str, port: int, timeout: float = 2.0) -> Optional[Dict]:
    """Simple TCP connect + optional rudimentary banner read."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            banner = "No banner detected"
            try:
                # Try a small recv for banner; do not send by default
                s.settimeout(0.8)
                data = s.recv(1024)
                if data:
                    banner = data.decode(errors="ignore").strip()
            except Exception:
                pass
            return {"port": port, "protocol": "TCP", "status": "open", "banner": banner}
    except Exception:
        pass
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return None


def http_probe(target: str, port: int, timeout: float = 3.0) -> Optional[Dict]:
    """Probe HTTP(S) services to get status and Server header."""
    try:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}"
        # For self-signed or odd certs we avoid failing; keep verify=True in production
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        server = r.headers.get("Server", "Unknown")
        return {
            "port": port,
            "protocol": "HTTP",
            "status": "open",
            "banner": f"HTTP {r.status_code} | {server}"
        }
    except Exception:
        return None


def udp_probe(target_ip: str, port: int, timeout: float = 2.0) -> Optional[Dict]:
    """Send lightweight UDP probes for common services."""
    probes = {
        53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',
        123: b'\x1b' + 47 * b'\0',
        161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x9f\x0b\x66\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
        69: b'\x00\x01test\x00octet\x00',
    }
    probe = probes.get(port, b"Hello")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(probe, (target_ip, port))
        try:
            data, _ = s.recvfrom(1024)
            banner = data.decode(errors="ignore")[:200] if data else "Response received"
            return {"port": port, "protocol": "UDP", "status": "open", "banner": banner}
        except socket.timeout:
            return {"port": port, "protocol": "UDP", "status": "open|filtered", "banner": "No response"}
    except Exception:
        pass
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return None


def scan_port(target: str, target_ip: str, port: int, mode: str = "tcp") -> Optional[Dict]:
    """Dispatch to appropriate probe based on mode/port."""
    if mode == "udp":
        return udp_probe(target_ip, port)
    # Prefer HTTP probe for common web ports
    if port in (80, 8080, 8000, 443):
        res = http_probe(target, port)
        if res:
            return res
    return tcp_connect(target_ip, port)


def hybrid_scanner(target: str, start_port: int = 1, end_port: int = 1024,
                   max_threads: int = 200, mode: str = "tcp") -> List[Dict]:
    """Perform a threaded port scan (tcp by default). Returns list of open ports."""
    target_ip = resolve_target(target)
    if not target_ip:
        return []

    logging.info(f"Starting {mode.upper()} scan on {target} ({target_ip}) ports {start_port}-{end_port}")
    open_ports: List[Dict] = []
    start_time = datetime.now()

    # Cap threads to a reasonable number
    max_workers = min(max_threads, (end_port - start_port + 1) or 1, 500)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, target, target_ip, port, mode): port
                   for port in range(start_port, end_port + 1)}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as e:
                logging.debug(f"Port scan worker error: {e}")
                continue
            if result:
                open_ports.append(result)
                logging.info(f"[PortScan] {result['protocol']} {result['port']:>5} OPEN | {result.get('banner','')[:120]}")

    end_time = datetime.now()
    logging.info(f"{mode.upper()} Scan complete in {(end_time - start_time).total_seconds():.2f}s")
    return sorted(open_ports, key=lambda x: x["port"])
# ...existing code...