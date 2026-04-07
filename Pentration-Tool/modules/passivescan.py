import json
import logging
import socket
import ssl
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse
import random
import string
import requests
from typing import Tuple, Dict, Any, List, Optional

# module logger (configured by runall.py)
log = logging.getLogger(__name__)

def normalize_base(url: str) -> Tuple[str, str, str, Optional[int]]:
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname
    port = parsed.port
    if host is None:
        raise ValueError("Could not parse host from URL: " + url)
    base = f"{scheme}://{host}"
    if port:
        base = f"{base}:{port}"
    return base, scheme, host, port

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def fetch_home(url: str, session: requests.Session, timeout: int = 10) -> requests.Response:
    headers = {"User-Agent": "Passive-Security-Scanner/3.0"}
    resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
    resp.raise_for_status()
    return resp

def analyze_headers(resp: requests.Response) -> Tuple[Dict[str, Any], List[str]]:
    hdrs: Dict[str, Any] = {}
    missing: List[str] = []
    for h in SECURITY_HEADERS:
        val = resp.headers.get(h)
        if val:
            hdrs[h] = val
        else:
            hdrs[h] = "Missing"
            missing.append(h)
    return hdrs, missing

def analyze_cookies(resp: requests.Response) -> List[Dict[str, Any]]:
    cookies_info: List[Dict[str, Any]] = []
    for cookie in resp.cookies:
        # requests' cookie objects expose attrs; fallback checks for cookie._rest
        rest = getattr(cookie, "_rest", {}) or {}
        http_only = any(k.lower() == "httponly" for k in rest.keys()) or rest.get("HttpOnly", False)
        cookies_info.append({
            "name": cookie.name,
            "value_sample": (cookie.value[:8] + "...") if cookie.value else "",
            "secure": bool(getattr(cookie, "secure", False)),
            "httpOnly": bool(http_only)
        })
    return cookies_info

def tls_info_for_host(host: str, port: Optional[int] = None, timeout: int = 8) -> Dict[str, Any]:
    if port is None:
        port = 443
    info: Dict[str, Any] = {}
    target = (host, port)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(target, timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                info["cipher"] = cipher[0] if cipher else None
                info["protocol"] = ssock.version()
                cert = ssock.getpeercert() or {}
                info.update(parse_cert(cert))
                info["trusted"] = True
    except Exception as e:
        # Try unverified context to at least obtain cert info
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection(target, timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    info["cipher"] = cipher[0] if cipher else None
                    info["protocol"] = ssock.version()
                    cert = ssock.getpeercert() or {}
                    info.update(parse_cert(cert))
                    info["trusted"] = False
                    info["error"] = str(e)
        except Exception as e2:
            log.warning(f"TLS handshake failed for {host}:{port} -> {e2}")
            return {"error": str(e2)}
    return info

def parse_cert(cert: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not cert:
        return out
    not_after = cert.get("notAfter")
    if not_after:
        # Try a couple of common formats returned by getpeercert
        parsed_expiry = None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
            try:
                parsed_expiry = datetime.strptime(not_after, fmt)
                break
            except Exception:
                continue
        if parsed_expiry:
            days_left = (parsed_expiry - datetime.utcnow()).days
            out["cert_expiry"] = parsed_expiry.strftime("%Y-%m-%d")
            out["days_to_expiry"] = days_left
            out["expired"] = days_left < 0
    subject = cert.get("subject")
    issuer = cert.get("issuer")
    if subject:
        out["subject"] = tuple(tuple(x) for x in subject)
    if issuer:
        out["issuer"] = tuple(tuple(x) for x in issuer)
    return out

DEFAULT_PATHS = [
    "/admin", "/administrator", "/login", "/user/login", "/phpmyadmin", "/pma",
    "/config", "/backup", "/.git", "/.env", "/wp-admin", "/server-status", "/debug",
]

def probe_path(session: requests.Session, base: str, path: str, timeout: int = 6, not_found_signature: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    url = base.rstrip("/") + "/" + path.lstrip("/")
    headers = {"User-Agent": "Passive-Security-Scanner/3.0"}
    try:
        r = session.get(url, allow_redirects=False, timeout=timeout, headers=headers, verify=True)
    except Exception:
        return None
    status = r.status_code
    if status == 200 and not_found_signature:
        content_len = len(r.content)
        content_hash = hashlib.md5(r.content).hexdigest()
        if content_len == not_found_signature.get("len") and content_hash == not_found_signature.get("hash"):
            return None
    if status == 200 or (300 <= status < 400):
        return {"path": path, "status": status, "url": url, "location": r.headers.get("Location")}
    return None

def probe_paths_concurrent(session: requests.Session, base: str, paths: List[str], concurrency: int = 8, timeout: int = 6) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    not_found_signature: Optional[Dict[str, Any]] = None
    try:
        rand_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        random_url = base.rstrip("/") + "/" + rand_str
        r_base = session.get(random_url, timeout=timeout, verify=True, headers={"User-Agent": "Passive-Security-Scanner/3.0"})
        if r_base.status_code == 200:
            not_found_signature = {"len": len(r_base.content), "hash": hashlib.md5(r_base.content).hexdigest()}
            log.info(f"Established soft 404 baseline: len={not_found_signature['len']}, hash={not_found_signature['hash']}")
    except Exception as e:
        log.debug(f"Could not establish a soft 404 baseline: {e}")

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(probe_path, session, base, p, timeout, not_found_signature): p for p in paths}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                log.info(f"Exposed path found: {res['path']} -> {res['status']} ({res['url']})")
                found.append(res)
    return found

def compute_score(scan: Dict[str, Any]) -> Dict[str, Any]:
    max_points = {"headers": 30, "cookies": 15, "tls": 25, "paths": 20, "misc": 10}
    header_score = 0.0
    for h in SECURITY_HEADERS:
        val = scan.get("headers", {}).get(h, "Missing")
        if val != "Missing":
            if h == "Content-Security-Policy" and ("'unsafe-inline'" in str(val) or "data:" in str(val)):
                header_score += 2.5
            else:
                header_score += 5.0
    cookies = scan.get("cookies", [])
    cookie_score = max_points["cookies"]
    if cookies:
        flags_total = sum((1 if c.get("secure") else 0) + (1 if c.get("httpOnly") else 0) for c in cookies)
        max_flags = 2 * len(cookies)
        cookie_score = max_points["cookies"] * (flags_total / max_flags) if max_flags else max_points["cookies"]
    tls = scan.get("tls", {})
    tls_score = 0.0
    if tls and not tls.get("error"):
        if tls.get("expired") is False and tls.get("trusted"):
            tls_score += 15.0
        days = tls.get("days_to_expiry")
        if isinstance(days, int) and days > 7:
            tls_score += 5.0
        proto = str(tls.get("protocol", "")).lower()
        if "1.2" in proto or "1.3" in proto:
            tls_score += 5.0
    path_score = max(0.0, max_points["paths"] - 5.0 * len(scan.get("sensitive_paths", [])))
    misc_score = max_points["misc"] if cookies else 0.0
    total = header_score + cookie_score + tls_score + path_score + misc_score
    return {
        "score": round(total, 1),
        "breakdown": {
            "headers": round(header_score, 1),
            "cookies": round(cookie_score, 1),
            "tls": round(tls_score, 1),
            "paths": round(path_score, 1),
            "misc": round(misc_score, 1),
        },
    }

def grade_scan(scan: Dict[str, Any]) -> Dict[str, str]:
    score = scan.get("score", 0)
    if score >= 80:
        grade, summary = "A", "Excellent security posture."
    elif score >= 70:
        grade, summary = "B", "Good security posture, minor improvements needed."
    elif score >= 60:
        grade, summary = "C", "Average security posture. Key areas need attention."
    elif score >= 50:
        grade, summary = "D", "Below average. Significant improvements needed."
    else:
        grade, summary = "F", "Poor security posture with critical issues."
    return {"grade": grade, "summary": summary}

def run_scan(target_url: str, session: requests.Session, extra_paths: Optional[List[str]] = None, timeout: int = 10, concurrency: int = 8) -> Dict[str, Any]:
    base, scheme, host, port = normalize_base(target_url)
    result: Dict[str, Any] = {"url": base, "fetched_at": datetime.utcnow().isoformat() + "Z"}
    try:
        resp = fetch_home(base, session, timeout=timeout)
    except Exception as e:
        log.error(f"Failed to fetch {base}: {e}")
        return {"error": str(e)}
    result["headers"], result["missing_headers"] = analyze_headers(resp)
    result["cookies"] = analyze_cookies(resp)
    result["tls"] = tls_info_for_host(host, port if port else 443, timeout=timeout) if scheme == "https" else {}
    paths_to_check = list(dict.fromkeys((extra_paths or []) + DEFAULT_PATHS))
    result["sensitive_paths"] = probe_paths_concurrent(session, base, paths_to_check, concurrency=concurrency, timeout=timeout)
    score_obj = compute_score(result)
    result.update(score_obj)
    result["grade"] = grade_scan(result)
    return result