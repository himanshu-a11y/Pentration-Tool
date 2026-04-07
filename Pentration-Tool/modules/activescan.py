import requests
import logging
import random
import string

log = logging.getLogger(__name__)

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch_array()",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ora-00933: sql command not properly ended",
    "microsoft ole db provider for odbc drivers",
    "invalid characters found in text",
]


class SQLiDetector:
    def __init__(self, session):
        self.session = session
        self.session.headers["User-Agent"] = "Penetration-Tester/1.0 (ActiveScan)"

    def _send_request(self, method, url, params_or_data):
        try:
            if method.upper() == "GET":
                return self.session.get(url, params=params_or_data, timeout=10, allow_redirects=True)
            elif method.upper() == "POST":
                return self.session.post(url, data=params_or_data, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            log.warning(f"Request failed for {url} ({e})")
        return None

    def _check_error_based(self, target):
        url, method = target['url'], target['method']
        base_params = target['params'].copy()

        for param in base_params:
            test_params = base_params.copy()
            base_value = str(test_params.get(param, ""))
            payload = base_value + "'"
            test_params[param] = payload
            log.info(f"[SQLi-Error] Testing {method} {url} on param '{param}'")
            resp = self._send_request(method, url, test_params)
            if resp:
                for signature in SQL_ERROR_SIGNATURES:
                    if signature.lower() in resp.text.lower():
                        finding = {
                            "type": "SQLi (Error-Based)",
                            "url": url,
                            "method": method,
                            "param": param,
                            "base_params": target['params'].copy(),
                            "payload": payload,
                            "evidence": signature
                        }
                        log.warning(f"Potential SQLi (Error-Based) found at {url} on param '{param}'")
                        return finding
        return None

    def _check_boolean_based(self, target):
        url, method = target['url'], target['method']
        base_params = target['params'].copy()
        resp_base = self._send_request(method, url, base_params)
        if not resp_base:
            return None

        len_base = len(resp_base.content)
        for param in base_params:
            params_true = base_params.copy()
            base_value = str(params_true.get(param, ""))
            payload_true = base_value + " and 1=1"
            params_true[param] = payload_true
            log.info(f"[SQLi-Bool] Testing {method} {url} on param '{param}' (True)")
            resp_true = self._send_request(method, url, params_true)
            if not resp_true:
                continue
            len_true = len(resp_true.content)

            params_false = base_params.copy()
            payload_false = base_value + " and 1=2"
            params_false[param] = payload_false
            log.info(f"[SQLi-Bool] Testing {method} {url} on param '{param}' (False)")
            resp_false = self._send_request(method, url, params_false)
            if not resp_false:
                continue
            len_false = len(resp_false.content)

            if len_base == len_true and len_base != len_false:
                finding = {
                    "type": "SQLi (Boolean-Based)",
                    "url": url,
                    "method": method,
                    "param": param,
                    "base_params": target['params'].copy(),
                    "evidence": f"Response lengths: Base={len_base}, True={len_true}, False={len_false}"
                }
                log.warning(f"Potential SQLi (Boolean-Based) found at {url} on param '{param}'")
                return finding
        return None

    def scan_target(self, target):
        log.info(f"--- Starting SQLi Scan on {target['url']} ---")
        error_finding = self._check_error_based(target)
        if error_finding:
            return [error_finding]
        boolean_finding = self._check_boolean_based(target)
        if boolean_finding:
            return [boolean_finding]
        log.info(f"--- Finished SQLi Scan on {target['url']}. No issues found. ---")
        return []


class XSSDetector:
    def __init__(self, session):
        self.session = session
        self.session.headers["User-Agent"] = "Penetration-Tester/1.0 (ActiveScan)"
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        self.unique_token = f"XssToken{rand_str}"
        self.payloads = {
            "simple": self.unique_token,
            "in_tag": f'"><tagTest>{self.unique_token}</tagTest>'
        }
        log.info(f"XSS Detector initialized. Unique token: {self.unique_token}")

    def _send_request(self, method, url, params_or_data):
        try:
            if method.upper() == "GET":
                return self.session.get(url, params=params_or_data, timeout=10, allow_redirects=True)
            elif method.upper() == "POST":
                return self.session.post(url, data=params_or_data, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            log.warning(f"Request failed for {url} ({e})")
        return None

    def scan_target(self, target):
        log.info(f"--- Starting XSS Scan on {target['url']} ---")
        url, method = target['url'], target['method']
        base_params = target['params'].copy()
        findings = []

        for param in base_params:
            for payload_name, payload_str in self.payloads.items():
                test_params = base_params.copy()
                test_params[param] = payload_str
                log.info(f"[XSS-{payload_name}] Testing {method} {url} on param '{param}'")
                resp = self._send_request(method, url, test_params)
                if resp and payload_str in resp.text:
                    finding = {
                        "type": f"XSS (Reflected, {payload_name})",
                        "url": url,
                        "method": method,
                        "param": param,
                        "base_params": target['params'].copy(),
                        "payload": payload_str,
                        "evidence": f"Found token '{payload_str}' in response body."
                    }
                    log.warning(f"Potential XSS found at {url} on param '{param}'")
                    findings.append(finding)

        log.info(f"--- Finished XSS Scan on {target['url']} ---")
        return findings
