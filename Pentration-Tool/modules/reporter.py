import html
import logging
import json
from typing import Any, Dict, List

log = logging.getLogger(__name__)

# --- Remediation Advice Database ---
REMEDIATION_ADVICE: Dict[str, Dict[str, Any]] = {
    "DEFAULT": {
        "summary": "No specific remediation advice available for this finding.",
        "details": [
            "Please investigate this issue manually to determine the best course of action."
        ]
    },
    "SQLi (Error-Based)": {
        "summary": "Use Parameterized Queries (Prepared Statements) to prevent user input from being interpreted as SQL code.",
        "details": [
            "Never concatenate or format user input directly into SQL strings.",
            "Use a data access layer (e.g., an ORM) that handles parameterization automatically.",
            "Configure your database user with the minimum permissions necessary (e.g., no 'DROP' or 'GRANT' privileges for a web user).",
            "In production, disable detailed database errors from being sent to the user."
        ]
    },
    "SQLi (Boolean-Based)": {
        "summary": "Use Parameterized Queries (Prepared Statements). This vulnerability is the same as Error-Based SQLi, just harder to detect.",
        "details": [
            "All remediation steps for Error-Based SQLi apply here.",
            "Implement input validation to ensure user-supplied values (like IDs) match the expected format (e.g., are numeric)."
        ]
    },
    "XSS (Reflected, simple)": {
        "summary": "Implement Context-Aware Output Encoding to neutralize malicious scripts.",
        "details": [
            "Before rendering any user-supplied data in an HTML response, encode it based on the context where it will be placed.",
            "HTML Body: `requests` becomes `&lt;requests&gt;`.",
            "HTML Attribute: `\"` becomes `&quot;`.",
            "JavaScript String: `'` becomes `\\'`.",
            "Use a modern web framework (like React, Vue, Angular) which often handles this automatically.",
            "Implement a strong Content Security Policy (CSP) to block inline scripts and untrusted domains."
        ]
    },
    "XSS (Reflected, in_tag)": {
        "summary": "Implement Context-Aware Output Encoding. This is a variation of Reflected XSS.",
        "details": [
            "All remediation steps for 'XSS (Reflected, simple)' apply.",
            "Pay special attention to user input that is placed inside HTML attributes (e.g., `<input value='USER_INPUT'>`)."
        ]
    },
    "Missing: Content-Security-Policy": {
        "summary": "Implement a strong Content Security Policy (CSP) to mitigate XSS and data injection attacks.",
        "details": [
            "A CSP tells the browser which sources of content (scripts, styles, images) are trusted.",
            "Start with a strict policy: `Content-Security-Policy: default-src 'self'`",
            "Gradually add trusted domains as needed: `script-src 'self' trusted-scripts.com;`",
            "Avoid `'unsafe-inline'` and `'unsafe-eval'` whenever possible."
        ]
    },
    "Missing: Strict-Transport-Security": {
        "summary": "Implement HTTP Strict Transport Security (HSTS) to force all connections over HTTPS.",
        "details": [
            "This header prevents downgrade attacks and cookie hijacking.",
            "Example Header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
            "Ensure all subdomains are also served over HTTPS before adding `includeSubDomains`."
        ]
    },
    "Missing: X-Frame-Options": {
        "summary": "Implement `X-Frame-Options` or a CSP `frame-ancestors` directive to prevent Clickjacking.",
        "details": [
            "Clickjacking tricks a user into clicking something different from what they perceive.",
            "Set the header to: `X-Frame-Options: DENY` (no framing) or `X-Frame-Options: SAMEORIGIN` (allow framing only by your own site)."
        ]
    },
    "Missing: X-Content-Type-Options": {
        "summary": "Set the `X-Content-Type-Options: nosniff` header.",
        "details": [
            "This header prevents the browser from 'MIME-sniffing' the content type.",
            "It protects against attacks where a user-uploaded file (e.g., an 'image') is actually a script."
        ]
    },
    "Missing: Referrer-Policy": {
        "summary": "Set a `Referrer-Policy` to control how much referrer information is sent with requests.",
        "details": [
            "This protects user privacy and can prevent leaking sensitive information from URLs.",
            "A good default policy is: `Referrer-Policy: strict-origin-when-cross-origin`"
        ]
    },
    "Missing: Permissions-Policy": {
        "summary": "Set a `Permissions-Policy` to control which browser features (e.g., camera, microphone, geolocation) the page can use.",
        "details": [
            "This helps prevent third-party content from using sensitive features without permission.",
            "Example: `Permissions-Policy: microphone=(), camera=(), geolocation=()`"
        ]
    },
    "Insecure: Cookie (No HttpOnly)": {
        "summary": "Set the `HttpOnly` flag on all sensitive cookies.",
        "details": [
            "The `HttpOnly` flag prevents client-side scripts (like JavaScript) from accessing the cookie.",
            "This is a critical defense against XSS, as it stops attackers from stealing session cookies."
        ]
    },
    "Insecure: Cookie (No Secure)": {
        "summary": "Set the `Secure` flag on all sensitive cookies.",
        "details": [
            "The `Secure` flag ensures the cookie is only sent over HTTPS.",
            "This prevents it from being intercepted in plain text over an unsecured connection."
        ]
    },
    "Exposed Path": {
        "summary": "Review and restrict access to sensitive paths and directories.",
        "details": [
            "Paths like `/.git/`, `/.env/`, or `/admin/` should not be publicly accessible.",
            "Configure your web server (e.g., Nginx, Apache) to return a 403 Forbidden or 404 Not Found for these paths.",
            "Ensure directory listing is disabled."
        ]
    }
}


class HTMLReporter:
    """
    Generates a single, self-contained HTML report from the
    master 'report_context' dictionary.
    """
    def __init__(self, context: Dict[str, Any], filename: str):
        self.context = context
        self.filename = filename
        self.report_parts: List[str] = []
        log.info(f"HTMLReporter initialized for {self.context.get('target_url')}")

    def _get_remediation(self, finding_key: str) -> Dict[str, Any]:
        """Fetches remediation advice, falling back to a default."""
        base_key = finding_key.split('(')[0].strip() if isinstance(finding_key, str) else "DEFAULT"
        if isinstance(finding_key, str) and finding_key in REMEDIATION_ADVICE:
            return REMEDIATION_ADVICE[finding_key]
        if base_key in REMEDIATION_ADVICE:
            return REMEDIATION_ADVICE[base_key]
        return REMEDIATION_ADVICE["DEFAULT"]

    def _h(self, text: Any) -> str:
        """Shortcut for HTML-escaping text."""
        return html.escape(str(text))

    def _build_header(self) -> None:
        target_url = self.context.get('target_url', 'Unknown Target')
        scan_time = self.context.get('scan_start_time', 'Unknown Time')
        self.report_parts.append(f"""
        <header>
            <h1>Penetration Test Report</h1>
            <div class="header-info">
                <strong>Target:</strong> <a href="{self._h(target_url)}" target="_blank">{self._h(target_url)}</a>
            </div>
            <div class="header-info">
                <strong>Scan Date:</strong> {self._h(scan_time)}
            </div>
        </header>
        """)

    def _build_summary(self) -> None:
        """Builds the top-level summary box with the overall grade."""
        passive_results = self.context.get('passive_scan_results', {}) or {}
        grade = passive_results.get('grade', {}).get('grade', 'N/A')
        summary = passive_results.get('grade', {}).get('summary', 'Scan did not complete.')
        active_findings_count = len(self.context.get('active_scan_findings', []) or [])
        open_ports_count = len(self.context.get('port_scan_results', []) or [])
        grade_class = f"grade-{str(grade).lower()}"

        self.report_parts.append(f"""
        <section class="card summary-card">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-box">
                    <span class="summary-title">Overall Grade</span>
                    <span class="summary-value {grade_class}">{self._h(grade)}</span>
                </div>
                <div class="summary-box">
                    <span class="summary-title">Active Vulnerabilities</span>
                    <span class="summary-value count-high">{self._h(active_findings_count)}</span>
                </div>
                <div class="summary-box">
                    <span class="summary-title">Open Ports</span>
                    <span class="summary-value count-medium">{self._h(open_ports_count)}</span>
                </div>
            </div>
            <p><strong>Finding:</strong> {self._h(summary)}</p>
        </section>
        """)

    def _build_active_findings(self) -> None:
        """Builds the detailed active findings section."""
        findings = self.context.get('active_scan_findings', []) or []
        if not findings:
            self.report_parts.append("<section class='card'><h2>Active Vulnerabilities (SQLi, XSS)</h2><p class='status-good'>No active vulnerabilities found.</p></section>")
            return

        self.report_parts.append("<section class='card'><h2>Active Vulnerabilities (SQLi, XSS)</h2>")
        for finding in findings:
            ftype = finding.get('type', 'Unknown Finding')
            finding_type = self._h(ftype)
            remediation = self._get_remediation(ftype)
            self.report_parts.append(f"""
            <div class="finding-box finding-high">
                <button class="accordion">
                    <span class="finding-title">{finding_type}</span>
                    <span class="finding-location">{self._h(finding.get('url'))}</span>
                </button>
                <div class="panel">
                    <h3>Details</h3>
                    <table>
                        <tr><th>URL</th><td>{self._h(finding.get('url'))}</td></tr>
                        <tr><th>Parameter</th><td>{self._h(finding.get('param'))}</td></tr>
                        <tr><th>Method</th><td>{self._h(finding.get('method'))}</td></tr>
                        <tr><th>Evidence</th><td><pre>{self._h(finding.get('evidence'))}</pre></td></tr>
                    </table>
                    <h3>Remediation</h3>
                    <p><strong>{self._h(remediation.get('summary'))}</strong></p>
                    <ul>
                        {''.join(f"<li>{self._h(detail)}</li>" for detail in remediation.get('details', []))}
                    </ul>
                </div>
            </div>
            """)
        self.report_parts.append("</section>")

    def _build_passive_findings(self) -> None:
        """Builds the passive scanner results (headers, cookies)."""
        passive = self.context.get('passive_scan_results', {}) or {}
        if not passive or 'missing_headers' not in passive:
            if passive.get('error'):
                self.report_parts.append(f"<section class='card'><h2>Passive Scan (Headers, Cookies)</h2><p class='status-bad'>Passive scan failed to run: {self._h(passive.get('error'))}</p></section>")
            else:
                self.report_parts.append("<section class='card'><h2>Passive Scan (Headers, Cookies)</h2><p class='status-bad'>Passive scan returned no data.</p></section>")
            return

        self.report_parts.append("<section class='card'><h2>Passive Scan (Headers, Cookies)</h2>")

        # Missing Headers
        for header in passive.get('missing_headers', []) or []:
            remediation = self._get_remediation(f"Missing: {header}")
            self.report_parts.append(f"""
            <div class="finding-box finding-medium">
                <button class="accordion">
                    <span class="finding-title">Missing Security Header: {self._h(header)}</span>
                </button>
                <div class="panel">
                    <h3>Remediation</h3>
                    <p><strong>{self._h(remediation.get('summary'))}</strong></p>
                    <ul>
                        {''.join(f"<li>{self._h(detail)}</li>" for detail in remediation.get('details', []))}
                    </ul>
                </div>
            </div>
            """)

        # Insecure Cookies
        for cookie in passive.get('cookies', []) or []:
            if not cookie.get('httpOnly'):
                remediation = self._get_remediation("Insecure: Cookie (No HttpOnly)")
                self.report_parts.append(f"""
                <div class="finding-box finding-medium">
                    <button class="accordion">
                        <span class="finding-title">Insecure Cookie: '{self._h(cookie.get('name'))}' (Missing HttpOnly)</span>
                    </button>
                    <div class="panel">
                        <h3>Remediation</h3>
                        <p><strong>{self._h(remediation.get('summary'))}</strong></p>
                        <ul>{''.join(f"<li>{self._h(detail)}</li>" for detail in remediation.get('details', []))}</ul>
                    </div>
                </div>
                """)
            if not cookie.get('secure'):
                remediation = self._get_remediation("Insecure: Cookie (No Secure)")
                self.report_parts.append(f"""
                <div class="finding-box finding-low">
                    <button class="accordion">
                        <span class="finding-title">Insecure Cookie: '{self._h(cookie.get('name'))}' (Missing Secure)</span>
                    </button>
                    <div class="panel">
                        <h3>Remediation</h3>
                        <p><strong>{self._h(remediation.get('summary'))}</strong></p>
                        <ul>{''.join(f"<li>{self._h(detail)}</li>" for detail in remediation.get('details', []))}</ul>
                    </div>
                </div>
                """)

        # Exposed Paths
        for path in passive.get('sensitive_paths', []) or []:
            remediation = self._get_remediation("Exposed Path")
            self.report_parts.append(f"""
            <div class="finding-box finding-medium">
                <button class="accordion">
                    <span class="finding-title">Exposed Path Found: {self._h(path.get('path'))} (Status: {self._h(path.get('status'))})</span>
                </button>
                <div class="panel">
                    <h3>Details</h3>
                    <p>The path <strong>{self._h(path.get('path'))}</strong> was found at <a href="{self._h(path.get('url'))}" target="_blank">{self._h(path.get('url'))}</a>.</p>
                    <h3>Remediation</h3>
                    <p><strong>{self._h(remediation.get('summary'))}</strong></p>
                    <ul>{''.join(f"<li>{self._h(detail)}</li>" for detail in remediation.get('details', []))}</ul>
                </div>
            </div>
            """)
        self.report_parts.append("</section>")

    def _build_port_scan(self) -> None:
        """Builds the table of open ports."""
        ports = self.context.get('port_scan_results', []) or []
        self.report_parts.append("<section class='card'><h2>Port Scan Results</h2>")
        if not ports:
            self.report_parts.append("<p class='status-good'>No open ports found in the scanned range.</p></section>")
            return

        self.report_parts.append("<table><tr><th>Port</th><th>Protocol</th><th>Status</th><th>Banner/Service</th></tr>")
        for port in ports:
            self.report_parts.append(f"""
            <tr>
                <td>{self._h(port.get('port'))}</td>
                <td>{self._h(port.get('protocol'))}</td>
                <td class="status-open">{self._h(port.get('status'))}</td>
                <td><pre>{self._h(port.get('banner'))}</pre></td>
            </tr>
            """)
        self.report_parts.append("</table></section>")

    def _build_all_data(self) -> None:
        """Builds a 'Raw Data' section for debugging."""
        self.report_parts.append("""
        <section class="card">
            <h2>Full Scan Data (JSON)</h2>
            <button class="accordion">View Raw JSON Output</button>
            <div class="panel">
                <pre class="raw-json">
        """)
        safe_context = dict(self.context)  # shallow copy
        # Normalize sets in crawl_results.metadata to lists
        try:
            crawl = safe_context.get('crawl_results', {}) or {}
            meta = crawl.get('metadata', {}) or {}
            for key, value in list(meta.items()):
                if isinstance(value, set):
                    meta[key] = list(value)
        except Exception:
            pass
        # Safely dump JSON using default=str to handle datetimes, etc.
        self.report_parts.append(html.escape(json.dumps(safe_context, indent=2, default=str)))
        self.report_parts.append("</pre></div></section>")

    def generate_report(self) -> None:
        """Assembles all the parts into a final HTML file."""
        log.info(f"Generating HTML report at {self.filename}")
        try:
            self._build_header()
            self._build_summary()
            self._build_active_findings()
            self._build_passive_findings()
            self._build_port_scan()
            self._build_all_data()

            final_html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>PenTest Report - {self._h(self.context.get('target_host'))}</title>
                <style>{self._get_css()}</style>
            </head>
            <body>
                <main>
                    {''.join(self.report_parts)}
                </main>
                <script>{self._get_js()}</script>
            </body>
            </html>
            """
            with open(self.filename, 'w', encoding='utf-8') as f:
                f.write(final_html)
            log.info("Report generation successful.")
        except Exception as e:
            log.error(f"Failed to generate HTML report: {e}", exc_info=True)

    def _get_css(self) -> str:
        """Returns the embedded CSS for the report."""
        return """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
               background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }
        main { max-width: 1000px; margin: 0 auto; }
        header { background-color: #fff; border-bottom: 3px solid #007bff; padding: 20px;
                 border-radius: 8px 8px 0 0; }
        header h1 { margin: 0; color: #007bff; }
        .header-info { margin-top: 10px; font-size: 1.1em; }
        .card { background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                margin-top: 20px; }
        .card h2 { margin: 0; padding: 20px; border-bottom: 1px solid #eee; }
        .card p, .card ul { padding: 0 20px 20px 20px; margin: 10px 0; line-height: 1.6; }
        .card ul { padding-left: 40px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                        gap: 20px; padding: 20px; }
        .summary-box { display: flex; flex-direction: column; align-items: center;
                       padding: 20px; background-color: #f9f9f9; border-radius: 8px; }
        .summary-title { font-size: 0.9em; color: #666; margin-bottom: 10px; }
        .summary-value { font-size: 2.5em; font-weight: bold; }
        .count-high { color: #d9534f; }
        .count-medium { color: #f0ad4e; }
        .grade-a { color: #5cb85c; }
        .grade-b { color: #78c478; }
        .grade-c { color: #f0ad4e; }
        .grade-d { color: #ee9336; }
        .grade-f { color: #d9534f; }
        .status-good { color: #5cb85c; font-weight: bold; }
        .status-bad { color: #d9534f; font-weight: bold; }
        .finding-box { border: 1px solid #ddd; border-radius: 6px; margin: 20px; }
        .finding-high { border-left: 5px solid #d9534f; }
        .finding-medium { border-left: 5px solid #f0ad4e; }
        .finding-low { border-left: 5px solid #007bff; }
        .accordion { background-color: #f9f9f9; color: #333; cursor: pointer; padding: 18px;
                     width: 100%; border: none; text-align: left; outline: none;
                     font-size: 1.1em; font-weight: bold; transition: 0.4s;
                     display: flex; justify-content: space-between; align-items: center; }
        .accordion:hover { background-color: #f1f1f1; }
        .accordion:after { content: '+'; font-size: 20px; color: #777; }
        .accordion.active:after { content: "−"; }
        .panel { padding: 0 18px; background-color: white; max-height: 0;
                 overflow: hidden; transition: max-height 0.3s ease-out; }
        .panel h3 { color: #007bff; border-bottom: 1px solid #eee; padding-bottom: 5px; }
        .finding-title { flex-grow: 1; }
        .finding-location { font-size: 0.9em; font-weight: normal; color: #555; margin-left: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f7f7f7; font-weight: bold; }
        td.status-open { color: #d9534f; font-weight: bold; }
        pre { background-color: #2b2b2b; color: #f1f1f1; padding: 15px; border-radius: 6px;
              overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        .raw-json { max-height: 500px; }
        """

    def _get_js(self) -> str:
        """Returns the embedded JavaScript for the accordion."""
        return """
        var acc = document.getElementsByClassName("accordion");
        for (var i = 0; i < acc.length; i++) {
            acc[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var panel = this.nextElementSibling;
                if (panel.style.maxHeight) {
                    panel.style.maxHeight = null;
                } else {
                    panel.style.maxHeight = panel.scrollHeight + "px";
                }
            });
        }
        """
