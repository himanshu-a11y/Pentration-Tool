#!/usr/bin/env python3
import requests
import time
import os
import json
import logging
from datetime import datetime
from urllib.parse import urlparse, parse_qs # <-- FIX 1 (Import parse_qs)

# --- Import all your weekly modules ---
# Make sure they are in a folder named 'modules'
try:
    from modules.crawler import WebsiteAnalyzer
    from modules.portscanner import hybrid_scanner
    from modules.passivescan import run_scan as run_passive_scan, normalize_base
    from modules.activescan import SQLiDetector, XSSDetector
    from modules.poc import PoCModule
    from modules.reporter import HTMLReporter
except ImportError as e:
    print(f"Error: Could not import modules. Make sure you have the 'modules' folder")
    print(f"Details: {e}")
    print("Please check your project structure.")
    exit(1)

# --- Setup Logging ---
# Set up a main log file for the entire run
logging.basicConfig(
    filename='pentest_run.log',
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s"
)
# Also print INFO messages to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(levelname)s: %(message)s")
console_handler.setFormatter(console_formatter)
logging.getLogger().addHandler(console_handler)


def get_user_input():
    """Asks the user for all necessary scan parameters."""
    print("="*50)
    print("        Welcome to the Pen-Testing Suite")
    print("="*50)
    
    target_url = input("Enter the target base URL (e.g., http://testphp.vulnweb.com): ").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = "http://" + target_url
        
    try:
        crawl_depth = int(input("Enter crawl depth (e.g., 2): ").strip() or "2")
        start_port = int(input("Enter port scan start (e.g., 1): ").strip() or "1")
        end_port = int(input("Enter port scan end (e.g., 1024): ").strip() or "1024")
    except ValueError:
        logging.error("Invalid input. Depth and ports must be numbers.")
        return None, None, None, None, None
    
    run_poc_str = input("Do you want to run the (safe) PoC module on findings? (y/n): ").strip().lower()
    run_poc = True if run_poc_str == 'y' else False

    return target_url, crawl_depth, start_port, end_port, run_poc

def format_crawl_targets(crawler_results):
    """
    This is the CRITICAL bridge.
    It converts the crawler's output (Week 2) into the
    input needed by the active scanner (Week 5).
    """
    targets = []
    logging.info(f"Formatting {len(crawler_results)} crawled pages for active scanning...")
    
    for page in crawler_results:
        # 1. Add forms found on the page
        for form in page['forms']:
            params = {}
            for inp in form['inputs']:
                if inp['name']:
                    # Assign a default test value
                    if inp['type'] == 'email':
                        params[inp['name']] = "test@example.com"
                    elif inp['type'] == 'number':
                         params[inp['name']] = "123"
                    else:
                        params[inp['name']] = "test"
            
            target = {
                "url": form['action'],
                "method": form['method'],
                "params": params
            }
            targets.append(target)
            
        # 2. Add URLs with query parameters (e.g., search.php?id=1)
        parsed_url = urlparse(page['url'])
        if parsed_url.query:
             # <-- FIX 2 (Use parse_qs here)
             params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
             if params:
                target = {
                    "url": page['url'].split('?')[0],
                    "method": "GET",
                    "params": params
                }
                targets.append(target)

    # De-duplicate targets (same URL, method, and param names)
    unique_targets = []
    seen = set()
    for target in targets:
        # Create a unique key for each target
        key = (target['url'], target['method'], tuple(sorted(target['params'].keys())))
        if key not in seen:
            unique_targets.append(target)
            seen.add(key)
            
    logging.info(f"Found {len(unique_targets)} unique active scan targets (forms/URL params).")
    return unique_targets

def main():
    """Main controller function to run the entire scan."""
    try:
        target_url, crawl_depth, start_port, end_port, run_poc = get_user_input()
        if not target_url: # Handle bad input from get_user_input
            return
    except ValueError:
        logging.error("Invalid input. Please enter numbers for ports and depth.")
        return

    # This master dictionary will hold all results for the report
    report_context = {
        "target_url": target_url,
        "scan_start_time": datetime.now().isoformat(),
        "crawl_results": {},
        "port_scan_results": [],
        "passive_scan_results": {},
        "active_scan_findings": [],
        "poc_results": []
    }

    try:
        base_url, scheme, host, port = normalize_base(target_url)
        report_context['target_host'] = host
    except ValueError as e:
        logging.error(f"Invalid URL: {e}")
        return

    try:
        # Create a single, persistent session for all HTTP requests
        with requests.Session() as session:
            
            # --- Week 2: Run Web Crawler ---
            logging.info("--- Starting Week 2: Web Crawler ---")
            analyzer = WebsiteAnalyzer(session)
            crawl_results, crawl_meta = analyzer.crawl(base_url, base_url, 0, crawl_depth)
            report_context['crawl_results'] = {'pages': crawl_results, 'metadata': crawl_meta}
            logging.info(f"Crawler finished. Found {len(crawl_results)} pages.")

            # --- Week 3: Run Port Scanner ---
            logging.info("--- Starting Week 3: Port Scanner ---")
            port_results = hybrid_scanner(host, start_port, end_port, max_threads=100, mode="tcp")
            report_context['port_scan_results'] = port_results
            logging.info(f"Port scan finished. Found {len(port_results)} open ports.")

            # --- Week 4: Run Passive Header/Path Scanner ---
            logging.info("--- Starting Week 4: Passive Scanner ---")
            passive_results = run_passive_scan(base_url, session=session) # Pass the session
            report_context['passive_scan_results'] = passive_results
            logging.info(f"Passive scan finished. Grade: {passive_results.get('grade', {}).get('grade', 'N/A')}")
            
            # --- Prepare for Active Scan ---
            active_scan_targets = format_crawl_targets(crawl_results)
            if not active_scan_targets:
                logging.warning("No forms or URL parameters found by crawler. Skipping active scan.")
            else:
                # --- Week 5: Run Active Scanners (SQLi, XSS) ---
                logging.info("--- Starting Week 5: Active Scanners (SQLi/XSS) ---")
                sqli_scanner = SQLiDetector(session)
                xss_scanner = XSSDetector(session)
                
                all_findings = []
                for target in active_scan_targets:
                    all_findings.extend(sqli_scanner.scan_target(target))
                    all_findings.extend(xss_scanner.scan_target(target))
                    
                report_context['active_scan_findings'] = all_findings
                logging.info(f"Active scan finished. Found {len(all_findings)} potential vulnerabilities.")

                # --- Week 6: Run PoC Module ---
                if run_poc and all_findings:
                    logging.info("--- Starting Week 6: Proof-of-Concept (PoC) Module ---")
                    
                    # The allowlist is the host we are scanning. This is safe.
                    allowlist = [base_url]
                    poc_runner = PoCModule(session, allowlist=allowlist)
                    poc_results = []
                    
                    # We will only run PoC on the *first* finding for this demo
                    # You could loop this and ask for each one
                    first_finding = all_findings[0]
                    poc_result = poc_runner.run_poc(first_finding) # This has the 'yes' prompt
                    poc_results.append(poc_result)
                    
                    report_context['poc_results'] = poc_results
                    logging.info("PoC module finished.")
                elif not all_findings:
                    logging.info("Skipping PoC: No active vulnerabilities found.")
                else:
                    logging.info("Skipping PoC: User did not select 'y'.")

            # --- Week 7: Generate Final Report ---
            logging.info("--- Starting Week 7: Report Generation ---")
            report_filename = f"Scan_Report_{host.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            reporter = HTMLReporter(report_context, report_filename)
            reporter.generate_report()
            
            logging.info(f"Report generation complete. File saved as: {report_filename}")
            print("\n" + "="*50)
            print("         Scan Complete!")
            print(f"         Report saved to: {report_filename}")
            print("="*50)
            
            # Open the report in the default web browser
            try:
                import webbrowser
                webbrowser.open(f"file://{os.path.realpath(report_filename)}")
            except Exception as e:
                logging.warning(f"Could not auto-open report: {e}")
    except KeyboardInterrupt:
        logging.warning("Scan aborted by user.")
    except Exception as e:
        logging.error(f"A critical error occurred: {e}", exc_info=True)
    finally:
        logging.info("Scan controller shutting down.")


# <-- FIX 3 (Indentation)
# This block is now at the top level (zero indentation).
if __name__ == "__main__":
    main()