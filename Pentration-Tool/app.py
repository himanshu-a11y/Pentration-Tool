#!/usr/bin/env python3
"""
Full-Stack Penetration Testing Web Application
Flask backend with REST API and WebSocket support
"""
import os
import json
import logging
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
try:
    from flask_socketio import SocketIO, emit
except ImportError:
    print("ERROR: flask-socketio is not installed!")
    print("Please run: pip install -r requirements.txt")
    exit(1)
from urllib.parse import urlparse, parse_qs
import requests

# Import all modules
from modules.crawler import WebsiteAnalyzer
from modules.portscanner import hybrid_scanner
from modules.passivescan import run_scan as run_passive_scan, normalize_base
from modules.activescan import SQLiDetector, XSSDetector
from modules.poc import PoCModule
from modules.reporter import HTMLReporter, REMEDIATION_ADVICE
from modules.ai_remediation import AIRemediationEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s"
)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active scans
active_scans = {}
scan_results = {}

def format_crawl_targets(crawler_results):
    """Convert crawler output into active scan targets."""
    targets = []
    log.info(f"Formatting {len(crawler_results)} crawled pages for active scanning...")
    
    for page in crawler_results:
        # Add forms found on the page
        for form in page['forms']:
            params = {}
            for inp in form['inputs']:
                if inp['name']:
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
            
        # Add URLs with query parameters
        parsed_url = urlparse(page['url'])
        if parsed_url.query:
            params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
            if params:
                target = {
                    "url": page['url'].split('?')[0],
                    "method": "GET",
                    "params": params
                }
                targets.append(target)

    # De-duplicate targets
    unique_targets = []
    seen = set()
    for target in targets:
        key = (target['url'], target['method'], tuple(sorted(target['params'].keys())))
        if key not in seen:
            unique_targets.append(target)
            seen.add(key)
            
    log.info(f"Found {len(unique_targets)} unique active scan targets.")
    return unique_targets

def emit_progress(scan_id, stage, message, progress=None):
    """Emit progress update to client."""
    socketio.emit('scan_progress', {
        'scan_id': scan_id,
        'stage': stage,
        'message': message,
        'progress': progress,
        'timestamp': datetime.now().isoformat()
    })

def run_scan_async(scan_id, target_url, crawl_depth, start_port, end_port, run_poc):
    """Run the full penetration test scan in a background thread."""
    try:
        emit_progress(scan_id, 'initializing', 'Starting penetration test scan...', 0)
        
        # Initialize report context
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
            emit_progress(scan_id, 'error', f"Invalid URL: {e}", 0)
            active_scans[scan_id]['status'] = 'error'
            active_scans[scan_id]['error'] = str(e)
            return

        # Create session
        with requests.Session() as session:
            # Week 2: Web Crawler
            emit_progress(scan_id, 'crawling', f'Crawling website: {base_url}...', 10)
            analyzer = WebsiteAnalyzer(session)
            crawl_results, crawl_meta = analyzer.crawl(base_url, base_url, 0, crawl_depth)
            report_context['crawl_results'] = {'pages': crawl_results, 'metadata': crawl_meta}
            emit_progress(scan_id, 'crawling', f'Crawler finished. Found {len(crawl_results)} pages.', 20)

            # Week 3: Port Scanner
            emit_progress(scan_id, 'port_scanning', f'Scanning ports {start_port}-{end_port}...', 30)
            port_results = hybrid_scanner(host, start_port, end_port, max_threads=100, mode="tcp")
            report_context['port_scan_results'] = port_results
            emit_progress(scan_id, 'port_scanning', f'Port scan finished. Found {len(port_results)} open ports.', 40)

            # Week 4: Passive Scanner
            emit_progress(scan_id, 'passive_scanning', 'Running passive security scan...', 50)
            passive_results = run_passive_scan(base_url, session=session)
            report_context['passive_scan_results'] = passive_results
            grade = passive_results.get('grade', {}).get('grade', 'N/A')
            emit_progress(scan_id, 'passive_scanning', f'Passive scan finished. Grade: {grade}', 60)
            
            # Week 5: Active Scanners
            active_scan_targets = format_crawl_targets(crawl_results)
            all_findings = []  # Initialize to avoid UnboundLocalError
            if not active_scan_targets:
                emit_progress(scan_id, 'active_scanning', 'No forms or URL parameters found. Skipping active scan.', 70)
                report_context['active_scan_findings'] = []
            else:
                emit_progress(scan_id, 'active_scanning', f'Running active vulnerability scans on {len(active_scan_targets)} targets...', 65)
                sqli_scanner = SQLiDetector(session)
                xss_scanner = XSSDetector(session)
                total_targets = len(active_scan_targets)
                for idx, target in enumerate(active_scan_targets):
                    all_findings.extend(sqli_scanner.scan_target(target))
                    all_findings.extend(xss_scanner.scan_target(target))
                    progress = 65 + int((idx + 1) / total_targets * 10)
                    emit_progress(scan_id, 'active_scanning', 
                                f'Scanned {idx + 1}/{total_targets} targets. Found {len(all_findings)} vulnerabilities.', 
                                progress)
                    
                report_context['active_scan_findings'] = all_findings
                emit_progress(scan_id, 'active_scanning', 
                            f'Active scan finished. Found {len(all_findings)} potential vulnerabilities.', 75)

                # Week 6: PoC Module (skip for web version - requires user interaction)
                if run_poc and all_findings:
                    emit_progress(scan_id, 'poc', 'PoC module skipped in web interface (requires interactive confirmation).', 80)
                    report_context['poc_results'] = []
            
            # Ensure poc_results is set even if not running PoC
            if 'poc_results' not in report_context:
                report_context['poc_results'] = []

            # Week 7: Generate Report
            emit_progress(scan_id, 'reporting', 'Generating HTML report...', 90)
            report_filename = f"reports/Scan_Report_{host.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            # Ensure reports directory exists
            os.makedirs('reports', exist_ok=True)
            
            reporter = HTMLReporter(report_context, report_filename)
            reporter.generate_report()
            
            emit_progress(scan_id, 'complete', f'Scan complete! Report saved.', 100)
            
            # Store results
            active_scans[scan_id]['status'] = 'complete'
            active_scans[scan_id]['report_path'] = report_filename
            active_scans[scan_id]['results'] = report_context
            scan_results[scan_id] = {
                'scan_id': scan_id,
                'target_url': target_url,
                'start_time': report_context['scan_start_time'],
                'end_time': datetime.now().isoformat(),
                'report_path': report_filename,
                'summary': {
                    'pages_crawled': len(crawl_results),
                    'open_ports': len(port_results),
                    'vulnerabilities': len(all_findings),
                    'grade': grade
                }
            }
            
    except Exception as e:
        log.error(f"Scan error: {e}", exc_info=True)
        emit_progress(scan_id, 'error', f'Scan failed: {str(e)}', 0)
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['error'] = str(e)

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new penetration test scan."""
    data = request.json
    target_url = data.get('target_url', '').strip()
    crawl_depth = int(data.get('crawl_depth', 2))
    start_port = int(data.get('start_port', 1))
    end_port = int(data.get('end_port', 1024))
    run_poc = data.get('run_poc', False)
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = "http://" + target_url
    
    # Generate scan ID
    scan_id = f"scan_{int(time.time())}_{os.urandom(4).hex()}"
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        'scan_id': scan_id,
        'target_url': target_url,
        'status': 'running',
        'start_time': datetime.now().isoformat()
    }
    
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan_async,
        args=(scan_id, target_url, crawl_depth, start_port, end_port, run_poc),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': 'Scan started successfully'
    })

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a scan."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan = active_scans[scan_id]
    return jsonify({
        'scan_id': scan_id,
        'status': scan.get('status', 'unknown'),
        'target_url': scan.get('target_url'),
        'start_time': scan.get('start_time'),
        'error': scan.get('error'),
        'report_path': scan.get('report_path')
    })

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def get_scan_report(scan_id):
    """Get the report file for a scan."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    report_path = active_scans[scan_id].get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Report not found'}), 404
    
    return send_file(report_path)

@app.route('/api/scan/<scan_id>/data', methods=['GET'])
def get_scan_data(scan_id):
    """Get the scan results as JSON for remediation API."""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = active_scans[scan_id].get('results')
    if not scan_data:
        return jsonify({'error': 'Scan results not available'}), 404
    
    # Return scan data in format expected by remediation API
    return jsonify(scan_data)

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans."""
    scans = []
    for scan_id, scan_data in scan_results.items():
        scans.append({
            'scan_id': scan_id,
            'target_url': scan_data['target_url'],
            'start_time': scan_data['start_time'],
            'end_time': scan_data['end_time'],
            'summary': scan_data['summary']
        })
    
    # Also include active scans
    for scan_id, scan_data in active_scans.items():
        if scan_id not in scan_results:
            scans.append({
                'scan_id': scan_id,
                'target_url': scan_data['target_url'],
                'start_time': scan_data['start_time'],
                'status': scan_data.get('status', 'running')
            })
    
    return jsonify({'scans': sorted(scans, key=lambda x: x.get('start_time', ''), reverse=True)})

@app.route('/api/remediation', methods=['POST'])
def get_remediations():
    """
    Accept raw JSON scan data and return AI-powered remediation suggestions.
    
    Expected JSON format:
    {
        "target_url": "...",
        "active_scan_findings": [...],
        "passive_scan_results": {...},
        "port_scan_results": [...],
        "provider": "gemini" | "zap" (optional, defaults to "gemini")
    }
    
    Environment Variables:
    - GEMINI_API_KEY: Required for Gemini provider
    - ZAP_API_URL: Defaults to http://localhost:8080 (for ZAP provider)
    - ZAP_API_KEY: Optional API key for ZAP
    """
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        target_url = data.get('target_url', 'Unknown')
        provider = data.get('provider', 'gemini').lower()  # Default to Gemini
        
        # Initialize AI remediation engine
        try:
            ai_engine = AIRemediationEngine(provider=provider)
        except Exception as e:
            log.error(f"Failed to initialize AI remediation engine: {e}")
            return jsonify({
                'error': f'Failed to initialize {provider} API',
                'message': str(e),
                'hint': 'Make sure GEMINI_API_KEY is set for Gemini or ZAP is running for OWASP ZAP'
            }), 500
        
        remediations = {
            'target_url': target_url,
            'provider': provider,
            'summary': {
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'medium_count': 0,
                'low_count': 0
            },
            'active_vulnerabilities': [],
            'passive_vulnerabilities': [],
            'port_recommendations': []
        }
        
        def map_severity_to_count(severity):
            """Map severity string to count field."""
            severity_lower = severity.lower() if severity else 'medium'
            if 'critical' in severity_lower or 'high' in severity_lower:
                return 'critical_count'
            elif 'low' in severity_lower:
                return 'low_count'
            else:
                return 'medium_count'
        
        # Process active scan findings dynamically
        active_findings = data.get('active_scan_findings', [])
        for finding in active_findings:
            try:
                # Get AI-powered remediation
                remediation_data = ai_engine.get_remediation_for_vulnerability(finding, target_url)
                severity = remediation_data.get('severity', 'High')
                count_field = map_severity_to_count(severity)
                
                remediations['active_vulnerabilities'].append({
                    'type': finding.get('type', 'Unknown Finding'),
                    'url': finding.get('url', ''),
                    'parameter': finding.get('param', finding.get('parameter', '')),
                    'method': finding.get('method', ''),
                    'evidence': finding.get('evidence', ''),
                    'severity': severity,
                    'priority': remediation_data.get('priority', 'High'),
                    'remediation': {
                        'summary': remediation_data.get('summary', ''),
                        'details': remediation_data.get('details', [])
                    }
                })
                remediations['summary']['total_vulnerabilities'] += 1
                remediations['summary'][count_field] += 1
            except Exception as e:
                log.error(f"Error processing active finding: {e}")
                continue
        
        # Process passive scan results dynamically
        passive_results = data.get('passive_scan_results', {})
        
        # Missing headers - create vulnerability objects for AI processing
        missing_headers = passive_results.get('missing_headers', [])
        for header in missing_headers:
            try:
                vuln_data = {
                    'type': f'Missing Security Header: {header}',
                    'url': passive_results.get('url', target_url),
                    'header': header
                }
                remediation_data = ai_engine.get_remediation_for_vulnerability(vuln_data, target_url)
                severity = remediation_data.get('severity', 'Medium')
                count_field = map_severity_to_count(severity)
                
                remediations['passive_vulnerabilities'].append({
                    'type': f'Missing Security Header: {header}',
                    'severity': severity,
                    'priority': remediation_data.get('priority', 'Medium'),
                    'remediation': {
                        'summary': remediation_data.get('summary', ''),
                        'details': remediation_data.get('details', [])
                    }
                })
                remediations['summary']['total_vulnerabilities'] += 1
                remediations['summary'][count_field] += 1
            except Exception as e:
                log.error(f"Error processing missing header: {e}")
                continue
        
        # Insecure cookies - process dynamically
        cookies = passive_results.get('cookies', [])
        for cookie in cookies:
            try:
                cookie_name = cookie.get('name', 'Unknown')
                
                # HttpOnly flag
                if not cookie.get('httpOnly'):
                    vuln_data = {
                        'type': 'Insecure Cookie (Missing HttpOnly)',
                        'url': passive_results.get('url', target_url),
                        'cookie_name': cookie_name,
                        'issue': 'Missing HttpOnly flag'
                    }
                    remediation_data = ai_engine.get_remediation_for_vulnerability(vuln_data, target_url)
                    severity = remediation_data.get('severity', 'Medium')
                    count_field = map_severity_to_count(severity)
                    
                    remediations['passive_vulnerabilities'].append({
                        'type': f"Insecure Cookie: '{cookie_name}' (Missing HttpOnly)",
                        'severity': severity,
                        'priority': remediation_data.get('priority', 'Medium'),
                        'remediation': {
                            'summary': remediation_data.get('summary', ''),
                            'details': remediation_data.get('details', [])
                        }
                    })
                    remediations['summary']['total_vulnerabilities'] += 1
                    remediations['summary'][count_field] += 1
                
                # Secure flag
                if not cookie.get('secure'):
                    vuln_data = {
                        'type': 'Insecure Cookie (Missing Secure)',
                        'url': passive_results.get('url', target_url),
                        'cookie_name': cookie_name,
                        'issue': 'Missing Secure flag'
                    }
                    remediation_data = ai_engine.get_remediation_for_vulnerability(vuln_data, target_url)
                    severity = remediation_data.get('severity', 'Low')
                    count_field = map_severity_to_count(severity)
                    
                    remediations['passive_vulnerabilities'].append({
                        'type': f"Insecure Cookie: '{cookie_name}' (Missing Secure)",
                        'severity': severity,
                        'priority': remediation_data.get('priority', 'Medium'),
                        'remediation': {
                            'summary': remediation_data.get('summary', ''),
                            'details': remediation_data.get('details', [])
                        }
                    })
                    remediations['summary']['total_vulnerabilities'] += 1
                    remediations['summary'][count_field] += 1
            except Exception as e:
                log.error(f"Error processing cookie: {e}")
                continue
        
        # Exposed paths - process dynamically
        sensitive_paths = passive_results.get('sensitive_paths', [])
        for path in sensitive_paths:
            try:
                path_str = path.get('path', 'Unknown')
                vuln_data = {
                    'type': 'Exposed Sensitive Path',
                    'url': path.get('url', ''),
                    'path': path_str,
                    'status': path.get('status', 'N/A')
                }
                remediation_data = ai_engine.get_remediation_for_vulnerability(vuln_data, target_url)
                severity = remediation_data.get('severity', 'Medium')
                count_field = map_severity_to_count(severity)
                
                remediations['passive_vulnerabilities'].append({
                    'type': f"Exposed Path: {path_str}",
                    'url': path.get('url', ''),
                    'status': path.get('status', 'N/A'),
                    'severity': severity,
                    'priority': remediation_data.get('priority', 'Medium'),
                    'remediation': {
                        'summary': remediation_data.get('summary', ''),
                        'details': remediation_data.get('details', [])
                    }
                })
                remediations['summary']['total_vulnerabilities'] += 1
                remediations['summary'][count_field] += 1
            except Exception as e:
                log.error(f"Error processing exposed path: {e}")
                continue
        
        # Port scan recommendations - use AI for dynamic recommendations
        port_results = data.get('port_scan_results', [])
        for port_info in port_results:
            try:
                recommendation = ai_engine.get_port_recommendation(port_info, target_url)
                if recommendation:
                    remediations['port_recommendations'].append({
                        'port': port_info.get('port', 0),
                        'protocol': port_info.get('protocol', 'Unknown'),
                        'status': port_info.get('status', 'unknown'),
                        'banner': port_info.get('banner', 'N/A'),
                        'recommendation': recommendation
                    })
            except Exception as e:
                log.error(f"Error processing port recommendation: {e}")
                continue
        
        return jsonify(remediations)
    
    except Exception as e:
        log.error(f"Error processing remediation request: {e}", exc_info=True)
        return jsonify({'error': f'Failed to process request: {str(e)}'}), 500

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    log.info('Client connected')
    emit('connected', {'message': 'Connected to scan server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    log.info('Client disconnected')

# Create necessary directories (for local development)
os.makedirs('reports', exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)

if __name__ == '__main__':
    # Run the app (local development only)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

