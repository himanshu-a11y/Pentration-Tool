#!/usr/bin/env python3
"""
AI-Powered Remediation Module
Uses Google Gemini API or OWASP ZAP API to generate dynamic remediation suggestions
"""
import os
import json
import logging
from typing import Dict, Any, List, Optional
import requests

log = logging.getLogger(__name__)

# Try importing Google Generative AI
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    log.warning("google-generativeai not installed. Gemini API will not be available.")


class AIRemediationEngine:
    """AI-powered remediation suggestion engine using Gemini API or OWASP ZAP."""
    
    def __init__(self, provider: str = "gemini"):
        """
        Initialize the AI remediation engine.
        
        Args:
            provider: "gemini" or "zap" (default: "gemini")
        """
        self.provider = provider.lower()
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        self.zap_api_url = os.getenv('ZAP_API_URL', 'http://localhost:8080')
        self.zap_api_key = os.getenv('ZAP_API_KEY', '')
        
        if self.provider == "gemini":
            self._init_gemini()
        elif self.provider == "zap":
            self._init_zap()
    
    def _init_gemini(self):
        """Initialize Gemini API."""
        if not GEMINI_AVAILABLE:
            raise ImportError("google-generativeai package is not installed. Run: pip install google-generativeai")
        
        if not self.gemini_api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is not set. "
                "Please set it before running the application:\n"
                "  Windows: set GEMINI_API_KEY=your-key-here\n"
                "  Linux/macOS: export GEMINI_API_KEY=your-key-here\n"
                "  Or use start_web.bat / start_web.sh which sets it automatically"
            )
        
        try:
            genai.configure(api_key=self.gemini_api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            log.info("Gemini API initialized successfully")
        except Exception as e:
            log.error(f"Failed to initialize Gemini API: {e}")
            raise
    
    def _init_zap(self):
        """Initialize OWASP ZAP API connection."""
        try:
            # Test connection
            test_url = f"{self.zap_api_url}/JSON/core/view/version/"
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                log.info("OWASP ZAP API connection successful")
            else:
                log.warning(f"OWASP ZAP API returned status {response.status_code}")
        except Exception as e:
            log.warning(f"OWASP ZAP API connection test failed: {e}")
    
    def get_remediation_for_vulnerability(self, vulnerability: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """
        Get AI-powered remediation suggestions for a specific vulnerability.
        
        Args:
            vulnerability: Dictionary containing vulnerability details
            target_url: The target URL being tested
            
        Returns:
            Dictionary with remediation summary and details
        """
        if self.provider == "gemini":
            return self._get_gemini_remediation(vulnerability, target_url)
        elif self.provider == "zap":
            return self._get_zap_remediation(vulnerability, target_url)
        else:
            return self._get_fallback_remediation(vulnerability)
    
    def _get_gemini_remediation(self, vulnerability: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """Get remediation from Gemini API."""
        if not self.gemini_api_key or not GEMINI_AVAILABLE:
            return self._get_fallback_remediation(vulnerability)
        
        try:
            vuln_type = vulnerability.get('type', 'Unknown vulnerability')
            url = vulnerability.get('url', 'N/A')
            param = vulnerability.get('param', vulnerability.get('parameter', 'N/A'))
            method = vulnerability.get('method', 'N/A')
            evidence = vulnerability.get('evidence', 'N/A')
            
            # Construct prompt for Gemini
            prompt = f"""You are a cybersecurity expert providing remediation advice for web application vulnerabilities.

Target URL: {target_url}
Vulnerability Type: {vuln_type}
Affected URL: {url}
HTTP Method: {method}
Parameter/Field: {param}
Evidence: {evidence}

Please provide specific, actionable remediation advice for this vulnerability. Your response must be in JSON format with the following structure:
{{
    "summary": "A brief 1-2 sentence summary of the remediation approach",
    "details": [
        "Specific step 1",
        "Specific step 2",
        "Specific step 3"
    ],
    "severity": "High|Medium|Low",
    "priority": "Immediate|High|Medium|Low"
}}

Focus on practical, implementable solutions. If this is a {vuln_type} vulnerability, provide detailed technical steps specific to this vulnerability type and the context provided. Do not include generic advice unless necessary.

Return only valid JSON, no markdown formatting or additional text."""

            # Call Gemini API
            response = self.model.generate_content(prompt)
            
            # Parse response
            response_text = response.text.strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            # Parse JSON
            remediation_data = json.loads(response_text)
            
            # Ensure required fields
            if 'summary' not in remediation_data:
                remediation_data['summary'] = "Remediation advice generated by AI."
            if 'details' not in remediation_data:
                remediation_data['details'] = []
            
            return {
                'summary': remediation_data.get('summary', ''),
                'details': remediation_data.get('details', []),
                'severity': remediation_data.get('severity', 'Medium'),
                'priority': remediation_data.get('priority', 'High')
            }
        
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse Gemini response as JSON: {e}")
            log.debug(f"Raw response: {response_text if 'response_text' in locals() else 'N/A'}")
            return self._get_fallback_remediation(vulnerability)
        except Exception as e:
            log.error(f"Error calling Gemini API: {e}")
            return self._get_fallback_remediation(vulnerability)
    
    def _get_zap_remediation(self, vulnerability: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """Get remediation from OWASP ZAP API."""
        try:
            vuln_type = vulnerability.get('type', 'Unknown')
            
            # Map our vulnerability types to ZAP alert types
            zap_alert_type_map = {
                'XSS': 'Cross Site Scripting',
                'SQLi': 'SQL Injection',
                'SQL Injection': 'SQL Injection'
            }
            
            # Get ZAP alerts
            alerts_url = f"{self.zap_api_url}/JSON/core/view/alerts/"
            params = {}
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = requests.get(alerts_url, params=params, timeout=10)
            if response.status_code == 200:
                alerts = response.json().get('alerts', [])
                
                # Find matching alert
                for alert in alerts:
                    alert_name = alert.get('name', '')
                    if vuln_type.lower() in alert_name.lower() or any(map_term in alert_name for map_term in zap_alert_type_map.values() if vuln_type in map_term):
                        solution = alert.get('solution', '')
                        description = alert.get('description', '')
                        
                        return {
                            'summary': solution if solution else f"Remediation for {vuln_type}",
                            'details': [desc.strip() for desc in description.split('\n') if desc.strip()] if description else [],
                            'severity': alert.get('risk', 'Medium'),
                            'priority': 'High' if alert.get('risk') == 'High' else 'Medium'
                        }
            
            return self._get_fallback_remediation(vulnerability)
        
        except Exception as e:
            log.error(f"Error calling OWASP ZAP API: {e}")
            return self._get_fallback_remediation(vulnerability)
    
    def _get_fallback_remediation(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback remediation when AI API is unavailable."""
        vuln_type = vulnerability.get('type', 'Unknown vulnerability')
        
        return {
            'summary': f"Investigate and remediate {vuln_type} vulnerability. Review OWASP guidelines for best practices.",
            'details': [
                "Review the vulnerability details and evidence",
                "Consult OWASP Top 10 guidelines",
                "Implement input validation and output encoding",
                "Test the fix thoroughly before deploying",
                "Consider security code review and penetration testing"
            ],
            'severity': 'High',
            'priority': 'High'
        }
    
    def get_port_recommendation(self, port_info: Dict[str, Any], target_url: str) -> Optional[str]:
        """Get AI-powered recommendation for an open port."""
        if self.provider == "gemini" and self.gemini_api_key and GEMINI_AVAILABLE:
            return self._get_gemini_port_recommendation(port_info, target_url)
        else:
            return self._get_fallback_port_recommendation(port_info)
    
    def _get_gemini_port_recommendation(self, port_info: Dict[str, Any], target_url: str) -> Optional[str]:
        """Get port recommendation from Gemini."""
        try:
            port = port_info.get('port', 0)
            protocol = port_info.get('protocol', 'Unknown')
            banner = port_info.get('banner', 'N/A')
            
            prompt = f"""You are a network security expert. Provide a brief, specific security recommendation for an open port found during a penetration test.

Target: {target_url}
Port: {port}
Protocol: {protocol}
Banner/Service Info: {banner}

Provide a concise 1-2 sentence recommendation on whether this port should be exposed and how to secure it. Focus on practical security advice.

Return only the recommendation text, no formatting or additional explanation."""

            response = self.model.generate_content(prompt)
            return response.text.strip()
        
        except Exception as e:
            log.error(f"Error getting Gemini port recommendation: {e}")
            return self._get_fallback_port_recommendation(port_info)
    
    def _get_fallback_port_recommendation(self, port_info: Dict[str, Any]) -> Optional[str]:
        """Fallback port recommendation."""
        port = port_info.get('port', 0)
        
        # Only provide recommendations for well-known risky ports
        common_recommendations = {
            21: "FTP port is exposed. Disable FTP or use SFTP/FTPS instead. If FTP is required, ensure strong authentication and encryption.",
            23: "Telnet port is exposed. Telnet is insecure. Disable it and use SSH (port 22) instead.",
            80: "HTTP port is exposed. Ensure HTTPS (443) is available and redirect HTTP to HTTPS using HSTS.",
            1433: "SQL Server port is exposed. Ensure the database is not accessible from the internet. Use firewall rules or VPN access only.",
            3306: "MySQL port is exposed. Ensure the database is not accessible from the internet. Use firewall rules or VPN access only.",
            5432: "PostgreSQL port is exposed. Ensure the database is not accessible from the internet. Use firewall rules or VPN access only.",
            3389: "RDP port is exposed. Ensure strong authentication, enable Network Level Authentication (NLA), and consider using VPN access instead.",
            8080: "Alternative HTTP port is exposed. Ensure proper security headers and authentication are in place.",
            8443: "Alternative HTTPS port is exposed. Verify SSL/TLS configuration and certificate validity."
        }
        
        return common_recommendations.get(port)

