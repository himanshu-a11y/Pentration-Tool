# AI-Powered Remediation API Documentation

## Overview

Your Flask application includes an AI-powered remediation API endpoint that uses **Google Gemini API** or **OWASP ZAP API** to generate dynamic, context-aware remediation suggestions for any vulnerability detected during penetration testing.

The API is **completely dynamic** and does not rely on hardcoded site-specific information. It analyzes each vulnerability in context and provides tailored remediation advice.

### Endpoint

**POST** `/api/remediation`

### Request Format

Send a POST request with JSON scan data in the body. The API accepts the same format as your scan results:

```json
{
  "target_url": "https://example.com",
  "active_scan_findings": [...],
  "passive_scan_results": {...},
  "port_scan_results": [...],
  "provider": "gemini"  // Optional: "gemini" or "zap" (defaults to "gemini")
}
```

**Note:** The `provider` field is optional. Use `"gemini"` for Google Gemini API (default) or `"zap"` for OWASP ZAP API.

### Response Format

The API returns a structured JSON response with:

- **Provider**: Which AI provider was used ("gemini" or "zap")
- **Summary**: Total count of vulnerabilities by severity (dynamically determined by AI)
- **Active Vulnerabilities**: AI-generated remediations for SQLi, XSS, and other active findings
- **Passive Vulnerabilities**: AI-generated remediations for missing headers, insecure cookies, exposed paths
- **Port Recommendations**: AI-generated security recommendations for open ports
- **Severity & Priority**: Dynamically assigned based on AI analysis

### Example Usage

#### Using cURL

```bash
curl -X POST http://localhost:5000/api/remediation \
  -H "Content-Type: application/json" \
  -d @scan_results.json
```

#### Using Python

```python
import requests
import os

# Your scan results JSON (works with ANY site)
scan_data = {
    "target_url": "https://example.com",  # Any URL you've scanned
    "active_scan_findings": [
        {
            "type": "XSS (Reflected, simple)",
            "url": "https://example.com/search",
            "param": "query",
            "method": "GET",
            "evidence": "Found token in response body"
        }
    ],
    "passive_scan_results": {
        "missing_headers": ["Content-Security-Policy"],
        "cookies": []
    },
    "port_scan_results": [
        {"port": 80, "protocol": "HTTP", "status": "open"}
    ],
    "provider": "gemini"  # or "zap"
}

# Send request
response = requests.post(
    'http://localhost:5000/api/remediation',
    json=scan_data
)

# Get AI-generated remediation suggestions
remediations = response.json()
print(f"Provider: {remediations['provider']}")
print(f"Total vulnerabilities: {remediations['summary']['total_vulnerabilities']}")

for vuln in remediations['active_vulnerabilities']:
    print(f"\n{vuln['type']} (Severity: {vuln['severity']}, Priority: {vuln['priority']})")
    print(f"Summary: {vuln['remediation']['summary']}")
    print("Details:")
    for detail in vuln['remediation']['details']:
        print(f"  - {detail}")
```

#### Using JavaScript/Fetch

```javascript
const scanData = {
    target_url: "https://www.httpbin.org",
    active_scan_findings: [...],
    passive_scan_results: {...},
    port_scan_results: [...]
};

fetch('http://localhost:5000/api/remediation', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(scanData)
})
.then(response => response.json())
.then(data => {
    console.log('Total vulnerabilities:', data.summary.total_vulnerabilities);
    data.active_vulnerabilities.forEach(vuln => {
        console.log(`${vuln.type}: ${vuln.remediation.summary}`);
    });
});
```

### Example Response

```json
{
  "target_url": "https://example.com",
  "provider": "gemini",
  "summary": {
    "total_vulnerabilities": 2,
    "critical_count": 1,
    "medium_count": 1,
    "low_count": 0
  },
  "active_vulnerabilities": [
    {
      "type": "XSS (Reflected, simple)",
      "url": "https://example.com/search",
      "parameter": "query",
      "method": "GET",
      "evidence": "Found token in response body",
      "severity": "High",
      "priority": "Immediate",
      "remediation": {
        "summary": "Implement input validation and output encoding to prevent XSS attacks in the search query parameter.",
        "details": [
          "Sanitize and validate all user input in the 'query' parameter before processing",
          "Use context-aware output encoding: HTML-encode (< becomes &lt;) when displaying in HTML body",
          "Implement a Content Security Policy (CSP) with 'unsafe-inline' disabled",
          "Consider using a web application firewall (WAF) as an additional layer of protection",
          "Test the fix with various XSS payloads to ensure proper sanitization"
        ]
      }
    }
  ],
  "passive_vulnerabilities": [
    {
      "type": "Missing Security Header: Content-Security-Policy",
      "severity": "Medium",
      "priority": "High",
      "remediation": {
        "summary": "Implement a Content Security Policy header to mitigate XSS and data injection attacks.",
        "details": [
          "Add 'Content-Security-Policy: default-src \'self\'' as a starting point",
          "Gradually add trusted domains: 'script-src \'self\' trusted-cdn.com'",
          "Avoid 'unsafe-inline' and 'unsafe-eval' unless absolutely necessary",
          "Test the policy using browser developer tools to ensure it doesn't break functionality"
        ]
      }
    }
  ],
  "port_recommendations": [
    {
      "port": 80,
      "protocol": "HTTP",
      "status": "open",
      "banner": "HTTP/1.1 200 OK",
      "recommendation": "HTTP port 80 is exposed. Ensure HTTPS (port 443) is available and configured properly. Implement automatic HTTP to HTTPS redirection using 301 permanent redirects and HSTS headers to prevent downgrade attacks."
    }
  ]
}
```

**Note:** All remediation suggestions are dynamically generated by AI based on the specific vulnerability context, target URL, and evidence provided. No hardcoded responses!

## Setup Instructions

### Google Gemini API Setup (Recommended)

1. **Get a Gemini API Key:**
   - Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Sign in with your Google account
   - Click "Create API Key"
   - Copy your API key

2. **Set Environment Variable:**
   
   **Windows (PowerShell):**
   ```powershell
   $env:GEMINI_API_KEY="your-api-key-here"
   ```
   
   **Windows (Command Prompt):**
   ```cmd
   set GEMINI_API_KEY=your-api-key-here
   ```
   
   **Linux/macOS:**
   ```bash
   export GEMINI_API_KEY="your-api-key-here"
   ```
   
   **Permanent Setup (Linux/macOS):**
   Add to `~/.bashrc` or `~/.zshrc`:
   ```bash
   echo 'export GEMINI_API_KEY="your-api-key-here"' >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Test the API:**
   ```bash
   python test_remediation_api.py
   ```

### OWASP ZAP API Setup (Alternative)

1. **Install OWASP ZAP:**
   - Download from [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)
   - Start ZAP and enable the API in Options → API

2. **Set Environment Variables:**
   ```bash
   export ZAP_API_URL="http://localhost:8080"
   export ZAP_API_KEY="your-zap-api-key"  # Optional
   ```

3. **Use ZAP Provider:**
   In your API request, set `"provider": "zap"` in the JSON payload.

## How It Works

The AI remediation engine:

1. **Accepts any vulnerability data** - No hardcoded site-specific logic
2. **Analyzes context** - Considers target URL, vulnerability type, evidence, and parameters
3. **Generates tailored advice** - Uses AI to create specific, actionable remediation steps
4. **Assigns severity dynamically** - AI determines severity and priority based on context
5. **Falls back gracefully** - If AI is unavailable, provides basic remediation guidance

## External API Options

For enterprise environments, you may also consider these commercial APIs:

### 1. **Qualys API**
- **Purpose**: Enterprise vulnerability management
- **Features**: Comprehensive vulnerability database, threat intelligence, remediation workflows
- **Website**: https://www.qualys.com
- **Best for**: Large organizations needing enterprise-grade vulnerability management

### 2. **Tenable Security Center API**
- **Purpose**: Vulnerability scanning and management
- **Features**: Vulnerability assessment, remediation recommendations, compliance tracking
- **Website**: https://www.tenable.com
- **Best for**: Enterprise environments with existing Tenable infrastructure

### 3. **Mend SCA API** (formerly WhiteSource)
- **Purpose**: Software Composition Analysis and vulnerability management
- **Features**: Dependency vulnerability scanning, remediation suggestions for libraries
- **Website**: https://www.mend.io
- **Best for**: Applications using third-party libraries and dependencies

### 4. **Edgescan API**
- **Purpose**: Continuous security monitoring
- **Features**: API security testing, vulnerability scanning, remediation advice
- **Website**: https://www.edgescan.com
- **Best for**: API-focused security testing

### 5. **Open Source Alternatives**

#### OWASP ZAP API
- **Purpose**: Open-source web application security scanner
- **Features**: Automated vulnerability scanning, passive and active scanning
- **Website**: https://www.zaproxy.org
- **Best for**: Developers wanting open-source solutions

#### Nuclei API
- **Purpose**: Vulnerability scanner based on community-contributed templates
- **Features**: Fast scanning, extensive vulnerability templates
- **Website**: https://github.com/projectdiscovery/nuclei
- **Best for**: Security researchers and developers

## Key Features

✅ **Fully Dynamic** - No hardcoded site-specific information  
✅ **AI-Powered** - Uses Google Gemini or OWASP ZAP for intelligent remediation  
✅ **Context-Aware** - Considers vulnerability details, target URL, and evidence  
✅ **Works with Any Site** - Test any website, not just hardcoded examples  
✅ **Severity Assessment** - AI determines vulnerability severity dynamically  
✅ **Priority Recommendations** - Get prioritized remediation steps  
✅ **Fallback Support** - Works even if AI API is temporarily unavailable  

## Notes

- **API Key Security**: Never commit API keys to version control. Use environment variables.
- **Gemini API Limits**: Google Gemini API has rate limits. Check [Google AI Studio](https://makersuite.google.com/app/apikey) for current limits.
- **Costs**: Gemini API has a free tier with generous limits. Check Google's pricing for high-volume usage.
- **Privacy**: Scan data is sent to Google Gemini API. Ensure compliance with your organization's data policies.
- **OWASP ZAP**: Requires ZAP to be running locally or on a server you control.
- **Production Use**: Consider adding authentication/authorization to the API endpoint for production deployments.

## Troubleshooting

**Error: "Failed to initialize gemini API"**
- Check that `GEMINI_API_KEY` environment variable is set
- Verify the API key is correct and not expired
- Ensure `google-generativeai` package is installed: `pip install google-generativeai`

**Error: "Failed to initialize zap API"**
- Ensure OWASP ZAP is running
- Check that `ZAP_API_URL` points to the correct ZAP instance
- Verify API is enabled in ZAP settings

**Fallback Mode:**
- If AI APIs are unavailable, the system will use basic remediation guidance
- Check logs for detailed error messages

