# Quick Start: AI-Powered Remediation API

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- `google-generativeai` - For Gemini API integration
- All other required packages

## Step 2: Get Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy your API key

## Step 3: Set API Key

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

For permanent setup, add to your shell profile (`~/.bashrc`, `~/.zshrc`, or system environment variables).

## Step 4: Run Setup Script (Optional)

```bash
python setup_remediation_api.py
```

This script will:
- Install dependencies
- Help you configure the API key
- Verify the setup

## Step 5: Start the Flask App

```bash
python app.py
```

The API will be available at `http://localhost:5000/api/remediation`

## Step 6: Test the API

```bash
python test_remediation_api.py
```

Or use your own scan data:

```python
import requests

scan_data = {
    "target_url": "https://example.com",  # Any site you've scanned
    "active_scan_findings": [...],
    "passive_scan_results": {...},
    "port_scan_results": [...]
}

response = requests.post(
    'http://localhost:5000/api/remediation',
    json=scan_data
)

remediations = response.json()
print(remediations)
```

## Key Features

✅ **No Hardcoded Logic** - Works with any website  
✅ **AI-Powered** - Uses Google Gemini for intelligent remediation  
✅ **Dynamic Severity** - AI determines vulnerability severity  
✅ **Context-Aware** - Considers target URL, vulnerability details, and evidence  
✅ **Fallback Support** - Works even if AI is temporarily unavailable  

## Troubleshooting

**"Failed to initialize gemini API"**
- Make sure `GEMINI_API_KEY` is set
- Verify the API key is correct
- Run: `pip install google-generativeai`

**"Package not found"**
- Run: `pip install -r requirements.txt`

For more details, see [API_REMEDIATION.md](API_REMEDIATION.md)

