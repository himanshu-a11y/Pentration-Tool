# Quick Start Guide

## Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the web application:**

   **Windows:**
   ```bash
   start_web.bat
   ```
   
   **Linux/Mac:**
   ```bash
   chmod +x start_web.sh
   ./start_web.sh
   ```
   
   **Or directly:**
   ```bash
   python app.py
   ```

3. **Open your browser:**
   Navigate to: `http://localhost:5000`

## First Scan

1. Enter a target URL (e.g., `http://testphp.vulnweb.com`)
2. Set crawl depth (default: 2)
3. Set port range (default: 1-1024)
4. Click "Start Scan"
5. Watch real-time progress
6. View results and download report

## Features

- ✅ Real-time progress updates
- ✅ Web-based interface
- ✅ Comprehensive security scanning
- ✅ Beautiful HTML reports
- ✅ Scan history

## Troubleshooting

**Port 5000 already in use?**
- Change the port in `app.py` (last line): `socketio.run(app, host='0.0.0.0', port=8080)`

**Module import errors?**
- Make sure you're in the project directory
- Verify all dependencies are installed: `pip install -r requirements.txt`

**Reports not generating?**
- Check that the `reports/` directory exists and is writable

## Original CLI Version

The original command-line version is still available:
```bash
python runall.py
```

