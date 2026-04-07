# Penetration Testing Suite - Web Application

A full-stack web application for penetration testing with real-time progress updates and comprehensive reporting.

## Features

- 🌐 **Web-Based Interface**: Modern, responsive web UI
- 🔄 **Real-Time Updates**: Live progress tracking via WebSockets
- 🕷️ **Web Crawler**: Automatically discovers pages and forms
- 🔌 **Port Scanner**: Scans for open ports and services
- 🔍 **Passive Scanner**: Analyzes security headers, cookies, and TLS
- 🐛 **Active Scanner**: Detects SQL injection and XSS vulnerabilities
- 📊 **HTML Reports**: Beautiful, detailed security reports
- 📜 **Scan History**: View and manage previous scans

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create necessary directories:
```bash
mkdir -p reports templates static/css static/js
```

## Running the Application

### Web Application (Recommended)

Start the Flask web server:
```bash
python app.py
```

Then open your browser and navigate to:
```
http://localhost:5000
```

### Command Line Interface (Original)

You can still use the original CLI version:
```bash
python runall.py
```

## Usage

### Web Interface

1. **Start a Scan**:
   - Enter the target URL
   - Configure crawl depth (1-5)
   - Set port range to scan
   - Optionally enable PoC module
   - Click "Start Scan"

2. **Monitor Progress**:
   - Watch real-time progress updates
   - See which stage is currently running
   - View detailed progress messages

3. **View Results**:
   - See summary statistics
   - Download/view full HTML report
   - Review scan history

### API Endpoints

- `POST /api/scan/start` - Start a new scan
- `GET /api/scan/<scan_id>/status` - Get scan status
- `GET /api/scan/<scan_id>/report` - Download scan report
- `GET /api/scans` - List all scans

## Project Structure

```
pentest_project/
├── app.py                 # Flask web application
├── runall.py              # Original CLI version
├── modules/               # Core scanning modules
│   ├── crawler.py
│   ├── portscanner.py
│   ├── passivescan.py
│   ├── activescan.py
│   ├── poc.py
│   └── reporter.py
├── templates/             # HTML templates
│   └── index.html
├── static/                # Static assets
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
└── reports/               # Generated reports
```

## Security Notes

⚠️ **Important**: This tool is for authorized security testing only. Always ensure you have permission before scanning any target.

- Only use on systems you own or have explicit permission to test
- The PoC module requires interactive confirmation (disabled in web version)
- All scans are logged for audit purposes

## Technologies Used

- **Backend**: Flask, Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript, Socket.IO
- **Python Libraries**: requests, BeautifulSoup4, socket, ssl

## License

This project is for educational and authorized security testing purposes only.

