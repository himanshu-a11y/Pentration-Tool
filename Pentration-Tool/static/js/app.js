// WebSocket connection for real-time updates
const socket = io();

let currentScanId = null;

// DOM Elements
const scanForm = document.getElementById('scan-form');
const startScanBtn = document.getElementById('start-scan-btn');
const progressSection = document.getElementById('progress-section');
const resultsSection = document.getElementById('results-section');
const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');
const progressMessages = document.getElementById('progress-messages');
const resultsContent = document.getElementById('results-content');
const viewReportBtn = document.getElementById('view-report-btn');
const newScanBtn = document.getElementById('new-scan-btn');
const getRemediationBtn = document.getElementById('get-remediation-btn');
const remediationSection = document.getElementById('remediation-section');
const remediationContent = document.getElementById('remediation-content');
const remediationLoading = document.getElementById('remediation-loading');
const closeRemediationBtn = document.getElementById('close-remediation-btn');

// WebSocket event handlers
socket.on('connect', () => {
    console.log('Connected to server');
    addMessage('Connected to scan server', 'success');
});

socket.on('scan_progress', (data) => {
    if (data.scan_id === currentScanId) {
        updateProgress(data);
    }
});

// Form submission
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
        target_url: document.getElementById('target_url').value,
        crawl_depth: parseInt(document.getElementById('crawl_depth').value),
        start_port: parseInt(document.getElementById('start_port').value),
        end_port: parseInt(document.getElementById('end_port').value),
        run_poc: document.getElementById('run_poc').checked
    };

    try {
        startScanBtn.disabled = true;
        startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
        
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();
        
        if (response.ok) {
            currentScanId = result.scan_id;
            startScan(formData.target_url);
            addMessage(`Scan started successfully! ID: ${result.scan_id}`, 'success');
        } else {
            addMessage(`Error: ${result.error}`, 'error');
            startScanBtn.disabled = false;
            startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        }
    } catch (error) {
        addMessage(`Error starting scan: ${error.message}`, 'error');
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    }
});

function startScan(targetUrl) {
    // Show progress section
    progressSection.style.display = 'block';
    resultsSection.style.display = 'none';
    document.getElementById('scan-form-section').style.display = 'none';
    
    // Reset progress
    updateProgress({ progress: 0, stage: 'initializing', message: 'Initializing scan...' });
    
    // Reset stages
    document.querySelectorAll('.stage').forEach(stage => {
        stage.classList.remove('active', 'completed');
    });
    
    // Poll for scan status
    pollScanStatus();
}

function updateProgress(data) {
    const progress = data.progress || 0;
    progressFill.style.width = `${progress}%`;
    progressText.textContent = `${progress}%`;
    
    // Update active stage
    const stageElement = document.getElementById(`stage-${data.stage}`);
    if (stageElement) {
        // Remove active from all stages
        document.querySelectorAll('.stage').forEach(s => {
            s.classList.remove('active');
        });
        
        // Mark previous stages as completed
        const stages = ['crawling', 'port_scanning', 'passive_scanning', 'active_scanning', 'reporting'];
        const currentIndex = stages.indexOf(data.stage);
        for (let i = 0; i < currentIndex; i++) {
            const prevStage = document.getElementById(`stage-${stages[i]}`);
            if (prevStage) {
                prevStage.classList.add('completed');
                prevStage.classList.remove('active');
            }
        }
        
        // Mark current stage as active
        stageElement.classList.add('active');
    }
    
    // Add message
    if (data.message) {
        addMessage(data.message, data.stage === 'error' ? 'error' : 'info');
    }
    
    // Check if complete
    if (data.stage === 'complete' || progress >= 100) {
        setTimeout(() => {
            showResults();
        }, 2000);
    }
}

function addMessage(message, type = 'info') {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    progressMessages.appendChild(messageDiv);
    progressMessages.scrollTop = progressMessages.scrollHeight;
}

async function pollScanStatus() {
    if (!currentScanId) return;
    
    try {
        const response = await fetch(`/api/scan/${currentScanId}/status`);
        const status = await response.json();
        
        if (status.status === 'complete') {
            showResults();
        } else if (status.status === 'error') {
            addMessage(`Scan failed: ${status.error}`, 'error');
            startScanBtn.disabled = false;
            startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        } else {
            // Continue polling
            setTimeout(pollScanStatus, 2000);
        }
    } catch (error) {
        console.error('Error polling scan status:', error);
        setTimeout(pollScanStatus, 5000);
    }
}

async function showResults() {
    try {
        const response = await fetch(`/api/scan/${currentScanId}/status`);
        const status = await response.json();
        
        if (status.report_path) {
            viewReportBtn.style.display = 'inline-flex';
            viewReportBtn.onclick = () => {
                window.open(`/api/scan/${currentScanId}/report`, '_blank');
            };
        }
        
        // Show remediation button if scan completed
        if (status.status === 'complete') {
            getRemediationBtn.style.display = 'inline-flex';
        }
        
        // Fetch scan results summary
        const scansResponse = await fetch('/api/scans');
        const scansData = await scansResponse.json();
        const currentScan = scansData.scans.find(s => s.scan_id === currentScanId);
        
        if (currentScan && currentScan.summary) {
            resultsContent.innerHTML = `
                <div class="results-summary">
                    <div class="summary-box ${currentScan.summary.vulnerabilities > 0 ? 'danger' : 'success'}">
                        <h3>Vulnerabilities</h3>
                        <div class="value">${currentScan.summary.vulnerabilities}</div>
                    </div>
                    <div class="summary-box">
                        <h3>Pages Crawled</h3>
                        <div class="value">${currentScan.summary.pages_crawled}</div>
                    </div>
                    <div class="summary-box">
                        <h3>Open Ports</h3>
                        <div class="value">${currentScan.summary.open_ports}</div>
                    </div>
                    <div class="summary-box ${currentScan.summary.grade === 'A' || currentScan.summary.grade === 'B' ? 'success' : currentScan.summary.grade === 'F' ? 'danger' : 'warning'}">
                        <h3>Security Grade</h3>
                        <div class="value">${currentScan.summary.grade}</div>
                    </div>
                </div>
            `;
        } else {
            resultsContent.innerHTML = '<p>Scan completed successfully!</p>';
        }
        
        resultsSection.style.display = 'block';
        progressSection.style.display = 'none';
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        
        // Reload scans list
        loadScansList();
    } catch (error) {
        console.error('Error showing results:', error);
        addMessage(`Error loading results: ${error.message}`, 'error');
    }
}

// Get remediation report
getRemediationBtn.addEventListener('click', async () => {
    try {
        // Show loading
        remediationSection.style.display = 'block';
        remediationLoading.style.display = 'block';
        remediationContent.innerHTML = '';
        
        // Scroll to remediation section
        remediationSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        // Get scan data
        const scanDataResponse = await fetch(`/api/scan/${currentScanId}/data`);
        if (!scanDataResponse.ok) {
            throw new Error('Failed to fetch scan data');
        }
        const scanData = await scanDataResponse.json();
        
        // Add provider
        scanData['provider'] = 'gemini';
        
        // Call remediation API
        const remediationResponse = await fetch('/api/remediation', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanData)
        });
        
        if (!remediationResponse.ok) {
            const error = await remediationResponse.json();
            throw new Error(error.error || 'Failed to get remediation suggestions');
        }
        
        const remediations = await remediationResponse.json();
        
        // Hide loading
        remediationLoading.style.display = 'none';
        
        // Display remediation report
        displayRemediationReport(remediations);
        
    } catch (error) {
        console.error('Error getting remediation:', error);
        remediationLoading.style.display = 'none';
        remediationContent.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-triangle"></i>
                <h3>Error Generating Remediation Report</h3>
                <p>${error.message}</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    Make sure GEMINI_API_KEY environment variable is set.
                </p>
            </div>
        `;
    }
});

function displayRemediationReport(remediations) {
    const summary = remediations.summary;
    const provider = remediations.provider || 'unknown';
    
    let html = `
        <div class="remediation-header">
            <div class="provider-badge">
                <i class="fas fa-robot"></i> Powered by ${provider.toUpperCase()}
            </div>
            <div class="remediation-summary">
                <div class="summary-stat">
                    <span class="stat-label">Total Vulnerabilities</span>
                    <span class="stat-value">${summary.total_vulnerabilities}</span>
                </div>
                <div class="summary-stat critical">
                    <span class="stat-label">Critical</span>
                    <span class="stat-value">${summary.critical_count}</span>
                </div>
                <div class="summary-stat medium">
                    <span class="stat-label">Medium</span>
                    <span class="stat-value">${summary.medium_count}</span>
                </div>
                <div class="summary-stat low">
                    <span class="stat-label">Low</span>
                    <span class="stat-value">${summary.low_count}</span>
                </div>
            </div>
        </div>
    `;
    
    // Active vulnerabilities
    if (remediations.active_vulnerabilities && remediations.active_vulnerabilities.length > 0) {
        html += `
            <div class="remediation-section">
                <h3><i class="fas fa-bug"></i> Active Vulnerabilities</h3>
                ${remediations.active_vulnerabilities.map((vuln, index) => `
                    <div class="vulnerability-card ${vuln.severity.toLowerCase()}">
                        <div class="vuln-header">
                            <h4>${index + 1}. ${escapeHtml(vuln.type)}</h4>
                            <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                            ${vuln.priority ? `<span class="priority-badge">Priority: ${vuln.priority}</span>` : ''}
                        </div>
                        <div class="vuln-details">
                            <p><strong>URL:</strong> ${escapeHtml(vuln.url)}</p>
                            ${vuln.parameter ? `<p><strong>Parameter:</strong> ${escapeHtml(vuln.parameter)}</p>` : ''}
                            ${vuln.method ? `<p><strong>Method:</strong> ${escapeHtml(vuln.method)}</p>` : ''}
                        </div>
                        <div class="remediation-advice">
                            <h5><i class="fas fa-lightbulb"></i> Remediation</h5>
                            <p class="remediation-summary">${escapeHtml(vuln.remediation.summary)}</p>
                            ${vuln.remediation.details && vuln.remediation.details.length > 0 ? `
                                <ul class="remediation-steps">
                                    ${vuln.remediation.details.map(detail => `<li>${escapeHtml(detail)}</li>`).join('')}
                                </ul>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    // Passive vulnerabilities
    if (remediations.passive_vulnerabilities && remediations.passive_vulnerabilities.length > 0) {
        html += `
            <div class="remediation-section">
                <h3><i class="fas fa-shield-alt"></i> Passive Vulnerabilities</h3>
                ${remediations.passive_vulnerabilities.map((vuln, index) => `
                    <div class="vulnerability-card ${vuln.severity.toLowerCase()}">
                        <div class="vuln-header">
                            <h4>${index + 1}. ${escapeHtml(vuln.type)}</h4>
                            <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                            ${vuln.priority ? `<span class="priority-badge">Priority: ${vuln.priority}</span>` : ''}
                        </div>
                        <div class="remediation-advice">
                            <h5><i class="fas fa-lightbulb"></i> Remediation</h5>
                            <p class="remediation-summary">${escapeHtml(vuln.remediation.summary)}</p>
                            ${vuln.remediation.details && vuln.remediation.details.length > 0 ? `
                                <ul class="remediation-steps">
                                    ${vuln.remediation.details.map(detail => `<li>${escapeHtml(detail)}</li>`).join('')}
                                </ul>
                            ` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    // Port recommendations
    if (remediations.port_recommendations && remediations.port_recommendations.length > 0) {
        html += `
            <div class="remediation-section">
                <h3><i class="fas fa-network-wired"></i> Port Recommendations</h3>
                ${remediations.port_recommendations.map(rec => `
                    <div class="port-recommendation">
                        <div class="port-header">
                            <span class="port-number">Port ${rec.port}</span>
                            <span class="protocol">${rec.protocol}</span>
                            <span class="port-status">${rec.status}</span>
                        </div>
                        <p class="recommendation-text">${escapeHtml(rec.recommendation)}</p>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    if (remediations.active_vulnerabilities.length === 0 && 
        remediations.passive_vulnerabilities.length === 0 && 
        remediations.port_recommendations.length === 0) {
        html += `
            <div class="no-vulnerabilities">
                <i class="fas fa-check-circle"></i>
                <h3>No Vulnerabilities Found</h3>
                <p>Great! No remediation suggestions needed.</p>
            </div>
        `;
    }
    
    remediationContent.innerHTML = html;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

closeRemediationBtn.addEventListener('click', () => {
    remediationSection.style.display = 'none';
});

newScanBtn.addEventListener('click', () => {
    currentScanId = null;
    progressSection.style.display = 'none';
    resultsSection.style.display = 'none';
    document.getElementById('scan-form-section').style.display = 'block';
    progressMessages.innerHTML = '';
    viewReportBtn.style.display = 'none';
});

async function loadScansList() {
    try {
        const response = await fetch('/api/scans');
        const data = await response.json();
        
        const scansList = document.getElementById('scans-list');
        
        if (data.scans.length === 0) {
            scansList.innerHTML = '<p class="loading">No previous scans found.</p>';
            return;
        }
        
        scansList.innerHTML = data.scans.map(scan => `
            <div class="scan-item">
                <div class="scan-info">
                    <h4>${scan.target_url}</h4>
                    <p>Started: ${new Date(scan.start_time).toLocaleString()}</p>
                    ${scan.summary ? `
                        <p>
                            ${scan.summary.vulnerabilities} vulnerabilities | 
                            ${scan.summary.open_ports} open ports | 
                            Grade: ${scan.summary.grade}
                        </p>
                    ` : ''}
                </div>
                <div>
                    <span class="scan-status ${scan.status || 'complete'}">
                        ${(scan.status || 'complete').toUpperCase()}
                    </span>
                    ${scan.scan_id === currentScanId && scan.status === 'complete' ? `
                        <button class="btn btn-success" style="margin-left: 10px;" 
                                onclick="window.open('/api/scan/${scan.scan_id}/report', '_blank')">
                            <i class="fas fa-file-alt"></i> View Report
                        </button>
                    ` : ''}
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading scans list:', error);
        document.getElementById('scans-list').innerHTML = 
            '<p class="loading">Error loading scan history.</p>';
    }
}

// Load scans list on page load
loadScansList();
setInterval(loadScansList, 10000); // Refresh every 10 seconds

