"""
MCP-Sec Gateway - Zero Trust Security Layer for Model Context Protocol
Main entry point for the Flask application
"""
import os
import time
import json
import logging
from flask import Flask, request, jsonify, render_template_string
from audit_logger import LOG_HISTORY

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Import and register the MCP routes
from mcp_routes import mcp_bp
app.register_blueprint(mcp_bp)

@app.route("/healthz")
def health():
    return {"status": "ok"}

@app.route("/")
def root():
    """Root endpoint with navigation menu"""
    return render_template_string("""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Gateway</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8 text-center">
                <h1 class="display-3 mb-4">MCP-Sec Gateway</h1>
                <p class="lead mb-5">Zero-trust security gateway for Model Context Protocol</p>
                
                <div class="row g-4">
                    <div class="col-md-6">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <h5 class="card-title">Dashboard</h5>
                                <p class="card-text">Monitor MCP traffic with detailed logs and risk analysis</p>
                                <a href="/dash" class="btn btn-primary">View Dashboard</a>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <h5 class="card-title">Test Interface</h5>
                                <p class="card-text">Generate test traffic to verify gateway functionality</p>
                                <a href="/test" class="btn btn-primary">Open Tester</a>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="mt-5">
                    <h4 class="mb-3">API Endpoints</h4>
                    <div class="list-group">
                        <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                            <code>/mcp/toolcall</code>
                            <span class="badge bg-primary">POST</span>
                        </div>
                        <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                            <code>/mcp/toolresult</code>
                            <span class="badge bg-primary">POST</span>
                        </div>
                        <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                            <code>/logs</code>
                            <span class="badge bg-success">GET</span>
                        </div>
                        <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                            <code>/healthz</code>
                            <span class="badge bg-success">GET</span>
                        </div>
                    </div>
                </div>
                
                <div class="mt-4">
                    <div class="text-muted">
                        <small>MCP-Sec Gateway v1.0</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>""")

@app.route("/logs")
def logs():
    return jsonify(LOG_HISTORY[-100:])

@app.route("/test")
def test():
    """Test interface for manual API request submission"""
    return render_template_string("""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Gateway - Test Interface</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>
    <div class="container mt-4">
        <header class="mb-4 d-flex justify-content-between align-items-center">
            <div>
                <h1 class="display-4">MCP-Sec Gateway Tester</h1>
                <p class="lead">Submit test requests to verify gateway functionality</p>
            </div>
            <div>
                <a href="/" class="btn btn-outline-secondary me-2">Home</a>
                <a href="/dash" class="btn btn-outline-primary">Dashboard</a>
            </div>
        </header>

        <div class="row">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Tool Call Request</h5>
                    </div>
                    <div class="card-body">
                        <form id="toolCallForm">
                            <div class="mb-3">
                                <label for="modelId" class="form-label">Model ID</label>
                                <input type="text" class="form-control" id="modelId" value="gpt-4o">
                            </div>
                            <div class="mb-3">
                                <label for="sessionId" class="form-label">Session ID</label>
                                <input type="text" class="form-control" id="sessionId" value="test-session-123">
                            </div>
                            <div class="mb-3">
                                <label for="toolName" class="form-label">Tool Name</label>
                                <input type="text" class="form-control" id="toolName" value="calendar.create_event">
                            </div>
                            <div class="mb-3">
                                <label for="inputJson" class="form-label">Input JSON</label>
                                <textarea class="form-control" id="inputJson" rows="5">{"title": "Team meeting", "start_time": "2025-05-10T09:00:00Z"}</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Submit Tool Call</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Tool Result Request</h5>
                    </div>
                    <div class="card-body">
                        <form id="toolResultForm">
                            <div class="mb-3">
                                <label for="resultModelId" class="form-label">Model ID</label>
                                <input type="text" class="form-control" id="resultModelId" value="gpt-4o">
                            </div>
                            <div class="mb-3">
                                <label for="resultSessionId" class="form-label">Session ID</label>
                                <input type="text" class="form-control" id="resultSessionId" value="test-session-123">
                            </div>
                            <div class="mb-3">
                                <label for="resultToolName" class="form-label">Tool Name</label>
                                <input type="text" class="form-control" id="resultToolName" value="calendar.create_event">
                            </div>
                            <div class="mb-3">
                                <label for="outputJson" class="form-label">Output JSON</label>
                                <textarea class="form-control" id="outputJson" rows="5">{"event_id": "evt-123", "status": "created"}</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Submit Tool Result</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Response</h5>
                        <button id="clearResponseBtn" class="btn btn-sm btn-outline-secondary">Clear</button>
                    </div>
                    <div class="card-body">
                        <pre id="responseOutput" class="bg-dark text-light p-3 rounded" style="min-height: 200px; overflow-x: auto;"></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('toolCallForm').addEventListener('submit', function(e) {
            e.preventDefault();
            sendRequest('/mcp/toolcall', {
                model_id: document.getElementById('modelId').value,
                session_id: document.getElementById('sessionId').value,
                tool_name: document.getElementById('toolName').value,
                input: JSON.parse(document.getElementById('inputJson').value)
            });
        });

        document.getElementById('toolResultForm').addEventListener('submit', function(e) {
            e.preventDefault();
            sendRequest('/mcp/toolresult', {
                model_id: document.getElementById('resultModelId').value,
                session_id: document.getElementById('resultSessionId').value,
                tool_name: document.getElementById('resultToolName').value,
                output: JSON.parse(document.getElementById('outputJson').value)
            });
        });

        document.getElementById('clearResponseBtn').addEventListener('click', function() {
            document.getElementById('responseOutput').textContent = '';
        });

        function sendRequest(endpoint, data) {
            fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('responseOutput').textContent = JSON.stringify(data, null, 2);
            })
            .catch((error) => {
                document.getElementById('responseOutput').textContent = 'Error: ' + error;
            });
        }
    </script>
</body>
</html>""")

@app.route("/dash")
def dash():
    return render_template_string(
        """<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Gateway Dashboard</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        .risk-high { background-color: #dc3545; color: white; }
        .risk-medium { background-color: #ffc107; color: black; }
        .risk-low { background-color: #198754; color: white; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <header class="mb-4 d-flex justify-content-between align-items-center">
            <div>
                <h1 class="display-4">MCP-Sec Gateway Dashboard</h1>
                <p class="lead">Real-time monitoring of Model Context Protocol traffic</p>
            </div>
            <div>
                <a href="/" class="btn btn-outline-secondary me-2">Home</a>
                <a href="/test" class="btn btn-outline-primary">Test Interface</a>
            </div>
        </header>

        <div class="row">
            <div class="col-md-12">
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Recent Activity Logs</h5>
                        <button id="refreshBtn" class="btn btn-sm btn-outline-secondary">Refresh</button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Model ID</th>
                                        <th>Session ID</th>
                                        <th>Tool</th>
                                        <th>Status</th>
                                        <th>Risk Level</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody id="logsTable">
                                    <!-- Logs will be populated here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detail Modal -->
        <div class="modal fade" id="logDetailModal" tabindex="-1" aria-labelledby="logDetailModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="logDetailModalLabel">Log Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <pre id="logDetailContent" class="bg-dark text-light p-3 rounded" style="overflow-x: auto;"></pre>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Function to fetch and display logs
        function fetchLogs() {
            fetch('/logs')
                .then(response => response.json())
                .then(data => {
                    const logsTable = document.getElementById('logsTable');
                    logsTable.innerHTML = '';

                    data.forEach((log, index) => {
                        const tr = document.createElement('tr');
                        
                        // Apply row styling based on risk level or status
                        let riskLevel = log.risk_level || 'low';
                        let statusClass = log.status === 'denied' ? 'table-danger' : 
                                         (log.status === 'allowed' ? 'table-success' : '');
                        
                        if (riskLevel === 'high') {
                            tr.classList.add('table-danger');
                        } else if (riskLevel === 'medium') {
                            tr.classList.add('table-warning');
                        } else if (statusClass) {
                            tr.classList.add(statusClass);
                        }

                        // Format timestamp to local time if it exists
                        const timestamp = log.timestamp ? 
                            new Date(log.timestamp).toLocaleString() : 
                            new Date().toLocaleString();
                        
                        tr.innerHTML = `
                            <td>${timestamp}</td>
                            <td>${log.model_id || '-'}</td>
                            <td>${log.session_id || '-'}</td>
                            <td>${log.tool || '-'}</td>
                            <td><span class="badge ${log.status === 'allowed' ? 'bg-success' : 'bg-danger'}">${log.status || '-'}</span></td>
                            <td><span class="badge risk-${riskLevel}">${riskLevel}</span></td>
                            <td>
                                <button class="btn btn-sm btn-outline-info view-details" data-index="${index}">
                                    Details
                                </button>
                            </td>
                        `;
                        logsTable.appendChild(tr);
                    });

                    // Set up event listeners for detail buttons
                    document.querySelectorAll('.view-details').forEach(button => {
                        button.addEventListener('click', function() {
                            const index = this.getAttribute('data-index');
                            const logData = data[index];
                            document.getElementById('logDetailContent').textContent = JSON.stringify(logData, null, 2);
                            document.getElementById('logDetailModalLabel').textContent = `Log Detail: ${logData.tool || 'Unknown'}`;
                            
                            // Show the modal
                            const modal = new bootstrap.Modal(document.getElementById('logDetailModal'));
                            modal.show();
                        });
                    });
                })
                .catch(error => {
                    console.error('Error fetching logs:', error);
                });
        }

        // Initial load
        document.addEventListener('DOMContentLoaded', fetchLogs);

        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', fetchLogs);

        // Auto-refresh every 15 seconds
        setInterval(fetchLogs, 15000);
    </script>
</body>
</html>
"""
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=False)