#!/usr/bin/env python3
"""
MCP-Sec Gateway - Zero Trust Security Layer for Model Context Protocol
Main entry point for the FastAPI application
"""
import os
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import gateway
from policy_engine import reload_policies
from audit_logger import get_recent_logs

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="MCP-Sec Gateway",
    description="Zero Trust Security Layer for Model Context Protocol",
    version="1.0.0",
)

# Include the gateway router
app.include_router(gateway.router)

# Add static files and templates
templates = Jinja2Templates(directory="templates")

# Create templates directory if it doesn't exist
os.makedirs("templates", exist_ok=True)

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint to check if the service is running"""
    return HTMLResponse("MCP-Sec Gateway OK")

# Get logs endpoint
@app.get("/logs")
async def logs():
    """Return the most recent log entries"""
    return {"logs": get_recent_logs(100)}

# Dashboard endpoint
@app.get("/dash", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Simple dashboard to display the most recent logs"""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )

# Reload policies endpoint
@app.post("/reload")
async def reload():
    """Reload the policies from the yaml file"""
    try:
        reload_policies()
        return {"status": "success", "message": "Policies reloaded successfully"}
    except Exception as e:
        logger.error(f"Failed to reload policies: {e}")
        return {"status": "error", "message": f"Failed to reload policies: {str(e)}"}

# Create templates directory and dashboard.html if they don't exist
os.makedirs("templates", exist_ok=True)
with open("templates/dashboard.html", "w") as f:
    f.write("""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Gateway Dashboard</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>
    <div class="container mt-4">
        <header class="mb-4">
            <h1 class="display-4">MCP-Sec Gateway Dashboard</h1>
            <p class="lead">Real-time monitoring of Model Context Protocol traffic</p>
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
                                        <th>Latency (ms)</th>
                                        <th>Actions</th>
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

                    data.logs.forEach((log, index) => {
                        const tr = document.createElement('tr');
                        
                        // Apply different row styling based on status
                        if (log.status === 'denied') {
                            tr.classList.add('table-danger');
                        } else if (log.status === 'allowed') {
                            tr.classList.add('table-success');
                        }

                        // Format timestamp to local time
                        const timestamp = new Date(log.timestamp).toLocaleString();
                        
                        tr.innerHTML = `
                            <td>${timestamp}</td>
                            <td>${log.model_id || '-'}</td>
                            <td>${log.session_id || '-'}</td>
                            <td>${log.tool || '-'}</td>
                            <td><span class="badge ${log.status === 'allowed' ? 'bg-success' : 'bg-danger'}">${log.status}</span></td>
                            <td>${log.latency_ms !== undefined ? log.latency_ms : '-'}</td>
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
                            const logData = data.logs[index];
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

        // Auto-refresh every 30 seconds
        setInterval(fetchLogs, 30000);
    </script>
</body>
</html>
""")

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
