#!/usr/bin/env python3
"""
MCP-Sec Gateway - Zero Trust Security Layer for Model Context Protocol
Main entry point for the Flask application
"""
import os
import logging
from flask import Flask, jsonify, render_template, send_from_directory
from dotenv import load_dotenv

from audit_logger import get_recent_logs
from policy_engine import reload_policies
from models import db, AuditLog

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__, template_folder="templates")

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if database_url:
    # SQLAlchemy 1.4+ compatibility fix for postgres URLs
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    logger.info(f"Database URL found, connecting to database...")
else:
    logger.error("DATABASE_URL environment variable not found")
    # Fall back to SQLite for development
    database_url = "sqlite:///mcp_gateway.db"
    logger.warning(f"Falling back to SQLite database: {database_url}")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the database with the app
db.init_app(app)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()
    logger.info("Database tables created if they didn't exist")

# Ensure templates directory exists
os.makedirs("templates", exist_ok=True)

# Root endpoint
@app.route("/")
def root():
    """Root endpoint to check if the service is running"""
    return "MCP-Sec Gateway OK"

# Get logs endpoint
@app.route("/logs")
def logs():
    """Return the most recent log entries"""
    return jsonify({"logs": get_recent_logs(100)})

# Dashboard endpoint
@app.route("/dash")
def dashboard():
    """Simple dashboard to display the most recent logs"""
    return render_template("dashboard.html")

# Test interface endpoint
@app.route("/test")
def test_interface():
    """Test interface for sending requests to the API"""
    return render_template("test.html")

# Reload policies endpoint
@app.route("/reload", methods=["POST"])
def reload():
    """Reload the policies from the yaml file"""
    try:
        reload_policies()
        return jsonify({"status": "success", "message": "Policies reloaded successfully"})
    except Exception as e:
        logger.error(f"Failed to reload policies: {e}")
        return jsonify({"status": "error", "message": f"Failed to reload policies: {str(e)}"})

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

# Import mcp routes after Flask app is created to avoid circular imports
from mcp_routes import register_mcp_routes
register_mcp_routes(app)

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
