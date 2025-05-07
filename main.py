"""
MCP-Sec Gateway - Zero Trust Security Layer for Model Context Protocol
Main entry point for the Flask application
"""
import os
import time
import json
import csv
import io
import logging
import functools
import datetime
import threading
from flask import Flask, request, jsonify, render_template_string, Response, redirect, url_for, session, make_response, abort
from werkzeug.security import check_password_hash
from audit_logger import LOG_HISTORY
import policy_engine
import rate_limiter

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Constants
ADMIN_KEY = os.environ.get("ADMIN_KEY", "changeme")

# Get a logger for this module
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

# Import and register the MCP routes
from mcp_routes import mcp_bp
app.register_blueprint(mcp_bp)

# Setup metrics
metrics = {
    "total_requests": 0,
    "allowed_requests": 0,
    "denied_requests": 0,
    "error_requests": 0,
    "high_risk_count": 0,
    "medium_risk_count": 0,
    "low_risk_count": 0
}

# Update metrics from log history on startup
def update_metrics_from_history():
    global metrics
    for event in LOG_HISTORY:
        metrics["total_requests"] += 1
        status = event.get("status")
        if status == "allowed":
            metrics["allowed_requests"] += 1
        elif status == "denied":
            metrics["denied_requests"] += 1
        elif status == "error":
            metrics["error_requests"] += 1
            
        risk = event.get("risk_level", "low")
        if risk == "high":
            metrics["high_risk_count"] += 1
        elif risk == "medium":
            metrics["medium_risk_count"] += 1
        else:
            metrics["low_risk_count"] += 1

# Run the initial metrics update
update_metrics_from_history()

# Sample data generator for testing (run in background thread)
def generate_sample_data():
    import random
    import string
    import time
    
    models = ["gpt-4o", "claude-3", "gemini-pro", "llama-3"]
    sessions = [f"session-{i}" for i in range(1, 5)]
    tools = ["calendar.create_event", "search.web", "weather.forecast", "db.write", "file.read"]
    statuses = ["allowed", "denied", "error"]
    risk_levels = ["low", "medium", "high"]
    
    while True:
        from audit_logger import log_event
        
        # Generate random event
        event = {
            "model_id": random.choice(models),
            "session_id": random.choice(sessions),
            "tool": random.choice(tools),
            "status": random.choice(statuses),
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "risk_level": random.choice(risk_levels),
            "input": {"query": "".join(random.choices(string.ascii_letters, k=10))}
        }
        
        if event["status"] == "denied":
            event["reason"] = "Policy violation"
            
        # Log the event
        log_event(event)
        
        # Update metrics
        metrics["total_requests"] += 1
        if event["status"] == "allowed":
            metrics["allowed_requests"] += 1
        elif event["status"] == "denied":
            metrics["denied_requests"] += 1
        else:
            metrics["error_requests"] += 1
            
        if event["risk_level"] == "high":
            metrics["high_risk_count"] += 1
        elif event["risk_level"] == "medium":
            metrics["medium_risk_count"] += 1
        else:
            metrics["low_risk_count"] += 1
        
        # Sleep for a bit
        time.sleep(2)

# Start the sample data generator in a background thread (for demo purposes)
if os.environ.get("ENABLE_DEMO_DATA", "false").lower() == "true":
    threading.Thread(target=generate_sample_data, daemon=True).start()

# Authentication decorator
def require_api_key(view_function):
    @functools.wraps(view_function)
    def decorated_function(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get("X-Admin-Key")
        
        if not api_key:
            return abort(401)
        
        if api_key != ADMIN_KEY:
            return abort(401)
        
        # Continue to the view
        return view_function(*args, **kwargs)
    return decorated_function

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

# Login page
@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    error = session.pop("auth_error", None)
    return render_template_string("""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Gateway - Login</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Administrator Login</h5>
                    </div>
                    <div class="card-body">
                        {% if error %}
                        <div class="alert alert-danger">{{ error }}</div>
                        {% endif %}
                        <form method="post" action="{{ url_for('login_post', next=next) }}">
                            <div class="mb-3">
                                <label for="api_key" class="form-label">Admin API Key</label>
                                <input type="password" class="form-control" id="api_key" name="api_key" required>
                            </div>
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="remember" name="remember">
                                <label class="form-check-label" for="remember">Remember me</label>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                            <a href="/" class="btn btn-outline-secondary ms-2">Cancel</a>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>""", error=error, next=next_url)

@app.route("/login", methods=["POST"])
def login_post():
    next_url = request.args.get("next", "/")
    api_key = request.form.get("api_key")
    remember = request.form.get("remember") == "on"
    
    if not api_key:
        session["auth_error"] = "API key is required"
        return redirect(url_for("login", next=next_url))
    
    if api_key != ADMIN_KEY:
        session["auth_error"] = "Invalid API key"
        return redirect(url_for("login", next=next_url))
    
    # Set authentication in session
    session["authenticated"] = True
    
    # If remember is checked, set a cookie
    response = redirect(next_url)
    if remember:
        response.set_cookie("api_key", api_key, max_age=60*60*24*30)  # 30 days
    
    return response

@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    response = redirect(url_for("root"))
    response.delete_cookie("api_key")
    return response

# --- JSON API ---
@app.route("/api/logs")
@require_api_key
def api_logs():
    """Return filtered logs."""
    # query params
    since = request.args.get("since")          # ISO timestamp
    model = request.args.get("model")
    tool  = request.args.get("tool")
    status = request.args.get("status")        # allowed / denied / error
    limit = int(request.args.get("limit", 100))

    logs = LOG_HISTORY
    if since:
        cutoff = datetime.fromisoformat(since)
        logs = [l for l in logs if datetime.fromisoformat(l["timestamp"]) >= cutoff]
    if model:
        logs = [l for l in logs if l["model_id"].startswith(model)]
    if tool:
        logs = [l for l in logs if tool in l["tool"]]
    if status:
        logs = [l for l in logs if l["status"] == status]
    return jsonify(logs[-limit:])

@app.route("/api/metrics")
@require_api_key
def api_metrics():
    """Return simple counts & top lists."""
    total = len(LOG_HISTORY)
    allows = sum(1 for l in LOG_HISTORY if l["status"] == "allowed")
    denies = sum(1 for l in LOG_HISTORY if l["status"] == "denied")
    recent = LOG_HISTORY[-500:]
    top_tools = {}
    top_models = {}
    for l in recent:
        top_tools[l["tool"]]  = top_tools.get(l["tool"], 0) + 1
        top_models[l["model_id"]] = top_models.get(l["model_id"], 0) + 1
    return {
        "total": total,
        "allows": allows,
        "denies": denies,
        "top_tools": sorted(top_tools.items(), key=lambda x: x[1], reverse=True)[:5],
        "top_models": sorted(top_models.items(), key=lambda x: x[1], reverse=True)[:5],
    }

@app.route("/api/policy")
@require_api_key
def api_policy():
    return {"policy": policy_engine.load_policy()}

@app.route("/api/policy/reload", methods=["POST"])
@require_api_key
def api_policy_reload():
    policy_engine.reload_policies()
    return {"status": "reloaded"}

@app.route("/api/logs/export")
@require_api_key
def api_logs_export():
    """Download CSV of recent logs."""
    limit = int(request.args.get("limit", 1000))
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=LOG_HISTORY[0].keys() if LOG_HISTORY else [])
    if LOG_HISTORY:
        writer.writeheader()
        for row in LOG_HISTORY[-limit:]:
            writer.writerow(row)
    return output.getvalue(), 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=audit.csv",
    }
    
    return response

@app.route("/dash")
@require_api_key
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
        
        .metric-card {
            transition: transform 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-5px);
        }
        
        .filter-controls {
            background-color: rgba(0,0,0,0.05);
            border-radius: 0.25rem;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1060;
        }
    </style>
</head>
<body>
    <div class="container-fluid mt-4">
        <header class="mb-4 d-flex justify-content-between align-items-center">
            <div>
                <h1 class="display-5">MCP-Sec Gateway Dashboard</h1>
                <p class="lead">Real-time monitoring of Model Context Protocol traffic</p>
            </div>
            <div>
                <a href="/" class="btn btn-outline-secondary me-2">Home</a>
                <a href="/test" class="btn btn-outline-primary me-2">Test Interface</a>
                <a href="/logout" class="btn btn-outline-danger">Logout</a>
            </div>
        </header>

        <!-- Metrics Row -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card bg-primary bg-opacity-25 h-100 metric-card">
                    <div class="card-body text-center">
                        <h5 class="card-title">Total Requests</h5>
                        <h2 id="total-requests" class="display-4">--</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-success bg-opacity-25 h-100 metric-card">
                    <div class="card-body text-center">
                        <h5 class="card-title">Allowed</h5>
                        <h2 id="allowed-requests" class="display-4">--</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-danger bg-opacity-25 h-100 metric-card">
                    <div class="card-body text-center">
                        <h5 class="card-title">Denied</h5>
                        <h2 id="denied-requests" class="display-4">--</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-warning bg-opacity-25 h-100 metric-card">
                    <div class="card-body text-center">
                        <h5 class="card-title">High Risk</h5>
                        <h2 id="high-risk" class="display-4">--</h2>
                    </div>
                </div>
            </div>
        </div>

        <!-- Controls Row -->
        <div class="row mb-3">
            <div class="col">
                <div class="filter-controls d-flex flex-wrap gap-3 align-items-center">
                    <div>
                        <label for="model-filter" class="form-label mb-0">Model:</label>
                        <select id="model-filter" class="form-select form-select-sm">
                            <option value="">All Models</option>
                        </select>
                    </div>
                    <div>
                        <label for="tool-filter" class="form-label mb-0">Tool:</label>
                        <select id="tool-filter" class="form-select form-select-sm">
                            <option value="">All Tools</option>
                        </select>
                    </div>
                    <div>
                        <label for="status-filter" class="form-label mb-0">Status:</label>
                        <select id="status-filter" class="form-select form-select-sm">
                            <option value="">All</option>
                            <option value="allowed">Allowed</option>
                            <option value="denied">Denied</option>
                            <option value="error">Error</option>
                        </select>
                    </div>
                    <div>
                        <label for="risk-filter" class="form-label mb-0">Risk:</label>
                        <select id="risk-filter" class="form-select form-select-sm">
                            <option value="">All</option>
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                        </select>
                    </div>
                    <div class="d-flex align-items-center gap-2 ms-auto">
                        <button id="reload-policy-btn" class="btn btn-outline-warning btn-sm">
                            <i class="bi bi-arrow-clockwise"></i> Reload Policy
                        </button>
                        <button id="export-csv-btn" class="btn btn-outline-secondary btn-sm">
                            <i class="bi bi-download"></i> Export Logs
                        </button>
                        <button id="refreshBtn" class="btn btn-primary btn-sm">
                            Refresh
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Logs Table -->
        <div class="row">
            <div class="col-md-12">
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Activity Logs</h5>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="auto-refresh" checked>
                            <label class="form-check-label" for="auto-refresh">Auto-refresh</label>
                        </div>
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
        
        <!-- Toast container for notifications -->
        <div class="toast-container">
            <div id="notification-toast" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="toast-header">
                    <strong class="me-auto" id="toast-title">Notification</strong>
                    <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
                <div class="toast-body" id="toast-body">
                    This is a notification message.
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global state
        let logData = [];
        let autoRefreshEnabled = true;
        let autoRefreshInterval;
        let models = new Set();
        let tools = new Set();
        
        // Show notification toast
        function showNotification(title, message, type = 'success') {
            const toast = document.getElementById('notification-toast');
            const toastTitle = document.getElementById('toast-title');
            const toastBody = document.getElementById('toast-body');
            
            // Set content
            toastTitle.textContent = title;
            toastBody.textContent = message;
            
            // Set appearance based on type
            toast.classList.remove('bg-success', 'bg-danger', 'bg-warning', 'text-white');
            if (type === 'success') {
                toast.classList.add('bg-success', 'text-white');
            } else if (type === 'error') {
                toast.classList.add('bg-danger', 'text-white');
            } else if (type === 'warning') {
                toast.classList.add('bg-warning');
            }
            
            // Show the toast
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
        }
        
        // Fetch and update metrics
        function updateMetrics() {
            fetch('/api/metrics' + getQueryString())
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-requests').textContent = data.total_requests;
                    document.getElementById('allowed-requests').textContent = data.allowed_requests;
                    document.getElementById('denied-requests').textContent = data.denied_requests;
                    document.getElementById('high-risk').textContent = data.high_risk_count;
                })
                .catch(error => {
                    console.error('Error fetching metrics:', error);
                });
        }
        
        // Get query string from filters
        function getQueryString() {
            const model = document.getElementById('model-filter').value;
            const tool = document.getElementById('tool-filter').value;
            const status = document.getElementById('status-filter').value;
            const risk = document.getElementById('risk-filter').value;
            
            let params = new URLSearchParams();
            if (model) params.append('model', model);
            if (tool) params.append('tool', tool);
            if (status) params.append('status', status);
            if (risk) params.append('risk', risk);
            
            return params.toString() ? '?' + params.toString() : '';
        }
        
        // Function to fetch and display logs with filters
        function fetchLogs() {
            fetch('/api/logs' + getQueryString())
                .then(response => response.json())
                .then(data => {
                    logData = data; // Store for detail view
                    const logsTable = document.getElementById('logsTable');
                    logsTable.innerHTML = '';
                    
                    // Collect model and tool names
                    data.forEach(log => {
                        if (log.model_id) models.add(log.model_id);
                        if (log.tool) tools.add(log.tool);
                    });
                    
                    // Update filter dropdowns if they're empty
                    const modelFilter = document.getElementById('model-filter');
                    const toolFilter = document.getElementById('tool-filter');
                    
                    if (modelFilter.options.length <= 1) {
                        updateFilterOptions(modelFilter, models);
                    }
                    
                    if (toolFilter.options.length <= 1) {
                        updateFilterOptions(toolFilter, tools);
                    }

                    // Populate table
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
                            <td><span class="badge ${log.status === 'allowed' ? 'bg-success' : (log.status === 'denied' ? 'bg-danger' : 'bg-warning')}">${log.status || '-'}</span></td>
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
                            showLogDetail(index);
                        });
                    });
                })
                .catch(error => {
                    console.error('Error fetching logs:', error);
                });
                
            // Also update metrics
            updateMetrics();
        }
        
        // Update filter dropdown options
        function updateFilterOptions(selectElement, values) {
            // Save current selection
            const currentValue = selectElement.value;
            
            // Clear options except the first one
            while (selectElement.options.length > 1) {
                selectElement.remove(1);
            }
            
            // Add new options
            Array.from(values).sort().forEach(value => {
                const option = document.createElement('option');
                option.value = value;
                option.textContent = value;
                selectElement.appendChild(option);
            });
            
            // Restore selection if it still exists
            if (currentValue && Array.from(values).includes(currentValue)) {
                selectElement.value = currentValue;
            }
        }
        
        // Show log detail in modal
        function showLogDetail(index) {
            const logData = window.logData[index];
            document.getElementById('logDetailContent').textContent = JSON.stringify(logData, null, 2);
            document.getElementById('logDetailModalLabel').textContent = `Log Detail: ${logData.tool || 'Unknown'}`;
            
            // Show the modal
            const modal = new bootstrap.Modal(document.getElementById('logDetailModal'));
            modal.show();
        }
        
        // Setup auto-refresh
        function setupAutoRefresh() {
            const autoRefreshCheckbox = document.getElementById('auto-refresh');
            
            autoRefreshCheckbox.addEventListener('change', function() {
                autoRefreshEnabled = this.checked;
                
                if (autoRefreshEnabled) {
                    autoRefreshInterval = setInterval(fetchLogs, 5000);
                    showNotification('Auto-refresh', 'Auto-refresh enabled');
                } else {
                    clearInterval(autoRefreshInterval);
                    showNotification('Auto-refresh', 'Auto-refresh disabled', 'warning');
                }
            });
            
            // Initial setup
            if (autoRefreshEnabled) {
                autoRefreshInterval = setInterval(fetchLogs, 5000);
            }
        }
        
        // Initial load
        document.addEventListener('DOMContentLoaded', function() {
            // Initial data load
            fetchLogs();
            
            // Setup auto-refresh
            setupAutoRefresh();
            
            // Setup filter change listeners
            document.getElementById('model-filter').addEventListener('change', fetchLogs);
            document.getElementById('tool-filter').addEventListener('change', fetchLogs);
            document.getElementById('status-filter').addEventListener('change', fetchLogs);
            document.getElementById('risk-filter').addEventListener('change', fetchLogs);
            
            // Refresh button
            document.getElementById('refreshBtn').addEventListener('click', fetchLogs);
            
            // Export CSV button
            document.getElementById('export-csv-btn').addEventListener('click', function() {
                window.location.href = '/api/logs/export';
            });
            
            // Reload policy button
            document.getElementById('reload-policy-btn').addEventListener('click', function() {
                fetch('/api/policy/reload', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        showNotification('Policy Reload', 'Policy reloaded successfully', 'success');
                    } else {
                        showNotification('Policy Reload', 'Error: ' + data.message, 'error');
                    }
                })
                .catch(error => {
                    showNotification('Policy Reload', 'Error: ' + error, 'error');
                });
            });
        });
    </script>
</body>
</html>
"""
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=False)