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
from flask import Flask, request, jsonify, render_template_string, Response, redirect, url_for, session, make_response, abort
from audit_logger import LOG_HISTORY
import policy_engine
import rate_limiter

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Constants
ADMIN_KEY = os.environ.get("ADMIN_KEY")

# Get a logger for this module
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

# Import and register the MCP routes
from mcp_routes import mcp_bp
app.register_blueprint(mcp_bp)

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
        
        # Sleep for a bit
        time.sleep(2)

# Start the sample data generator in a background thread (for demo purposes)
if os.environ.get("ENABLE_DEMO_DATA", "false").lower() == "true":
    import threading
    threading.Thread(target=generate_sample_data, daemon=True).start()

# Authentication decorator
def require_api_key(view_function):
    @functools.wraps(view_function)
    def decorated_function(*args, **kwargs):
        # Check for API key in header or query param
        api_key = request.headers.get("X-Admin-Key") 
        if not api_key and request.args.get("api_key"):
            api_key = request.args.get("api_key")
        
        if not api_key:
            logger.warning("Missing API key in request")
            return abort(401)
        
        if api_key != ADMIN_KEY:
            logger.warning(f"Invalid API key provided: {api_key[:3]}...")
            return abort(401)
        
        # Continue to the view
        return view_function(*args, **kwargs)
    return decorated_function

@app.route("/healthz")
def health():
    return {"status": "ok"}

@app.route("/dashkey")
def dashboard_key():
    """Simple dashboard to test authentication"""
    admin_key = os.environ.get("ADMIN_KEY")
    return f"""
    <html>
    <head><title>Dashboard API Key Test</title></head>
    <body>
        <h1>Dashboard API Key Test</h1>
        <p>Your ADMIN_KEY environment variable is set to: {admin_key[:3]}*** (first 3 characters shown)</p>
        <p>Try visiting the <a href="/dash">dashboard</a> using this key.</p>
        <p>To access the <a href="/api/metrics">API metrics endpoint</a> with a curl request:</p>
        <pre>curl -H "X-Admin-Key: {admin_key}" https://your-site.example.com/api/metrics</pre>
    </body>
    </html>
    """

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

from pathlib import Path

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
        cutoff = datetime.datetime.fromisoformat(since)
        logs = [l for l in logs if datetime.datetime.fromisoformat(l["timestamp"]) >= cutoff]
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
    
@app.route("/api/schema/reload", methods=["POST"])
@require_api_key
def api_schema_reload():
    from schema_validator import reload_schemas
    reload_schemas()
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

@app.route("/api/config")
@require_api_key
def api_get_config():
    return {
        "log_level": os.getenv("LOG_LEVEL", "info"),
        "max_hist": int(os.getenv("MAX_HIST", 500)),
        "auto_refresh_ms": int(os.getenv("AUTO_REFRESH_MS", 2000)),
        "policy_yaml": Path(os.getenv("POLICY_PATH", "policies.yaml")).read_text(),
        "contextual_policy_yaml": Path("contextual_policy.yaml").read_text(),
    }

@app.route("/api/config", methods=["POST"])
@require_api_key
def api_save_config():
    data = request.json or {}
    # 1. Update basic policy
    if "policy_yaml" in data:
        Path(os.getenv("POLICY_PATH", "policies.yaml")).write_text(data["policy_yaml"])
    
    # 2. Update contextual policy
    if "contextual_policy_yaml" in data:
        Path("contextual_policy.yaml").write_text(data["contextual_policy_yaml"])
    
    # 3. Reload policies if either was updated
    if "policy_yaml" in data or "contextual_policy_yaml" in data:
        policy_engine.reload_policies()
        
    # 4. Update runtime env vars (non-persistent in Replit)
    for k in ("LOG_LEVEL", "MAX_HIST", "AUTO_REFRESH_MS"):
        if k.lower() in data:
            os.environ[k] = str(data[k.lower()])
            
    return {"status": "saved"}

@app.route("/dash", methods=["GET"])
@require_api_key
def dash():
    return """<!doctype html>
<html>
<head>
<title>MCP‑Sec Dashboard</title>
<style>
  body{font-family:Arial,sans-serif;margin:0;padding:0;background:#121212;color:#eee;}
  
  /* Header and menu styles */
  header{padding:15px;background:#202020;}
  .main-menu{display:flex;flex-wrap:wrap;gap:10px;align-items:center;}
  .menu-button{background:#303030;color:#fff;border:1px solid #555;padding:8px 15px;
    cursor:pointer;border-radius:4px;font-weight:bold;min-width:100px;transition:all 0.2s ease;}
  .menu-button:hover{background:#404040;transform:translateY(-2px);box-shadow:0 3px 5px rgba(0,0,0,0.2);}
  .menu-button.active{background:#0a84ff;border-color:#0a84ff;}
  .menu-button.action{background:#2a6b2a;border-color:#2a6b2a;}
  .menu-button.action:hover{background:#3c8c3c;}
  
  /* Filter and control elements */
  header input, header select, .panel select, .panel input{
    background:#303030;color:#fff;border:1px solid #555;padding:6px 8px;border-radius:4px;}
  .export-button{color:#fff;text-decoration:none;padding:6px 10px;
    background:#303030;border:1px solid #555;border-radius:4px;transition:all 0.2s ease;}
  .export-button:hover{background:#404040;}
  
  /* Panel containers */
  .panel{padding:15px;display:none;}
  .panel-title{margin-top:0;margin-bottom:15px;font-size:1.4em;color:#0a84ff;}
  
  /* Metrics and stats visualization */
  #metrics-panel{display:flex;flex-wrap:wrap;gap:20px;}
  .metric{padding:15px;background:#202020;border-radius:8px;min-width:150px;
    display:flex;flex-direction:column;align-items:center;text-align:center;}
  .metric-value{font-size:2em;font-weight:bold;margin:10px 0;}
  .metric-label{font-size:0.9em;color:#aaa;}
  
  /* Tables */
  table{width:100%;border-collapse:collapse;margin-top:10px;border-radius:4px;overflow:hidden;}
  th{background:#252525;text-align:left;font-weight:bold;}
  th,td{padding:8px 12px;border-bottom:1px solid #333;}
  tr:hover{background:#252525;}
  tr.allowed{background:#0b3d0b;} 
  tr.allowed:hover{background:#0c470c;}
  tr.denied{background:#4d0b0b;}
  tr.denied:hover{background:#5e0d0d;}
  tr.error{background:#4d360b;}
  tr.error:hover{background:#5e420d;}
  
  /* Form elements */
  .panel label{display:block;margin-bottom:15px;}
  .panel textarea{background:#303030;color:#fff;border:1px solid #555;
    padding:10px;border-radius:4px;font-family:monospace;resize:vertical;}
  .save-button{background:#2a6b2a;color:#fff;border:1px solid #1e4e1e;
    padding:8px 15px;cursor:pointer;border-radius:4px;font-weight:bold;transition:all 0.2s ease;}
  .save-button:hover{background:#3c8c3c;}
  .success-message{color:#4caf50;margin-left:10px;font-weight:bold;}
</style>
</head>
<body>
<header>
  <div class="main-menu">
    <button onclick="showTab('logs')" class="menu-button">Audit Logs</button>
    <button onclick="showTab('metrics-panel')" class="menu-button">Metrics</button>
    <button onclick="showTab('basic-policy')" class="menu-button">Basic Policy</button>
    <button onclick="showTab('contextual-policy')" class="menu-button">Contextual Policy</button>
    <button onclick="showTab('settings')" class="menu-button">Settings</button>
    <button onclick="reloadPolicy()" class="menu-button action">Reload Policies</button>
  </div>
  <div id="log-controls" style="display:flex;gap:10px;align-items:center;margin-top:10px;background:#252525;padding:8px;border-radius:6px;">
    <label>Since (ISO): <input id="since" type="text" placeholder="2025-05-07T00:00:00"></label>
    <label>Model: <input id="model" type="text"></label>
    <label>Tool:  <input id="tool"  type="text"></label>
    <label>Status:
      <select id="status">
        <option value="">all</option><option>allowed</option><option>denied</option><option>error</option>
      </select>
    </label>
    <a id="csv-export" class="export-button" href="/api/logs/export">Export CSV</a>
  </div>
</header>
<!-- Logs Panel -->
<div id="logs" class="panel">
  <h2 class="panel-title">Audit Logs</h2>
  <p>View and filter all security gateway activity including tool calls, policy decisions, and errors.</p>
  <table id="logtbl">
    <thead>
      <tr>
        <th>Time</th><th>Model</th><th>Tool</th><th>Status</th><th>Reason</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
</div>

<!-- Metrics Panel -->
<div id="metrics-panel" class="panel">
  <h2 class="panel-title">Security Metrics</h2>
  <p>Real-time dashboard of security gateway activity and policy enforcement.</p>
  
  <div class="metrics-container">
    <div class="metric">
      <div class="metric-label">Total Requests</div>
      <div id="metric-total" class="metric-value">0</div>
    </div>
    
    <div class="metric">
      <div class="metric-label">Allowed</div>
      <div id="metric-allows" class="metric-value">0</div>
    </div>
    
    <div class="metric">
      <div class="metric-label">Denied</div>
      <div id="metric-denies" class="metric-value">0</div>
    </div>
    
    <div class="metric">
      <div class="metric-label">Error Rate</div>
      <div id="metric-error-rate" class="metric-value">0%</div>
    </div>
  </div>
</div>

<!-- Basic Policy Panel -->
<div id="basic-policy" class="panel">
  <h2 class="panel-title">Basic Policy Configuration</h2>
  <p>Configure the core policies that control which models can access which tools.</p>
  
  <textarea id="policy_editor" style="width:100%;height:400px;"></textarea>
  <button onclick="savePolicy('basic')" class="save-button">Save & Reload</button>
  <span id="basic_save_msg" class="success-message"></span>
</div>

<!-- Contextual Policy Panel -->
<div id="contextual-policy" class="panel">
  <h2 class="panel-title">Contextual Policy Configuration</h2>
  <p>Configure advanced policies that evaluate the full session context, including prompts and tool call history.</p>
  
  <textarea id="contextual_policy_editor" style="width:100%;height:400px;"></textarea>
  <button onclick="savePolicy('contextual')" class="save-button">Save & Reload</button>
  <span id="contextual_save_msg" class="success-message"></span>
</div>

<!-- Settings Panel -->
<div id="settings" class="panel">
  <h2 class="panel-title">Gateway Settings</h2>
  <p>Configure global settings for the security gateway operation.</p>
  
  <div class="settings-grid">
    <label>Log level:
      <select id="cfg_log_level">
        <option>debug</option><option selected>info</option>
        <option>warning</option><option>error</option>
      </select>
    </label>
    
    <label>Max log rows in memory:
      <input id="cfg_max_hist" type="number" min="100" step="100">
    </label>
    
    <label>Auto-refresh interval (ms):
      <input id="cfg_auto" type="number" step="500">
    </label>
  </div>
  
  <button onclick="saveSettings()" class="save-button">Save Settings</button>
  <span id="settings_save_msg" class="success-message"></span>
</div>

<script>
const apiKey = prompt("Admin API key:", "");
const headers = {"X-Admin-Key": apiKey};
// Update CSV export URL with proper header
document.getElementById("csv-export").href = `/api/logs/export`;
document.getElementById("csv-export").onclick = function(e) {
  e.preventDefault();
  fetch('/api/logs/export', {
    headers: headers
  })
  .then(response => response.blob())
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
  });
};

let currentTab = "logs";
function qs(id){return document.getElementById(id)}

function showTab(t){
  // Update current tab
  currentTab = t;
  
  // Hide all panels
  document.querySelectorAll('.panel').forEach(panel => {
    panel.style.display = 'none';
  });
  
  // Remove active class from all menu buttons
  document.querySelectorAll('.menu-button').forEach(btn => {
    btn.classList.remove('active');
  });
  
  // Show selected panel
  if (t === 'logs') {
    qs('logs').style.display = 'block';
    qs('log-controls').style.display = 'flex';
    document.querySelector('.menu-button:nth-child(1)').classList.add('active');
  } else if (t === 'metrics-panel') {
    qs('metrics-panel').style.display = 'block';
    updateMetricsDisplay();
    document.querySelector('.menu-button:nth-child(2)').classList.add('active');
  } else if (t === 'basic-policy') {
    qs('basic-policy').style.display = 'block';
    document.querySelector('.menu-button:nth-child(3)').classList.add('active');
  } else if (t === 'contextual-policy') {
    qs('contextual-policy').style.display = 'block';
    document.querySelector('.menu-button:nth-child(4)').classList.add('active');
  } else if (t === 'settings') {
    qs('settings').style.display = 'block';
    document.querySelector('.menu-button:nth-child(5)').classList.add('active');
  }
}

async function loadConfig(){
  const cfg = await fetchJSON("/api/config");
  // Settings panel
  qs("cfg_log_level").value = cfg.log_level || "info";
  qs("cfg_max_hist").value = cfg.max_hist || 500;
  qs("cfg_auto").value = cfg.auto_refresh_ms || 2000;
  
  // Policy panels
  qs("policy_editor").value = cfg.policy_yaml || "";
  qs("contextual_policy_editor").value = cfg.contextual_policy_yaml || "";
}

function updateMetricsDisplay() {
  // Only update if we're on the metrics tab
  if (currentTab !== 'metrics-panel') return;
  
  fetchJSON("/api/metrics").then(m => {
    qs("metric-total").textContent = m.total || 0;
    qs("metric-allows").textContent = m.allows || 0;
    qs("metric-denies").textContent = m.denies || 0;
    
    // Calculate error rate
    const errorRate = m.total > 0 ? Math.round((m.errors || 0) * 100 / m.total) : 0;
    qs("metric-error-rate").textContent = errorRate + "%";
  });
}

async function savePolicy(policyType) {
  const saveMsg = qs(policyType + "_save_msg");
  const body = {};
  
  if (policyType === 'basic') {
    body.policy_yaml = qs("policy_editor").value;
  } else if (policyType === 'contextual') {
    body.contextual_policy_yaml = qs("contextual_policy_editor").value;
  }
  
  try {
    const res = await fetch("/api/config", {
      method: "POST",
      headers: {...headers, "Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
    
    if (res.ok) {
      // Reload policies
      await fetch("/api/policy/reload", {method: "POST", headers});
      saveMsg.textContent = "Saved and reloaded ✅";
      setTimeout(() => saveMsg.textContent = "", 2000);
    } else {
      saveMsg.textContent = "Error: " + (await res.text());
      setTimeout(() => saveMsg.textContent = "", 5000);
    }
  } catch (e) {
    saveMsg.textContent = "Error: " + e.message;
    setTimeout(() => saveMsg.textContent = "", 5000);
  }
}

async function saveSettings() {
  const saveMsg = qs("settings_save_msg");
  const body = {
    log_level: qs("cfg_log_level").value,
    max_hist: parseInt(qs("cfg_max_hist").value),
    auto_refresh_ms: parseInt(qs("cfg_auto").value)
  };
  
  try {
    const res = await fetch("/api/config", {
      method: "POST",
      headers: {...headers, "Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
    
    if (res.ok) {
      saveMsg.textContent = "Settings saved ✅";
      setTimeout(() => saveMsg.textContent = "", 2000);
    } else {
      saveMsg.textContent = "Error: " + (await res.text());
      setTimeout(() => saveMsg.textContent = "", 5000);
    }
  } catch (e) {
    saveMsg.textContent = "Error: " + e.message;
    setTimeout(() => saveMsg.textContent = "", 5000);
  }
}

async function fetchJSON(url){
  const res = await fetch(url, {headers}); 
  if(!res.ok) return {};
  return res.json();
}

async function updateMetricsDisplay() {
  // Only update if we're on the metrics tab
  if (currentTab !== 'metrics-panel') return;
  
  try {
    const m = await fetchJSON("/api/metrics");
    qs("metric-total").textContent = m.total || 0;
    qs("metric-allows").textContent = m.allows || 0;
    qs("metric-denies").textContent = m.denies || 0;
    
    // Calculate error rate
    const errorRate = m.total > 0 ? Math.round((m.errors || 0) * 100 / m.total) : 0;
    qs("metric-error-rate").textContent = errorRate + "%";
  } catch (e) {
    console.error("Error updating metrics:", e);
  }
}

async function loadLogs(){
  if (currentTab !== "logs") return;
  
  try {
    const p = new URLSearchParams();
    ["since","model","tool","status"].forEach(k => {
      const v = qs(k).value;
      if(v) p.set(k,v);
    });
    
    const logs = await fetchJSON("/api/logs?" + p.toString());
    const tb = qs("logtbl").querySelector("tbody");
    
    if (logs && Array.isArray(logs) && logs.length > 0) {
      tb.innerHTML = logs.map(l => `
        <tr class="${l.status || 'unknown'}">
          <td>${l.timestamp || ''}</td>
          <td>${l.model_id || ''}</td>
          <td>${l.tool || ''}</td>
          <td>${l.status || ''}</td>
          <td>${l.reason || ''}</td>
        </tr>`).join("");
    } else {
      tb.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;">No logs match the current filter criteria</td></tr>';
    }
  } catch (e) {
    console.error("Error loading logs:", e);
  }
}

function reloadPolicy(){
  fetch("/api/policy/reload", {
    method: "POST", 
    headers
  }).then(res => {
    if (res.ok) {
      alert("Policies successfully reloaded");
    } else {
      alert("Error reloading policies: " + res.statusText);
    }
  }).catch(e => {
    alert("Error reloading policies: " + e.message);
  });
}

// Initialize app
loadConfig();
showTab('logs');
loadLogs();

// Start polling for updates
setInterval(() => {
  if (currentTab === "logs") {
    loadLogs();
  } else if (currentTab === "metrics-panel") {
    updateMetricsDisplay();
  }
}, parseInt(qs("cfg_auto") ? qs("cfg_auto").value : 2000));
</script>
</body>
</html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=False)