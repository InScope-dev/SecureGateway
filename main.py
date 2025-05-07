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
    }

@app.route("/api/config", methods=["POST"])
@require_api_key
def api_save_config():
    data = request.json or {}
    # 1. Update policy
    if "policy_yaml" in data:
        Path(os.getenv("POLICY_PATH", "policies.yaml")).write_text(data["policy_yaml"])
        policy_engine.reload_policies()
    # 2. Update runtime env vars (non-persistent in Replit)
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
  body{font-family:Arial;margin:0;padding:0;background:#121212;color:#eee;}
  header{padding:10px;background:#202020;display:flex;gap:20px;align-items:center;}
  header input,header select,#config select,#config input{background:#303030;color:#fff;border:1px solid #555;padding:4px;}
  #metrics{display:flex;gap:20px;margin:10px;}
  .metric{padding:10px;background:#202020;border-radius:6px;}
  table{width:100%;border-collapse:collapse;margin-top:10px;}
  th,td{padding:6px 8px;border-bottom:1px solid #333;}
  tr.allowed{background:#0b3d0b;} tr.denied{background:#4d0b0b;}
  tr.error{background:#4d360b;}
  button{background:#303030;color:#fff;border:1px solid #555;padding:6px 12px;cursor:pointer;margin-right:5px;}
  button:hover{background:#404040;}
  #config label{display:block;margin-bottom:10px;}
  #config textarea{background:#303030;color:#fff;border:1px solid #555;}
</style>
</head>
<body>
<header>
  <button onclick="showTab('logs')">Logs</button>
  <button onclick="showTab('config')">Config</button>
  <div id="log-controls" style="display:flex;gap:10px;align-items:center;">
    <label>Since (ISO): <input id="since" type="text" placeholder="2025-05-07T00:00:00"></label>
    <label>Model: <input id="model" type="text"></label>
    <label>Tool:  <input id="tool"  type="text"></label>
    <label>Status:
      <select id="status">
        <option value="">all</option><option>allowed</option><option>denied</option><option>error</option>
      </select>
    </label>
    <button onclick="reloadPolicy()">Reload Policy</button>
    <a id="csv-export" class="btn btn-sm btn-outline-secondary" style="color:#aaa;text-decoration:none;padding:4px 8px;border:1px solid #555;border-radius:3px;" href="/api/logs/export">Export CSV</a>
  </div>
</header>
<div id="metrics"></div>

<!-- Logs Panel -->
<div id="logs">
  <table id="logtbl"><thead><tr>
    <th>Time</th><th>Model</th><th>Tool</th><th>Status</th><th>Reason</th>
  </tr></thead><tbody></tbody></table>
</div>

<!-- Config Panel -->
<div id="config" style="display:none;padding:10px;">
  <h3>Gateway Settings</h3>
  <label>Log level:
    <select id="cfg_log_level">
      <option>debug</option><option selected>info</option>
      <option>warning</option><option>error</option>
    </select>
  </label>
  <label>Max log rows in memory:
    <input id="cfg_max_hist" type="number" min="100" step="100">
  </label>
  <label>Auto‑refresh ms:
    <input id="cfg_auto" type="number" step="500">
  </label>
  <h3>Policies.yaml</h3>
  <textarea id="policy_editor" style="width:100%;height:300px;font-family:monospace;"></textarea>
  <br><button onclick="saveConfig()">Save & Reload</button>
  <span id="save_msg"></span>
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
  currentTab = t;
  qs("logs").style.display = t === "logs" ? "block" : "none";
  qs("config").style.display = t === "config" ? "block" : "none";
  qs("log-controls").style.display = t === "logs" ? "flex" : "none";
  qs("metrics").style.display = t === "logs" ? "flex" : "none";
}

async function loadConfig(){
  const cfg = await fetchJSON("/api/config");
  qs("cfg_log_level").value = cfg.log_level;
  qs("cfg_max_hist").value = cfg.max_hist;
  qs("cfg_auto").value = cfg.auto_refresh_ms;
  qs("policy_editor").value = cfg.policy_yaml;
}

async function saveConfig(){
  const body = {
    log_level: qs("cfg_log_level").value,
    max_hist: parseInt(qs("cfg_max_hist").value),
    auto_refresh_ms: parseInt(qs("cfg_auto").value),
    policy_yaml: qs("policy_editor").value
  };
  const res = await fetch("/api/config",{
    method: "POST",
    headers: {...headers, "Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  if(res.ok){ 
    qs("save_msg").innerText = "Saved ✔"; 
    setTimeout(() => qs("save_msg").innerText = "", 2000); 
  } else { 
    alert("Save failed"); 
  }
}

async function fetchJSON(url){
  const res = await fetch(url,{headers}); if(!res.ok) return [];
  return res.json();
}

async function loadMetrics(){
  const m=await fetchJSON("/api/metrics");
  qs("metrics").innerHTML=
    `<div class=metric>Total ${m.total}</div>`+
    `<div class=metric>Allows ${m.allows}</div>`+
    `<div class=metric>Denies ${m.denies}</div>`;
}

async function loadLogs(){
  if (currentTab !== "logs") return;
  const p=new URLSearchParams();
  ["since","model","tool","status"].forEach(k=>{const v=qs(k).value;if(v)p.set(k,v)});
  const logs=await fetchJSON("/api/logs?"+p.toString());
  const tb=qs("logtbl").querySelector("tbody");
  tb.innerHTML=logs.map(l=>`
    <tr class="${l.status}">
      <td>${l.timestamp}</td><td>${l.model_id}</td>
      <td>${l.tool}</td><td>${l.status}</td><td>${l.reason||""}</td>
    </tr>`).join("");
}

function reloadPolicy(){
  fetch("/api/policy/reload",{method:"POST",headers}).then(()=>alert("Policy reloaded"));
}

// Load configuration on first load
loadConfig();

// Start polling for logs/metrics
setInterval(() => {
  if (currentTab === "logs") {
    loadLogs();
    loadMetrics();
  }
}, parseInt(qs("cfg_auto") ? qs("cfg_auto").value : 2000));

// Initial load
loadLogs();
loadMetrics();
</script>
</body>
</html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=False)