"""
MCP-Sec Gateway - Zero Trust Security Layer for Model Context Protocol
Main entry point for the Flask application
"""
import datetime
import json
import logging
import os
import random
import time
from functools import wraps
from typing import Dict, List, Union, Optional, Any, Tuple

import yaml
from flask import Flask, request, jsonify, Response, render_template

import audit_logger
import mcp_routes
import policy_engine
import schema_validator
import session_tracker
from rate_limiter import reset_limits

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Setup logger for this module
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "mcp-sec-insecure-key")

# Configuration defaults
config = {
    "log_level": "info",
    "max_hist": 500,
    "auto_refresh_ms": 2000
}

def generate_sample_data():
    """Generate sample data for initial testing"""
    models = ["gpt-4-0613", "claude-3-opus", "gemini-pro", "llama-3-70b"]
    tools = ["calendar.create_event", "email.send", "search.web", "file.write", "file.read"]
    statuses = ["allowed", "allowed", "allowed", "denied", "error"]
    
    events = []
    
    # Generate events over the past week
    for i in range(100):
        timestamp = datetime.datetime.now() - datetime.timedelta(
            days=random.randint(0, 7),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        status = random.choice(statuses)
        model = random.choice(models)
        tool = random.choice(tools)
        
        reason = None
        if status == "denied":
            reason = random.choice([
                "Model not authorized for this tool",
                "Rate limit exceeded",
                "Policy violation detected",
                "Missing required permissions"
            ])
        elif status == "error":
            reason = random.choice([
                "Schema validation failed",
                "Tool endpoint unavailable",
                "Malformed request",
                "Invalid parameters"
            ])
            
        event = {
            "timestamp": timestamp.isoformat(),
            "session_id": f"sess_{random.randint(1000, 9999)}",
            "model_id": model,
            "tool": tool,
            "status": status,
            "risk_level": audit_logger.calculate_risk_level({
                "model_id": model,
                "tool": tool,
                "status": status
            }),
            "reason": reason
        }
        
        events.append(event)
        audit_logger.log_event(event)
        
    return events

def require_api_key(view_function):
    """Decorator to require admin API key for sensitive endpoints."""
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        admin_key = os.environ.get("ADMIN_KEY", "admin-dev-key")
        header_key = request.headers.get("X-Admin-Key")
        
        # Also check query params for ease of testing
        if not header_key:
            header_key = request.args.get("api_key")
            
        if header_key != admin_key:
            return jsonify({"error": "Invalid or missing API key"}), 401
        
        return view_function(*args, **kwargs)
    
    return decorated_function

@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.datetime.now().isoformat()})

@app.route("/dashboard/key")
@require_api_key
def dashboard_key():
    """Simple dashboard to test authentication"""
    return jsonify({"message": "Authentication successful"})

@app.route("/")
def root():
    """Root endpoint with navigation menu"""
    return """<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MCP-Sec Gateway</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <style>
        .jumbotron {
            background-color: rgba(33, 37, 41, 0.7);
            padding: 2rem;
            border-radius: 0.5rem;
        }
        .card {
            transition: transform 0.2s;
            height: 100%;
        }
        .card:hover {
            transform: translateY(-5px);
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <header class="pb-3 mb-4 border-bottom">
            <h1 class="fs-4">MCP-Sec Gateway</h1>
        </header>

        <div class="p-5 mb-4 bg-body-tertiary rounded-3 jumbotron">
            <div class="container-fluid py-3">
                <h1 class="display-5 fw-bold">Zero Trust Security Layer</h1>
                <p class="col-md-8 fs-4">Validate, control, and monitor AI tool interactions with comprehensive security policies.</p>
                <div class="d-flex gap-2 mt-4">
                    <a href="/dash" class="btn btn-primary btn-lg px-4">Dashboard</a>
                    <a href="/test" class="btn btn-outline-secondary btn-lg px-4">Test Interface</a>
                </div>
            </div>
        </div>

        <div class="row mb-4 g-4">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Security Policies</h5>
                        <p class="card-text">Define and enforce which models can access which tools with fine-grained control.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Schema Validation</h5>
                        <p class="card-text">Ensure all AI tool interactions follow strict schema definitions for both inputs and outputs.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Audit Logging</h5>
                        <p class="card-text">Comprehensive logging of all AI activity with advanced filtering and risk assessment.</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Rate Limiting</h5>
                        <p class="card-text">Prevent abuse with configurable rate limits per model and session.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Session Tracking</h5>
                        <p class="card-text">Maintain context across interactions for advanced policy decisions.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Contextual Policies</h5>
                        <p class="card-text">Evaluate security based on full session history and context.</p>
                    </div>
                </div>
            </div>
        </div>

        <footer class="pt-3 mt-4 text-body-secondary border-top">
            &copy; 2025 MCP-Sec Gateway
        </footer>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

@app.route("/logs")
@require_api_key
def logs():
    """View audit logs in a simplified format"""
    with open("audit.log", "r") as f:
        logs = [json.loads(line) for line in f.readlines()]
    
    return jsonify(logs)

@app.route("/test")
def test():
    """Test interface for manual API request submission"""
    return """<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MCP-Sec Gateway - Test Interface</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <style>
        pre {
            background-color: #1c1c1c;
            border-radius: 4px;
            padding: 15px;
            color: #d0d0d0;
        }
        #response {
            display: none;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <header class="pb-3 mb-4 border-bottom d-flex justify-content-between align-items-center">
            <h1 class="fs-4">MCP-Sec Gateway - Test Interface</h1>
            <a href="/" class="btn btn-sm btn-outline-secondary">Home</a>
        </header>

        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">Initialize Session</h5>
                    </div>
                    <div class="card-body">
                        <form id="promptForm">
                            <div class="mb-3">
                                <label for="modelId" class="form-label">Model ID</label>
                                <input type="text" class="form-control" id="modelId" placeholder="e.g., gpt-4-0613" value="gpt-4-0613">
                            </div>
                            <div class="mb-3">
                                <label for="prompt" class="form-label">Initial Prompt</label>
                                <textarea class="form-control" id="prompt" rows="3" placeholder="User's initial prompt...">I need to schedule a meeting for tomorrow.</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Initialize</button>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Tool Call</h5>
                    </div>
                    <div class="card-body">
                        <form id="toolCallForm">
                            <div class="mb-3">
                                <label for="sessionId" class="form-label">Session ID</label>
                                <input type="text" class="form-control" id="sessionId" placeholder="Session ID from initialization">
                            </div>
                            <div class="mb-3">
                                <label for="toolName" class="form-label">Tool Name</label>
                                <input type="text" class="form-control" id="toolName" placeholder="e.g., calendar.create_event" value="calendar.create_event">
                            </div>
                            <div class="mb-3">
                                <label for="toolInput" class="form-label">Tool Input (JSON)</label>
                                <textarea class="form-control" id="toolInput" rows="5" placeholder="{}">{
    "title": "Planning Meeting",
    "start_time": "2025-05-08T10:00:00",
    "duration_minutes": 60,
    "attendees": ["john@example.com"]
}</textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Call Tool</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Response</h5>
                        <div>
                            <button id="clearBtn" class="btn btn-sm btn-outline-secondary">Clear</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="response">
                            <div class="mb-2">
                                <span class="badge bg-secondary" id="responseStatus">200</span>
                                <span class="ms-2" id="responseTime"></span>
                            </div>
                            <pre id="responseData">Response will appear here...</pre>
                        </div>
                        <div id="noResponse" class="text-center py-5 text-body-tertiary">
                            <div>No response yet</div>
                            <div class="mt-2">Submit a request to see results</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="alert alert-info">
                    <h5>Test Sequence</h5>
                    <ol>
                        <li>Initialize a session with a model ID and prompt</li>
                        <li>Copy the <code>session_id</code> from the response</li>
                        <li>Make tool calls using the session ID</li>
                    </ol>
                    <p>Try different models and tools to test policy enforcement.</p>
                </div>
            </div>
        </div>

        <footer class="pt-3 mt-4 text-body-secondary border-top">
            &copy; 2025 MCP-Sec Gateway
        </footer>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Prompt form submission
            document.getElementById('promptForm').addEventListener('submit', function(e) {
                e.preventDefault();
                
                const modelId = document.getElementById('modelId').value;
                const prompt = document.getElementById('prompt').value;
                
                fetch('/mcp/prompt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        model_id: modelId,
                        prompt: prompt
                    })
                })
                .then(response => {
                    showResponse(response);
                    return response.json();
                })
                .then(data => {
                    if (data.session_id) {
                        document.getElementById('sessionId').value = data.session_id;
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                });
            });
            
            // Tool call form submission
            document.getElementById('toolCallForm').addEventListener('submit', function(e) {
                e.preventDefault();
                
                const sessionId = document.getElementById('sessionId').value;
                const toolName = document.getElementById('toolName').value;
                
                let toolInput;
                try {
                    toolInput = JSON.parse(document.getElementById('toolInput').value);
                } catch (error) {
                    alert('Invalid JSON in tool input');
                    return;
                }
                
                fetch('/mcp/tool_call', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        session_id: sessionId,
                        tool: toolName,
                        input: toolInput
                    })
                })
                .then(response => {
                    showResponse(response);
                })
                .catch(error => {
                    console.error('Error:', error);
                });
            });
            
            // Clear response
            document.getElementById('clearBtn').addEventListener('click', function() {
                document.getElementById('response').style.display = 'none';
                document.getElementById('noResponse').style.display = 'block';
            });
            
            // Helper to show response
            async function showResponse(response) {
                const responseElement = document.getElementById('response');
                const noResponseElement = document.getElementById('noResponse');
                const statusElement = document.getElementById('responseStatus');
                const timeElement = document.getElementById('responseTime');
                const dataElement = document.getElementById('responseData');
                
                responseElement.style.display = 'block';
                noResponseElement.style.display = 'none';
                
                // Set status badge
                statusElement.textContent = response.status;
                statusElement.className = 'badge ' + (response.ok ? 'bg-success' : 'bg-danger');
                
                // Set time
                timeElement.textContent = new Date().toLocaleTimeString();
                
                // Set data
                try {
                    const data = await response.json();
                    dataElement.textContent = JSON.stringify(data, null, 2);
                } catch (e) {
                    dataElement.textContent = 'Error parsing response as JSON';
                }
            }
        });
    </script>
</body>
</html>"""

@app.route("/api/logs")
@require_api_key
def api_logs():
    """Return filtered logs."""
    # Read log file
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    # Apply filters
    since = request.args.get("since")
    model = request.args.get("model")
    tool = request.args.get("tool")
    status = request.args.get("status")
    limit = int(request.args.get("limit", 100))
    
    if since:
        try:
            since_dt = datetime.datetime.fromisoformat(since)
            logs = [log for log in logs if datetime.datetime.fromisoformat(log.get("timestamp", "2000-01-01T00:00:00")) >= since_dt]
        except ValueError:
            pass
        
    if model:
        logs = [log for log in logs if log.get("model_id", "") == model]
        
    if tool:
        logs = [log for log in logs if log.get("tool", "") == tool]
        
    if status:
        logs = [log for log in logs if log.get("status", "") == status]
    
    # Sort by timestamp descending and limit
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    logs = logs[:limit]
    
    return jsonify(logs)

@app.route("/api/metrics")
@require_api_key
def api_metrics():
    """Return simple counts & top lists."""
    # Read log file
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    # Basic metrics
    total = len(logs)
    allows = len([log for log in logs if log.get("status") == "allowed"])
    denies = len([log for log in logs if log.get("status") == "denied"])
    errors = len([log for log in logs if log.get("status") == "error"])
    
    # Top models and tools
    model_counts = {}
    tool_counts = {}
    
    for log in logs:
        model = log.get("model_id")
        if model:
            model_counts[model] = model_counts.get(model, 0) + 1
            
        tool = log.get("tool")
        if tool:
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
    
    # Sort by count descending
    top_models = sorted(model_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return jsonify({
        "total": total,
        "allows": allows,
        "denies": denies,
        "errors": errors,
        "top_models": dict(top_models),
        "top_tools": dict(top_tools)
    })

@app.route("/api/policy", methods=["GET"])
@require_api_key
def api_policy():
    """Return current policy"""
    try:
        with open("policies.yaml", "r") as f:
            policy_yaml = f.read()
            
        with open("contextual_policy.yaml", "r") as f:
            contextual_policy_yaml = f.read()
            
        return jsonify({
            "policy": yaml.safe_load(policy_yaml),
            "contextual_policy": yaml.safe_load(contextual_policy_yaml),
            "policy_yaml": policy_yaml,
            "contextual_policy_yaml": contextual_policy_yaml
        })
    except (FileNotFoundError, yaml.YAMLError) as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/policy/reload", methods=["POST"])
@require_api_key
def api_policy_reload():
    """Reload policy from disk"""
    try:
        policy_engine.reload_policies()
        return jsonify({"status": "reloaded"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/schema/reload", methods=["POST"])
@require_api_key
def api_schema_reload():
    """Reload schemas from disk"""
    try:
        schema_validator.reload_schemas()
        return jsonify({"status": "reloaded"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs/export")
@require_api_key
def api_logs_export():
    """Download CSV of recent logs."""
    # Apply same filters as for /api/logs
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    # Apply filters
    since = request.args.get("since")
    model = request.args.get("model")
    tool = request.args.get("tool")
    status = request.args.get("status")
    
    if since:
        try:
            since_dt = datetime.datetime.fromisoformat(since)
            logs = [log for log in logs if datetime.datetime.fromisoformat(log.get("timestamp", "2000-01-01T00:00:00")) >= since_dt]
        except ValueError:
            pass
        
    if model:
        logs = [log for log in logs if log.get("model_id", "") == model]
        
    if tool:
        logs = [log for log in logs if log.get("tool", "") == tool]
        
    if status:
        logs = [log for log in logs if log.get("status", "") == status]
    
    # Sort by timestamp descending
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Generate CSV
    headers = ["timestamp", "session_id", "model_id", "tool", "status", "risk_level", "reason"]
    csv_lines = [",".join(headers)]
    
    for log in logs:
        row = []
        for header in headers:
            value = log.get(header, "")
            # Escape commas and quotes in values
            if isinstance(value, str):
                value = value.replace('"', '""')
                if "," in value:
                    value = f'"{value}"'
            row.append(str(value))
        csv_lines.append(",".join(row))
    
    csv_data = "\n".join(csv_lines)
    
    # Return as attachment
    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=audit_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return response

@app.route("/api/config", methods=["GET"])
@require_api_key
def api_get_config():
    """Get current configuration"""
    policy_yaml = ""
    contextual_policy_yaml = ""
    
    try:
        with open("policies.yaml", "r") as f:
            policy_yaml = f.read()
            
        with open("contextual_policy.yaml", "r") as f:
            contextual_policy_yaml = f.read()
    except (FileNotFoundError, yaml.YAMLError):
        pass
    
    return jsonify({
        **config,
        "policy_yaml": policy_yaml,
        "contextual_policy_yaml": contextual_policy_yaml
    })

@app.route("/api/config", methods=["POST"])
@require_api_key
def api_save_config():
    """Save configuration"""
    data = request.json
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Update config values
    if "log_level" in data:
        config["log_level"] = data["log_level"]
        
    if "max_hist" in data:
        config["max_hist"] = int(data["max_hist"])
        
    if "auto_refresh_ms" in data:
        config["auto_refresh_ms"] = int(data["auto_refresh_ms"])
    
    # Save policies if provided
    if "policy_yaml" in data:
        try:
            # Validate YAML format
            yaml.safe_load(data["policy_yaml"])
            
            # Create backup before overwriting
            from shutil import copyfile
            import time
            backup_name = f"policies.{int(time.time())}.yaml"
            try:
                copyfile("policies.yaml", backup_name)
            except Exception as e:
                logging.error(f"Failed to create policy backup: {str(e)}")
            
            with open("policies.yaml", "w") as f:
                f.write(data["policy_yaml"])
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML: {str(e)}"}), 400
    
    if "contextual_policy_yaml" in data:
        try:
            # Validate YAML format
            yaml.safe_load(data["contextual_policy_yaml"])
            
            # Create backup before overwriting
            from shutil import copyfile
            import time
            backup_name = f"contextual_policy.{int(time.time())}.yaml"
            try:
                copyfile("contextual_policy.yaml", backup_name)
            except Exception as e:
                logging.error(f"Failed to create contextual policy backup: {str(e)}")
            
            with open("contextual_policy.yaml", "w") as f:
                f.write(data["contextual_policy_yaml"])
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML: {str(e)}"}), 400
            
    # Set environment variables for use by other modules
    for k in config:
        if k.upper() in os.environ:
            os.environ[k] = str(data[k.lower()])
            
    return {"status": "saved"}

@app.route("/api/session/<session_id>", methods=["GET"])
@require_api_key
def api_session(session_id):
    """Get details of a specific session"""
    import session_tracker
    context = session_tracker.get_context(session_id)
    if not context:
        return {"error": "Session not found"}, 404
    return context

@app.route("/dash")
def dash():
    """Simple working dashboard with minimal JavaScript"""
    api_key = request.args.get("api_key", "")
    
    # Get recent logs
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
            logs = logs[-20:]  # Get most recent 20 logs
            logs.reverse()  # Show newest first
    except:
        pass
    
    # Get metrics
    total_requests = len(logs)
    allowed = len([log for log in logs if log.get("status") == "allowed"])
    denied = len([log for log in logs if log.get("status") == "denied"])
    errors = len([log for log in logs if log.get("status") == "error"])
    
    # Format logs for display
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            "timestamp": log.get("timestamp", ""),
            "model_id": log.get("model_id", ""),
            "tool": log.get("tool", ""),
            "status": log.get("status", ""),
            "reason": log.get("reason", "")
        })
    
    # Simple render_template replacement
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Dashboard</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <style>
        .status-allowed {{ background-color: rgba(40, 167, 69, 0.2); }}
        .status-denied {{ background-color: rgba(220, 53, 69, 0.2); }}
        .status-error {{ background-color: rgba(255, 193, 7, 0.2); }}
        pre {{ background: #222; padding: 10px; border-radius: 4px; overflow: auto; }}
    </style>
</head>
<body>
    <div class="container-fluid p-4">
        <header class="pb-3 mb-4 border-bottom d-flex justify-content-between align-items-center">
            <h1 class="h3">MCP-Sec Gateway Dashboard</h1>
            <div>
                <a href="/" class="btn btn-sm btn-outline-secondary me-2">Home</a>
                <a href="/test" class="btn btn-sm btn-outline-secondary">Test Interface</a>
            </div>
        </header>

        <div class="row mb-4">
            <div class="col-md-3 col-6">
                <div class="card text-center bg-primary bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Total Requests</h6>
                        <h2 class="card-title">{total_requests}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-6">
                <div class="card text-center bg-success bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Allowed</h6>
                        <h2 class="card-title">{allowed}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-6">
                <div class="card text-center bg-danger bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Denied</h6>
                        <h2 class="card-title">{denied}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-6">
                <div class="card text-center bg-warning bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Errors</h6>
                        <h2 class="card-title">{errors}</h2>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Recent Audit Logs</h5>
                        <div>
                            <a href="/api/logs/export" class="btn btn-sm btn-outline-secondary">Export CSV</a>
                        </div>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Model</th>
                                        <th>Tool</th>
                                        <th>Status</th>
                                        <th>Reason</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {"".join([f'''
                                    <tr class="status-{log['status']}">
                                        <td>{log['timestamp']}</td>
                                        <td>{log['model_id']}</td>
                                        <td>{log['tool']}</td>
                                        <td>{log['status']}</td>
                                        <td>{log['reason'] or ''}</td>
                                    </tr>
                                    ''' for log in formatted_logs]) if formatted_logs else '<tr><td colspan="5" class="text-center py-3">No audit logs found</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Policy Management</h5>
                        <form method="POST" action="/api/policy/reload">
                            <button type="submit" class="btn btn-sm btn-success">Reload Policies</button>
                        </form>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <p class="mb-0">Policy configuration is available via the API:</p>
                            <ul class="mb-0">
                                <li>View policies: <code>/api/policy</code></li>
                                <li>Reload policies: <code>/api/policy/reload</code> (POST)</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Schema Management</h5>
                        <form method="POST" action="/api/schema/reload">
                            <button type="submit" class="btn btn-sm btn-success">Reload Schemas</button>
                        </form>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <p class="mb-0">Schema validation ensures all API requests meet required formats.</p>
                            <p class="mb-0 mt-2">Reload schemas after making changes to schema definitions.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""

# Register the MCP routes
app.register_blueprint(mcp_routes.mcp_bp)

# Generate some sample data on startup
if __name__ == "__main__":
    # Only generate sample data in development to avoid polluting production logs
    if not os.getenv("PRODUCTION"):
        generate_sample_data()
        
    app.run(debug=True, host="0.0.0.0")