"""
MCP-Sec Gateway - Zero Trust Security Layer for Model Context Protocol
Main entry point for the Flask application

- Phase 4 enhancement: Federation support for cross-gateway trust
- Phase 5 enhancement: Adaptive policy with session risk scoring & simulation
"""
import datetime
import glob
import json
import logging
import os
import random
import time
import uuid
from functools import wraps
from typing import Dict, List, Union, Optional, Any, Tuple

import yaml
from flask import Flask, request, jsonify, Response, render_template

import audit_logger
import mcp_routes
from mcp_routes import load_trusted_peers, call_tool_api
import policy_engine
from policy_engine import check_policy, check_policy_contextual, simulate_shadow_policy
import schema_validator
import session_tracker
from session_tracker import get_context, score_session
from rate_limiter import reset_limits

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Setup logger for this module
logger = logging.getLogger(__name__)

# Set environment variables for testing if not set
if not os.environ.get("BYPASS_MODEL_KEY_CHECK"):
    os.environ["BYPASS_MODEL_KEY_CHECK"] = "true"

if not os.environ.get("GATEWAY_ID"):
    os.environ["GATEWAY_ID"] = "mcp-gateway-dev"

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
        # Get the admin key from environment variable
        admin_key = os.environ.get("ADMIN_KEY")
        
        if not admin_key:
            logger.error("ADMIN_KEY environment variable not set. Using a secure fallback.")
            # Use a secure random value that changes on each restart
            # This is just a fallback and will be highly secure but inconvenient
            import secrets
            admin_key = secrets.token_hex(16)
            logger.info(f"Using temporary admin key: {admin_key}")
        
        # Check header first (more secure)
        header_key = request.headers.get("X-Admin-Key")
        
        # Also check query params for ease of testing
        if not header_key:
            header_key = request.args.get("api_key")
            
        if not header_key or header_key != admin_key:
            # Log failed attempt but don't expose too much detail
            logger.warning(f"API key authentication failed from {request.remote_addr}")
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
                    <a href="/monitor" class="btn btn-primary btn-lg px-4">Monitoring</a>
                    <a href="/admin" class="btn btn-danger btn-lg px-4">Admin Panel</a>
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

@app.route("/api/propose_policy", methods=["POST"])
@require_api_key
def api_propose_policy():
    """
    Allow models or admins to propose policy changes
    
    This endpoint:
    1. Validates the YAML format
    2. Checks if the requesting model is allowed to propose policies
    3. Logs the proposal
    4. Auto-approves safe proposals or marks them for review
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Validate required fields
        if "yaml" not in data:
            return jsonify({"error": "Missing required field: yaml"}), 400
        
        yaml_str = data["yaml"]
        model_id = data.get("model_id")
        justification = data.get("justification", "")
        
        # Parse the YAML to validate format
        try:
            new_policy = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            return jsonify({"status": "rejected", "reason": f"Invalid YAML: {str(e)}"}), 400
        
        # Check if model is allowed to propose policies
        if model_id and not policy_engine.is_model_permitted_to_propose(model_id):
            return jsonify({
                "status": "rejected", 
                "reason": "The specified model is not authorized to propose policy changes"
            }), 403
        
        # Sign the policy proposal
        signature = policy_engine.sign_policy(yaml_str)
        
        # Log the proposal
        audit_logger.log_event({
            "event_type": "policy_proposal",
            "model_id": model_id or "admin",
            "yaml": yaml_str,
            "justification": justification,
            "signature": signature,
            "status": "pending"
        })
        
        # Check if policy is safe for auto-approval
        is_safe = policy_engine.is_safe_policy(new_policy)
        
        if is_safe:
            # Auto-approve and merge the policy
            success = policy_engine.merge_policy_yaml("policies.yaml", new_policy)
            if success:
                # Reload policies
                policy_engine.reload_policies()
                
                # Log the approval
                audit_logger.log_event({
                    "event_type": "policy_approval",
                    "model_id": model_id or "admin",
                    "yaml": yaml_str,
                    "justification": justification,
                    "signature": signature,
                    "status": "auto_approved"
                })
                
                return jsonify({
                    "status": "approved",
                    "reason": "Policy change was automatically approved as it only contains safe changes"
                })
            else:
                return jsonify({
                    "status": "error",
                    "reason": "Failed to merge policy changes"
                }), 500
        else:
            # Mark for manual review
            return jsonify({
                "status": "pending",
                "reason": "Policy change requires manual review",
                "review_required": True
            })
    except Exception as e:
        logger.error(f"Error processing policy proposal: {str(e)}")
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
        
@app.route("/api/policy/history")
@require_api_key
def api_policy_history():
    """Get policy version history"""
    try:
        history = policy_engine.get_policy_history()
        return jsonify({"history": history})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/policy/rollback/<timestamp>", methods=["POST"])
@require_api_key
def api_policy_rollback(timestamp):
    """Rollback to a previous policy version"""
    try:
        ts = int(timestamp)
        success = policy_engine.rollback_policy(ts)
        if success:
            return jsonify({"status": "success", "message": f"Rolled back to policy from {datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')}"})
        else:
            return jsonify({"error": "Failed to rollback policy"}), 400
    except ValueError:
        return jsonify({"error": "Invalid timestamp"}), 400
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
    
    # Add risk score
    risk_score = session_tracker.score_session(session_id)
    context["risk_score"] = risk_score
    
    # Add session stats
    stats = session_tracker.get_session_stats(session_id)
    context["stats"] = stats
    
    return context

@app.route("/api/simulate", methods=["POST"])
@require_api_key
def api_simulate():
    """Simulate policy evaluation for a tool call"""
    data = request.json
    if not data:
        return {"error": "No data provided"}, 400
    
    # Required fields
    model_id = data.get("model_id")
    tool = data.get("tool")
    session_id = data.get("session_id", f"simulation-{int(time.time())}")
    input_data = data.get("input", {})
    
    if not model_id or not tool:
        return {"error": "Missing required fields: model_id, tool"}, 400
    
    try:
        # Create context simulation
        context = {
            "model_id": model_id,
            "session_id": session_id,
            "tool_calls": [
                {
                    "tool": tool,
                    "input": input_data,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
            ],
            "initial_prompt": data.get("prompt", "")
        }
        
        # Check basic policy
        basic_result = policy_engine.check_policy(model_id, tool, session_id)
        allowed_basic = basic_result[0]
        reason_basic = basic_result[1]
        
        # Check contextual policy
        contextual_result = policy_engine.check_policy_contextual(model_id, tool, session_id, context)
        allowed_contextual = contextual_result.get("allowed", False)
        reason_contextual = contextual_result.get("reason", "")
        
        # Validate model key if provided
        key_valid = True
        key_reason = ""
        if "model_key" in data:
            key_result = policy_engine.validate_model_key(model_id, data["model_key"], tool)
            key_valid = key_result[0]
            key_reason = key_result[1]
        
        # Return simulation results
        return {
            "simulation": True,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "model_id": model_id,
            "tool": tool,
            "session_id": session_id,
            "input": input_data,
            "basic_policy": {
                "allowed": allowed_basic,
                "reason": reason_basic
            },
            "contextual_policy": {
                "allowed": allowed_contextual,
                "reason": reason_contextual
            },
            "key_validation": {
                "checked": "model_key" in data,
                "valid": key_valid,
                "reason": key_reason
            },
            "final_result": {
                "allowed": allowed_basic and allowed_contextual and (not "model_key" in data or key_valid),
                "reason": reason_contextual or reason_basic or key_reason or "Allowed"
            }
        }
    except Exception as e:
        import traceback
        return {
            "error": str(e),
            "traceback": traceback.format_exc()
        }, 500

@app.route("/api/shadow_policy", methods=["GET"])
@require_api_key
def api_shadow_policy():
    """Get current shadow policy"""
    try:
        shadow_policy_path = "contextual_policy.preview.yaml"
        if os.path.exists(shadow_policy_path):
            with open(shadow_policy_path, "r") as f:
                shadow_policy_yaml = f.read()
                
            # Try to parse for validation
            shadow_policy = yaml.safe_load(shadow_policy_yaml)
            
            return {
                "shadow_policy_yaml": shadow_policy_yaml,
                "shadow_policy": shadow_policy
            }
        else:
            return {
                "shadow_policy_yaml": "",
                "shadow_policy": None,
                "message": "No shadow policy file found"
            }
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/api/shadow_policy", methods=["POST"])
@require_api_key
def api_save_shadow_policy():
    """Save shadow policy"""
    data = request.json
    if not data or "shadow_policy_yaml" not in data:
        return {"error": "No policy data provided"}, 400
    
    try:
        # Validate YAML format
        yaml.safe_load(data["shadow_policy_yaml"])
        
        # Create backup before overwriting
        shadow_policy_path = "contextual_policy.preview.yaml"
        if os.path.exists(shadow_policy_path):
            from shutil import copyfile
            import time
            backup_name = f"contextual_policy.preview.{int(time.time())}.yaml"
            try:
                copyfile(shadow_policy_path, backup_name)
            except Exception as e:
                logging.error(f"Failed to create shadow policy backup: {str(e)}")
        
        # Save the new shadow policy
        with open(shadow_policy_path, "w") as f:
            f.write(data["shadow_policy_yaml"])
        
        return {"status": "saved"}
    except yaml.YAMLError as e:
        return {"error": f"Invalid YAML: {str(e)}"}, 400
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/api/projects", methods=["GET"])
@require_api_key
def api_projects():
    """Get list of available projects"""
    try:
        # Get all YAML files in the policies directory
        projects = ["default"]  # Always include default
        
        # Look for project-specific policy files
        for path in glob.glob("policies/*.yaml"):
            try:
                # Extract project ID from filename
                filename = os.path.basename(path)
                project_id = os.path.splitext(filename)[0]
                
                if project_id != "default" and project_id not in projects:
                    projects.append(project_id)
            except:
                pass
        
        return {"projects": projects}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/monitor")
def monitor():
    """Public monitoring dashboard with basic metrics and recent logs"""
    # Get recent logs
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
            logs = logs[-20:]  # Get most recent 20 logs
            logs.reverse()  # Show newest first
    except:
        pass
        
@app.route("/admin")
@require_api_key
def admin():
    """Admin dashboard with full configuration options and detailed metrics"""
    api_key = request.args.get("api_key", "")
    
    # Get metrics
    total_requests = len(logs)
    allowed = len([log for log in logs if log.get("status") == "allowed"])
    denied = len([log for log in logs if log.get("status") == "denied"])
    errors = len([log for log in logs if log.get("status") == "error"])
    
    # Format logs for display
    formatted_logs = []
    for log in logs:
        formatted_log = {
            "timestamp": log.get("timestamp", ""),
            "model_id": log.get("model_id", ""),
            "tool": log.get("tool", ""),
            "status": log.get("status", ""),
            "reason": log.get("reason", ""),
            "risk_score": log.get("risk_score", 0.0),
            "latency_ms": log.get("latency_ms", 0)
        }
        
        # Add explainable decision details if available
        if "reasoning" in log:
            formatted_log["reasoning"] = log["reasoning"]
        if "rule_trace" in log:
            formatted_log["rule_trace"] = log["rule_trace"]
            
        formatted_logs.append(formatted_log)
    
    # Main HTML content
    html_parts = []
    
    # Start of HTML
    html_parts.append(f"""<!DOCTYPE html>
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
        </div>""")
    
    # Logs table
    logs_table = """
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
                                        <th>Reason & Explanations</th>
                                        <th>Response Time</th>
                                    </tr>
                                </thead>
                                <tbody>"""
    
    if formatted_logs:
        for log in formatted_logs:
            logs_table += f"""
                                    <tr class="status-{log['status']}">
                                        <td>{log['timestamp']}</td>
                                        <td>{log['model_id']}</td>
                                        <td>{log['tool']}</td>
                                        <td>{log['status']}</td>
                                        <td>
                                            <div>{log['reason'] or ''}</div>
                                            {f'<div class="mt-1 small text-muted"><strong>Reasoning:</strong> {"<br>".join(log["reasoning"]) if isinstance(log.get("reasoning"), list) else ""}</div>' if log.get('reasoning') else ''}
                                            {f'<div class="mt-1 small text-muted"><strong>Rules:</strong> {", ".join(log["rule_trace"]) if isinstance(log.get("rule_trace"), list) else ""}</div>' if log.get('rule_trace') else ''}
                                        </td>
                                        <td>{f"{log['latency_ms']}ms" if log.get('latency_ms') else '-'}</td>
                                    </tr>"""
    else:
        logs_table += """
                                    <tr><td colspan="6" class="text-center py-3">No audit logs found</td></tr>"""
        
    logs_table += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    html_parts.append(logs_table)
    
    # Tools catalog section
    tools_section = """
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Tools Catalog</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <div class="list-group" id="tool_list">
                                    <div class="d-flex justify-content-center">
                                        <div class="spinner-border text-primary" role="status">
                                            <span class="visually-hidden">Loading...</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-8">
                                <pre id="tool_detail" class="p-3 bg-dark text-light rounded" style="min-height: 200px;">Select a tool to view details</pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    html_parts.append(tools_section)
    
    # Policy management and schema validation
    html_parts.append("""
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Policy Management</h5>
                        <div>
                            <form method="POST" action="/api/policy/reload" class="d-inline">
                                <button type="submit" class="btn btn-sm btn-success">Reload Policies</button>
                            </form>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <p class="mb-0">Policy configuration is available via the API:</p>
                            <ul class="mb-0">
                                <li>View policies: <code>/api/policy</code></li>
                                <li>Reload policies: <code>/api/policy/reload</code> (POST)</li>
                                <li>View history: <code>/api/policy/history</code></li>
                                <li>Rollback: <code>/api/policy/rollback/{timestamp}</code> (POST)</li>
                                <li>Propose changes: <code>/api/propose_policy</code> (POST)</li>
                            </ul>
                        </div>
                        
                        <div class="mt-3">
                            <h6 class="border-bottom pb-2 mb-3">Policy Versioning</h6>
                            <div id="policyHistory">
                                <div class="text-center">
                                    <div class="spinner-border spinner-border-sm" role="status">
                                        <span class="visually-hidden">Loading...</span>
                                    </div>
                                    <span class="ms-2">Loading policy history...</span>
                                </div>
                            </div>
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
        
        <div class="row">
            <div class="col-md-12 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Shadow Policy Management</h5>
                        <div class="d-flex gap-2">
                            <button id="loadShadowPolicy" class="btn btn-sm btn-secondary">Load Current</button>
                            <button id="saveShadowPolicy" class="btn btn-sm btn-success">Save Changes</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <p class="mb-0"><strong>Shadow Mode Policies</strong> allow you to test new policy rules without enforcing them. These policies are evaluated but not enforced, letting you collect metrics and analyze the potential impact before activating them.</p>
                        </div>
                        <div class="form-group">
                            <label for="shadowPolicyEditor" class="form-label">Shadow Policy Configuration (YAML):</label>
                            <textarea id="shadowPolicyEditor" class="form-control font-monospace" rows="12" style="font-size: 0.875rem;"></textarea>
                        </div>
                        <div id="shadowPolicyStatus" class="mt-2"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Session Inspector</h5>
                    </div>
                    <div class="card-body">
                        <form id="sessionForm" class="row g-3">
                            <div class="col-md-8">
                                <input type="text" class="form-control" id="sessionId" placeholder="Enter Session ID">
                            </div>
                            <div class="col-md-4">
                                <button type="submit" class="btn btn-primary w-100">View Session</button>
                            </div>
                        </form>
                        <div id="sessionDetails" class="mt-3" style="display:none;">
                            <h6 class="border-bottom pb-2 mb-3">Session Details</h6>
                            <pre id="sessionJson" class="bg-dark p-3 rounded" style="max-height: 300px; overflow-y: auto;"></pre>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Multi-Project Management</h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <p class="mb-0">MCP-Sec now supports multiple projects with per-project policies.</p>
                            <p class="mb-0 mt-2">Create project-specific policies in <code>policies/{project_id}.yaml</code>.</p>
                        </div>
                        
                        <form id="projectSwitcher" class="row g-3">
                            <div class="col-md-8">
                                <select class="form-select" id="projectId">
                                    <option value="default">default</option>
                                    <!-- Projects will be loaded dynamically -->
                                </select>
                            </div>
                            <div class="col-md-4">
                                <button type="submit" class="btn btn-primary w-100">Switch Project</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-12 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Policy Proposal Management</h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <p class="mb-0"><strong>Explainable Policy Negotiation</strong> allows trusted models to propose policy changes that can be automatically approved if they meet safety criteria or reviewed by administrators.</p>
                        </div>
                        
                        <div class="form-group mb-3">
                            <label for="policyProposalEditor" class="form-label">Create/Edit Policy Proposal (YAML):</label>
                            <textarea id="policyProposalEditor" class="form-control font-monospace" rows="8" style="font-size: 0.875rem;" placeholder="# Enter YAML policy proposal here"></textarea>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="modelId" class="form-label">Model ID (for testing)</label>
                                    <input type="text" id="modelId" class="form-control" placeholder="e.g., claude-3-opus">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="modelApiKey" class="form-label">API Key (for testing)</label>
                                    <input type="text" id="modelApiKey" class="form-control" placeholder="Model API key">
                                </div>
                            </div>
                        </div>
                        
                        <div class="d-flex gap-2">
                            <button id="submitProposal" class="btn btn-primary">Submit Proposal</button>
                            <button id="checkProposalSafety" class="btn btn-secondary">Check Safety</button>
                        </div>
                        
                        <div id="proposalStatus" class="mt-3"></div>
                        
                        <div class="mt-4">
                            <h6 class="border-bottom pb-2 mb-3">Recent Policy Proposals</h6>
                            <div id="policyProposals">
                                <div class="text-center">
                                    <p class="text-muted">No recent policy proposals found</p>
                                    <p class="small text-muted">Policy proposals from trusted models will appear here</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-12 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Policy Simulation</h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <p class="mb-0">Test how a policy would handle a specific session without actually processing any tool calls.</p>
                        </div>
                        
                        <form id="simulationForm" class="row g-3">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="simulationModel">Model ID</label>
                                    <input type="text" class="form-control" id="simulationModel" placeholder="e.g., claude-3-haiku">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="simulationTool">Tool Name</label>
                                    <input type="text" class="form-control" id="simulationTool" placeholder="e.g., search.query">
                                </div>
                            </div>
                            <div class="col-12">
                                <div class="form-group">
                                    <label for="simulationPayload">Input Payload (JSON)</label>
                                    <textarea class="form-control" id="simulationPayload" rows="3" placeholder='{"query": "example search"}'></textarea>
                                </div>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn btn-primary">Run Simulation</button>
                            </div>
                        </form>
                        
                        <div id="simulationResults" class="mt-3" style="display:none;">
                            <h6 class="border-bottom pb-2 mb-3">Simulation Results</h6>
                            <pre id="simulationJson" class="bg-dark p-3 rounded" style="max-height: 300px; overflow-y: auto;"></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>""")
    
    # JavaScript
    html_parts.append("""
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Shadow policy handlers
        document.getElementById('loadShadowPolicy').addEventListener('click', loadShadowPolicy);
        document.getElementById('saveShadowPolicy').addEventListener('click', saveShadowPolicy);
        
        // Policy proposal handlers
        document.getElementById('submitProposal').addEventListener('click', submitPolicyProposal);
        document.getElementById('checkProposalSafety').addEventListener('click', checkPolicyProposalSafety);
        
        // Initial shadow policy load
        loadShadowPolicy();
        
        // Load policy history
        loadPolicyHistory();
        
        // Load project list
        loadProjects();
        
        // Load tools catalog
        loadToolsCatalog();
        
        // Session inspector form handler
        document.getElementById('sessionForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const sessionId = document.getElementById('sessionId').value.trim();
            if (!sessionId) return;
            
            fetch('/api/session/' + sessionId)
                .then(response => response.json())
                .then(data => {
                    const sessionDetails = document.getElementById('sessionDetails');
                    const sessionJson = document.getElementById('sessionJson');
                    sessionJson.textContent = JSON.stringify(data, null, 2);
                    sessionDetails.style.display = 'block';
                })
                .catch(error => {
                    alert('Error loading session: ' + error);
                });
        });
        
        // Policy simulation form handler
        document.getElementById('simulationForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const modelId = document.getElementById('simulationModel').value.trim();
            const toolName = document.getElementById('simulationTool').value.trim();
            const payloadText = document.getElementById('simulationPayload').value.trim();
            
            if (!modelId || !toolName) {
                alert('Please enter both Model ID and Tool Name');
                return;
            }
            
            let payload = {};
            if (payloadText) {
                try {
                    payload = JSON.parse(payloadText);
                } catch (error) {
                    alert('Invalid JSON payload: ' + error.message);
                    return;
                }
            }
            
            // Prepare simulation data
            const simulationData = {
                model_id: modelId,
                tool: toolName,
                input: payload,
                session_id: 'simulation-' + Date.now()
            };
            
            // Call simulation API
            fetch('/api/simulate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(simulationData)
            })
            .then(response => response.json())
            .then(data => {
                const resultsDiv = document.getElementById('simulationResults');
                const jsonPre = document.getElementById('simulationJson');
                jsonPre.textContent = JSON.stringify(data, null, 2);
                resultsDiv.style.display = 'block';
            })
            .catch(error => {
                alert('Simulation error: ' + error.message);
            });
        });
        
        // Project switcher form handler
        document.getElementById('projectSwitcher').addEventListener('submit', function(e) {
            e.preventDefault();
            const projectId = document.getElementById('projectId').value;
            if (!projectId) return;
            
            // Redirect to same page with project parameter
            window.location.href = window.location.pathname + '?project=' + encodeURIComponent(projectId);
        });
    });
    
    // Function to load policy history
    function loadPolicyHistory() {
        const historyDiv = document.getElementById('policyHistory');
        
        fetch('/api/policy/history')
            .then(response => response.json())
            .then(data => {
                if (!data.history || data.history.length === 0) {
                    historyDiv.innerHTML = '<div class="alert alert-info">No policy history found.</div>';
                    return;
                }
                
                // Create history table
                let tableHtml = `
                <div class="table-responsive">
                    <table class="table table-sm table-hover">
                        <thead>
                            <tr>
                                <th>Date/Time</th>
                                <th>Policy File</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>`;
                
                // Add rows for each history item
                data.history.forEach(item => {
                    tableHtml += `
                    <tr>
                        <td>${item.datetime}</td>
                        <td>${item.filename}</td>
                        <td>
                            <button class="btn btn-sm btn-outline-warning rollback-btn" 
                                    data-timestamp="${item.timestamp}"
                                    onclick="rollbackPolicy(${item.timestamp})">
                                Rollback
                            </button>
                        </td>
                    </tr>`;
                });
                
                tableHtml += `
                        </tbody>
                    </table>
                </div>`;
                
                historyDiv.innerHTML = tableHtml;
            })
            .catch(error => {
                historyDiv.innerHTML = `<div class="alert alert-danger">Error loading policy history: ${error.message}</div>`;
            });
    }
    
    // Function to load projects
    function loadProjects() {
        const selectElement = document.getElementById('projectId');
        
        fetch('/api/projects')
            .catch(() => {
                // If API not implemented yet, we'll just use default
                console.log('Project API not implemented yet');
                return { projects: ['default'] };
            })
            .then(response => {
                if (response.projects) return response;
                return response.json();
            })
            .then(data => {
                // Clear options except default
                while (selectElement.options.length > 1) {
                    selectElement.remove(1);
                }
                
                // Add options for each project
                if (data.projects) {
                    data.projects.forEach(project => {
                        if (project === 'default') return; // Skip default which is already there
                        
                        const option = document.createElement('option');
                        option.value = project;
                        option.text = project;
                        selectElement.add(option);
                    });
                }
                
                // Set current project based on URL
                const urlParams = new URLSearchParams(window.location.search);
                const currentProject = urlParams.get('project');
                if (currentProject) {
                    selectElement.value = currentProject;
                }
            });
    }
    
    // Function to rollback to a policy version
    function rollbackPolicy(timestamp) {
        if (!confirm('Are you sure you want to rollback to this policy version? This will overwrite the current policy file.')) {
            return;
        }
        
        fetch('/api/policy/rollback/' + timestamp, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Policy rolled back successfully: ' + data.message);
                // Reload the page to reflect the changes
                window.location.reload();
            } else {
                alert('Error rolling back policy: ' + (data.error || data.message || 'Unknown error'));
            }
        })
        .catch(error => {
            alert('Error rolling back policy: ' + error.message);
        });
    }
    
    // Function to load shadow policy
    function loadShadowPolicy() {
        const editor = document.getElementById('shadowPolicyEditor');
        const statusDiv = document.getElementById('shadowPolicyStatus');
        
        statusDiv.innerHTML = '<div class="alert alert-info">Loading shadow policy...</div>';
        
        fetch('/api/shadow_policy')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    statusDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                    return;
                }
                
                // Show the policy in the editor
                editor.value = data.shadow_policy_yaml || '';
                
                if (data.message) {
                    statusDiv.innerHTML = `<div class="alert alert-info">${data.message}</div>`;
                } else {
                    statusDiv.innerHTML = `<div class="alert alert-success">Shadow policy loaded successfully!</div>`;
                    
                    // Auto-hide the status after 3 seconds
                    setTimeout(() => {
                        statusDiv.innerHTML = '';
                    }, 3000);
                }
            })
            .catch(error => {
                statusDiv.innerHTML = `<div class="alert alert-danger">Error loading shadow policy: ${error.message}</div>`;
            });
    }
    
    // Function to save shadow policy
    function saveShadowPolicy() {
        const editor = document.getElementById('shadowPolicyEditor');
        const statusDiv = document.getElementById('shadowPolicyStatus');
        const policyYaml = editor.value.trim();
        
        if (!policyYaml) {
            statusDiv.innerHTML = '<div class="alert alert-warning">Cannot save empty policy</div>';
            return;
        }
        
        statusDiv.innerHTML = '<div class="alert alert-info">Saving shadow policy...</div>';
        
        fetch('/api/shadow_policy', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                shadow_policy_yaml: policyYaml
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    statusDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                    return;
                }
                
                statusDiv.innerHTML = '<div class="alert alert-success">Shadow policy saved successfully! It will be used for shadow simulation but will not affect actual policy decisions.</div>';
                
                // Don't auto-hide the success message - it's important
            })
            .catch(error => {
                statusDiv.innerHTML = `<div class="alert alert-danger">Error saving shadow policy: ${error.message}</div>`;
            });
    }
    
    // Function to load tools catalog
    function loadToolsCatalog() {
        const toolList = document.getElementById('tool_list');
        const toolDetail = document.getElementById('tool_detail');
        
        fetch('/tools')
            .then(response => response.json())
            .then(data => {
                // Clear loading spinner
                toolList.innerHTML = '';
                
                if (!data.tools || data.tools.length === 0) {
                    toolList.innerHTML = '<div class="alert alert-info">No tools found in catalog</div>';
                    return;
                }
                
                // Sort tools by name
                data.tools.sort();
                
                // Create list items for each tool
                data.tools.forEach(toolName => {
                    const listItem = document.createElement('a');
                    listItem.href = '#';
                    listItem.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
                    listItem.textContent = toolName;
                    
                    // Add risk badge based on tool name pattern matching
                    // This will be replaced with actual risk data from tool metadata once available
                    let riskBadge = '';
                    if (toolName.includes('file') || toolName.includes('exec') || toolName.includes('admin')) {
                        riskBadge = '<span class="badge bg-danger">High Risk</span>';
                    } else if (toolName.includes('write') || toolName.includes('delete') || toolName.includes('update')) {
                        riskBadge = '<span class="badge bg-warning text-dark">Medium Risk</span>';
                    } else {
                        riskBadge = '<span class="badge bg-success">Low Risk</span>';
                    }
                    
                    // Add the risk badge to the list item
                    listItem.innerHTML += riskBadge;
                    
                    // Add click event to load tool details
                    listItem.addEventListener('click', function(e) {
                        e.preventDefault();
                        
                        // Highlight the selected tool
                        document.querySelectorAll('#tool_list a').forEach(item => {
                            item.classList.remove('active');
                        });
                        this.classList.add('active');
                        
                        // Load and display tool details
                        loadToolDetails(toolName);
                    });
                    
                    toolList.appendChild(listItem);
                });
            })
            .catch(error => {
                toolList.innerHTML = `<div class="alert alert-danger">Error loading tools: ${error.message}</div>`;
            });
    }
    
    // Function to load details for a specific tool
    function loadToolDetails(toolName) {
        const toolDetail = document.getElementById('tool_detail');
        
        // Show loading indicator
        toolDetail.textContent = 'Loading tool details...';
        
        fetch('/tools/' + toolName)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    toolDetail.textContent = 'Error: ' + data.error;
                    return;
                }
                
                // Format and display the tool details
                toolDetail.textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                toolDetail.textContent = 'Error loading tool details: ' + error.message;
            });
    }
    
    // Function to submit a policy proposal
    function submitPolicyProposal() {
        const editor = document.getElementById('policyProposalEditor');
        const policyYaml = editor.value.trim();
        const modelId = document.getElementById('modelId').value.trim();
        const modelApiKey = document.getElementById('modelApiKey').value.trim();
        const statusDiv = document.getElementById('proposalStatus');
        
        if (!policyYaml) {
            statusDiv.innerHTML = '<div class="alert alert-warning">Cannot submit empty policy proposal</div>';
            return;
        }
        
        if (!modelId) {
            statusDiv.innerHTML = '<div class="alert alert-warning">Please enter a model ID for the proposal</div>';
            return;
        }
        
        statusDiv.innerHTML = '<div class="alert alert-info">Submitting policy proposal...</div>';
        
        // Headers with optional API key
        const headers = {
            'Content-Type': 'application/json'
        };
        if (modelApiKey) {
            headers['X-API-Key'] = modelApiKey;
        }
        
        fetch('/api/propose_policy', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                model_id: modelId,
                policy_yaml: policyYaml
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                statusDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            if (data.auto_approved) {
                statusDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h5>Policy Proposal Auto-Approved!</h5>
                        <p>${data.message || 'The proposal was automatically approved as it meets all safety criteria.'}</p>
                        <p>The changes have been applied to the active policy.</p>
                    </div>`;
            } else {
                statusDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <h5>Policy Proposal Needs Review</h5>
                        <p>${data.message || 'The proposal requires administrator review before application.'}</p>
                        <p>Reason: ${data.review_reason || 'Policy changes may impact security or contain sensitive modifications.'}</p>
                    </div>`;
            }
        })
        .catch(error => {
            statusDiv.innerHTML = `<div class="alert alert-danger">Error submitting policy proposal: ${error.message}</div>`;
        });
    }
    
    // Function to check if a policy proposal is safe
    function checkPolicyProposalSafety() {
        const editor = document.getElementById('policyProposalEditor');
        const policyYaml = editor.value.trim();
        const statusDiv = document.getElementById('proposalStatus');
        
        if (!policyYaml) {
            statusDiv.innerHTML = '<div class="alert alert-warning">Cannot check empty policy proposal</div>';
            return;
        }
        
        statusDiv.innerHTML = '<div class="alert alert-info">Checking policy safety...</div>';
        
        fetch('/api/check_policy_safety', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                policy_yaml: policyYaml
            })
        })
        .then(response => {
            // Check if endpoint exists
            if (response.status === 404) {
                throw new Error('Policy safety check endpoint not available');
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                statusDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            if (data.is_safe) {
                statusDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h5>Policy Changes Are Safe</h5>
                        <p>The proposed policy meets all safety criteria for automatic approval.</p>
                    </div>`;
            } else {
                statusDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <h5>Policy Changes Need Review</h5>
                        <p>The proposed policy contains changes that require administrator review:</p>
                        <ul>
                            ${data.reasons.map(reason => `<li>${reason}</li>`).join('')}
                        </ul>
                    </div>`;
            }
        })
        .catch(error => {
            // Special case for missing endpoint
            if (error.message === 'Policy safety check endpoint not available') {
                statusDiv.innerHTML = `
                    <div class="alert alert-info">
                        <p>Safety check endpoint not implemented yet.</p>
                        <p>Submit your proposal to check if it will be auto-approved.</p>
                    </div>`;
            } else {
                statusDiv.innerHTML = `<div class="alert alert-danger">Error checking policy safety: ${error.message}</div>`;
            }
        });
    }
    </script>
</body>
</html>""")
    
    # Join all parts
    return "".join(html_parts)

@app.route("/federation/forward", methods=["POST"])
def federation_forward():
    """
    Handle requests forwarded from trusted peer gateways
    
    This endpoint:
    1. Validates the incoming request is from a trusted peer
    2. Verifies the tool call against local policies
    3. Executes the tool call if allowed
    4. Returns the result back to the peer gateway
    """
    start_time = time.time()
    
    # Validate it's coming from a trusted peer via gateway key
    gateway_key = request.headers.get("X-Gateway-Key")
    if not gateway_key:
        logger.warning("Federation forward request missing gateway key")
        return jsonify({
            "allowed": False,
            "status": "error",
            "reason": "Missing gateway key"
        }), 401
    
    # Load trusted peers
    peers = load_trusted_peers()
    trusted_peer = None
    for peer_id, peer_config in peers.items():
        if gateway_key == peer_config.get("key"):
            trusted_peer = peer_id
            break
    
    if not trusted_peer:
        logger.warning(f"Untrusted peer attempted federation request")
        return jsonify({
            "allowed": False,
            "status": "error",
            "reason": "Invalid gateway key"
        }), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "allowed": False,
                "status": "error",
                "reason": "Invalid JSON body"
            }), 400
            
        # Validate required fields
        for field in ["model_id", "session_id", "tool_name", "input"]:
            if field not in data:
                return jsonify({
                    "allowed": False,
                    "status": "error",
                    "reason": f"Missing required field: {field}"
                }), 400
        
        model_id = data["model_id"]
        session_id = data["session_id"] 
        tool_name = data["tool_name"]
        input_data = data["input"]
        trace_id = data.get("trace_id", str(uuid.uuid4()))
        
        # Include federation info in the session ID to avoid collisions
        # with local sessions and for tracking purposes
        federation_session_id = f"fed_{trusted_peer}_{session_id}"
        
        # Get or initialize session context
        context = get_context(federation_session_id)
        if not context:
            # Initialize session with federation marker
            session_tracker.init_session(federation_session_id, model_id, 
                                        prompt=f"[FEDERATION] Request from peer: {trusted_peer}")
            context = get_context(federation_session_id)
        
        # Check policies - local policies always take precedence
        allowed, reason = check_policy(model_id, tool_name, federation_session_id)
        if not allowed:
            logger.info(f"Federation request denied by basic policy: {reason}")
            return jsonify({
                "allowed": False,
                "status": "denied",
                "reason": f"Remote policy denial: {reason}",
                "origin": "federation_policy"
            })
        
        # Contextual policy check
        contextual_decision = check_policy_contextual(model_id, tool_name, federation_session_id, context)
        if not contextual_decision.get("allowed", True):
            reason = contextual_decision.get("reason", "Denied by contextual policy")
            logger.info(f"Federation request denied by contextual policy: {reason}")
            return jsonify({
                "allowed": False,
                "status": "denied",
                "reason": f"Remote contextual policy denial: {reason}",
                "origin": "federation_contextual_policy"
            })
        
        # Calculate risk score for this session
        risk_score = score_session(federation_session_id)
        
        # Run shadow policy simulation
        shadow_results = simulate_shadow_policy(model_id, tool_name, federation_session_id, context)
        
        # Execute the tool call
        try:
            tool_result = call_tool_api(tool_name, input_data)
            
            # Update session
            session_tracker.update_tool_call(federation_session_id, tool_name, input_data, 
                                           "allowed", output=tool_result)
            
            # Log the allowed federation request
            audit_logger.log_event({
                "model_id": model_id,
                "session_id": federation_session_id,
                "trace_id": trace_id,
                "tool": tool_name,
                "input": input_data,
                "status": "allowed",
                "federation": {
                    "peer": trusted_peer,
                    "original_session": session_id
                },
                "tool_result": tool_result,
                "risk_score": risk_score,
                "shadow_results": shadow_results,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            
            return jsonify({
                "allowed": True,
                "status": "allowed",
                "result": tool_result,
                "risk_score": risk_score,
                "shadow_results": shadow_results,
                "federation": {
                    "source": "remote_execution",
                    "gateway_id": os.environ.get("GATEWAY_ID", "mcp-gateway")
                },
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            
        except Exception as e:
            reason = f"Tool error: {str(e)}"
            logger.error(f"Federation tool execution error: {reason}")
            
            # Update session
            session_tracker.update_tool_call(federation_session_id, tool_name, input_data, 
                                           "error", reason=reason)
            
            # Log the federation error
            audit_logger.log_event({
                "model_id": model_id,
                "session_id": federation_session_id,
                "trace_id": trace_id,
                "tool": tool_name,
                "input": input_data,
                "status": "error",
                "federation": {
                    "peer": trusted_peer,
                    "original_session": session_id
                },
                "reason": reason,
                "risk_score": risk_score,
                "shadow_results": shadow_results,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            
            return jsonify({
                "allowed": False,
                "status": "error",
                "reason": f"Remote tool error: {reason}",
                "risk_score": risk_score,
                "federation": {
                    "source": "remote_execution",
                    "gateway_id": os.environ.get("GATEWAY_ID", "mcp-gateway")
                },
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            
    except Exception as e:
        logger.error(f"Error processing federation request: {str(e)}")
        return jsonify({
            "allowed": False,
            "status": "error",
            "reason": f"Remote gateway error: {str(e)}"
        }), 500

# Tools catalog API endpoints
# Tools catalog API endpoints
@app.route("/tools")
def list_tools():
    """List all available tools in the catalog"""
    try:
        # Try to use the tools catalog first
        from tools_catalog.catalog import get_all_tools
        tools = get_all_tools()
        return jsonify({"tools": tools})
    except ImportError:
        # Fall back to directory listing if tools catalog is not available
        from pathlib import Path
        tools = [p.stem for p in Path("tools").glob("*.json")]
        return jsonify({"tools": tools})

@app.route("/tools/<name>")
def get_tool_schema(name):
    """Get the schema for a specific tool"""
    try:
        # Try to use the tools catalog for metadata and schema
        from tools_catalog.catalog import get_tool_metadata, get_tool_schema as get_catalog_schema
        
        # Get both input and output schemas
        input_schema = get_catalog_schema(name, "input")
        output_schema = get_catalog_schema(name, "output")
        
        # Get metadata
        metadata = get_tool_metadata(name)
        
        # Combine everything into a single response
        response = {
            "name": name,
            "input_schema": input_schema or {},
            "output_schema": output_schema or {},
            "metadata": metadata or {}
        }
        
        return jsonify(response)
    except (ImportError, ValueError):
        # Fall back to just returning the JSON schema file
        try:
            import json
            from pathlib import Path
            
            # Check if the file exists
            schema_path = Path(f"tools/{name}.json")
            if not schema_path.exists():
                return jsonify({"error": f"Tool schema for '{name}' not found"}), 404
                
            # Read the file to extract any metadata
            schema_data = json.loads(schema_path.read_text())
            
            # Make a best effort to categorize the tool by name pattern
            risk_level = "low"
            if any(pattern in name for pattern in ["file", "exec", "admin", "delete", "rm"]):
                risk_level = "high"
            elif any(pattern in name for pattern in ["write", "update", "modify", "create"]):
                risk_level = "medium"
            
            # Create a response with the schema and basic metadata
            response = {
                "name": name,
                "input_schema": schema_data,
                "metadata": {
                    "description": schema_data.get("description", f"Schema for {name}"),
                    "risk_level": risk_level,
                    "category": "unknown",
                    "version": "1.0"
                }
            }
            
            return jsonify(response)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
# Register the MCP routes
app.register_blueprint(mcp_routes.mcp_bp)

# Generate some sample data on startup
if __name__ == "__main__":
    # Only generate sample data in development to avoid polluting production logs
    if not os.getenv("PRODUCTION"):
        generate_sample_data()
        
    app.run(debug=True, host="0.0.0.0")