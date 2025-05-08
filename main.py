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
from flask import Flask, request, jsonify, Response, render_template, render_template_string, Blueprint

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

# Import blueprints
try:
    from admin_dashboard import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')
    logger.info("Loaded admin dashboard blueprint")
except ImportError:
    logger.warning("Admin dashboard module not available")

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
        # For development purposes, allow bypassing authentication with query param
        if os.environ.get("BYPASS_AUTH", "").lower() == "true" or request.args.get("bypass_auth") == "true":
            return view_function(*args, **kwargs)
            
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
            
            # Return an HTML page for browser requests, JSON for API requests
            if request.headers.get('Accept', '').find('application/json') >= 0:
                return jsonify({"error": "Invalid or missing API key"}), 401
            else:
                return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Authentication Required</title>
                    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
                </head>
                <body>
                    <div class="container mt-5">
                        <div class="row justify-content-center">
                            <div class="col-md-6">
                                <div class="card">
                                    <div class="card-header bg-danger text-white">
                                        <h4 class="mb-0">Authentication Required</h4>
                                    </div>
                                    <div class="card-body">
                                        <p>You need an API key to access this administrative area.</p>
                                        <form method="get" action="/admin">
                                            <div class="mb-3">
                                                <label for="api_key" class="form-label">Admin API Key:</label>
                                                <input type="password" class="form-control" id="api_key" name="api_key" required>
                                            </div>
                                            <button type="submit" class="btn btn-primary">Submit</button>
                                            <a href="/monitor" class="btn btn-secondary ms-2">Go to Monitoring</a>
                                        </form>
                                        <div class="mt-3">
                                            <p class="small text-muted">For development, you can also append <code>?bypass_auth=true</code> to the URL</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """), 401
        
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
                                <label for="toolInput" class="form-label">Tool Input</label>
                                <textarea class="form-control" id="toolInput" rows="5" placeholder="JSON input for the tool..." value="{}"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary">Submit Tool Call</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Response</h5>
                        <div>
                            <button id="clearBtn" class="btn btn-sm btn-outline-secondary">Clear</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="responseArea">
                            <div class="alert alert-secondary">
                                <p class="mb-0">Test the MCP-Sec Gateway by initializing a session and making tool calls.</p>
                                <p class="mb-0 mt-2">The response will appear here.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const promptForm = document.getElementById('promptForm');
            const toolCallForm = document.getElementById('toolCallForm');
            const responseArea = document.getElementById('responseArea');
            const clearBtn = document.getElementById('clearBtn');
            const sessionIdInput = document.getElementById('sessionId');
            
            // Initialize session form handler
            promptForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const modelId = document.getElementById('modelId').value;
                const prompt = document.getElementById('prompt').value;
                
                // Show loading state
                responseArea.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-2">Initializing session...</p></div>';
                
                // Make API call
                fetch('/mcp/prompt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        model_id: modelId,
                        prompt: prompt
                    })
                })
                .then(response => response.json())
                .then(data => {
                    // Display the formatted response
                    responseArea.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    
                    // If session ID is returned, fill it in the session ID field
                    if (data.session_id) {
                        sessionIdInput.value = data.session_id;
                    }
                })
                .catch(error => {
                    responseArea.innerHTML = '<div class="alert alert-danger">Error: ' + error.message + '</div>';
                });
            });
            
            // Tool call form handler
            toolCallForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const sessionId = sessionIdInput.value;
                const toolName = document.getElementById('toolName').value;
                const toolInputText = document.getElementById('toolInput').value;
                
                let toolInput;
                try {
                    toolInput = JSON.parse(toolInputText || '{}');
                } catch (e) {
                    responseArea.innerHTML = '<div class="alert alert-danger">Invalid JSON in tool input</div>';
                    return;
                }
                
                // Show loading state
                responseArea.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-2">Submitting tool call...</p></div>';
                
                // Make API call
                fetch('/mcp/tool', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        session_id: sessionId,
                        model_id: document.getElementById('modelId').value, // use the same model ID from initialization
                        tool: toolName,
                        input: toolInput
                    })
                })
                .then(response => response.json())
                .then(data => {
                    // Display the formatted response
                    responseArea.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                })
                .catch(error => {
                    responseArea.innerHTML = '<div class="alert alert-danger">Error: ' + error.message + '</div>';
                });
            });
            
            // Clear button handler
            clearBtn.addEventListener('click', function() {
                responseArea.innerHTML = '<div class="alert alert-secondary"><p class="mb-0">Test the MCP-Sec Gateway by initializing a session and making tool calls.</p><p class="mb-0 mt-2">The response will appear here.</p></div>';
            });
            
            // Auto-fill tool input with a valid JSON example
            const toolNameInput = document.getElementById('toolName');
            const toolInputField = document.getElementById('toolInput');
            
            toolNameInput.addEventListener('change', function() {
                // Provide examples for common tools
                const toolName = this.value;
                
                if (toolName === 'calendar.create_event') {
                    toolInputField.value = JSON.stringify({
                        title: "Team Meeting",
                        start_time: "2025-05-09T10:00:00",
                        duration_minutes: 60,
                        attendees: ["john@example.com", "sara@example.com"]
                    }, null, 2);
                } else if (toolName === 'search.web') {
                    toolInputField.value = JSON.stringify({
                        query: "Latest AI research papers 2025",
                        num_results: 5
                    }, null, 2);
                } else if (toolName === 'email.send') {
                    toolInputField.value = JSON.stringify({
                        to: "recipient@example.com",
                        subject: "Meeting Summary",
                        body: "Here are the key points from our meeting today..."
                    }, null, 2);
                } else if (toolName === 'file.read') {
                    toolInputField.value = JSON.stringify({
                        path: "/tmp/example.txt"
                    }, null, 2);
                } else if (toolName === 'file.write') {
                    toolInputField.value = JSON.stringify({
                        path: "/tmp/notes.txt",
                        content: "Meeting notes from today's discussion...",
                        mode: "append"
                    }, null, 2);
                } else {
                    toolInputField.value = "{}";
                }
            });
        });
    </script>
</body>
</html>"""

@app.route("/monitor")
def monitor():
    """Public monitoring dashboard with basic metrics and recent logs"""
    # Get recent logs
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
            logs = logs[-30:]  # Get most recent 30 logs
            logs.reverse()  # Show newest first
    except Exception as e:
        logger.error(f"Error reading logs for monitoring: {e}")
    
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
        }
        formatted_logs.append(formatted_log)
    
    # Render dashboard with a distinct monitoring style
    return render_template_string("""
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Monitoring View</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .status-allowed { background-color: rgba(40, 167, 69, 0.2); }
        .status-denied { background-color: rgba(220, 53, 69, 0.2); }
        .status-error { background-color: rgba(255, 193, 7, 0.2); }
        .monitor-header { background-color: #0d6efd; color: white; }
        .monitor-badge { 
            position: fixed; 
            top: 0; 
            right: 0; 
            background: #0d6efd; 
            color: white; 
            padding: 5px 15px; 
            z-index: 1000; 
        }
    </style>
</head>
<body>
    <div class="monitor-badge">MONITOR MODE</div>
    
    <div class="container-fluid p-4">
        <div class="row mb-4">
            <div class="col-12">
                <div class="card monitor-header">
                    <div class="card-body d-flex justify-content-between align-items-center">
                        <h2 class="mb-0">MCP-Sec Gateway Monitoring</h2>
                        <div>
                <a href="/" class="btn btn-sm btn-outline-secondary me-2">Home</a>
                <a href="/admin" class="btn btn-sm btn-outline-danger">Admin Panel</a>
            </div>
        </header>

        <div class="row mb-4">
            <div class="col-md-3 col-6">
                <div class="card text-center bg-primary bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Total Requests</h6>
                        <h2 class="card-title">{{ total_requests }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-6">
                <div class="card text-center bg-success bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Allowed</h6>
                        <h2 class="card-title">{{ allowed }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-6">
                <div class="card text-center bg-danger bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Denied</h6>
                        <h2 class="card-title">{{ denied }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-6">
                <div class="card text-center bg-warning bg-opacity-25 h-100">
                    <div class="card-body">
                        <h6 class="card-subtitle mb-2 text-muted">Errors</h6>
                        <h2 class="card-title">{{ errors }}</h2>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Recent Activity</h5>
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
                                    {% if formatted_logs %}
                                        {% for log in formatted_logs %}
                                        <tr class="status-{{ log.status }}">
                                            <td>{{ log.timestamp }}</td>
                                            <td>{{ log.model_id }}</td>
                                            <td>{{ log.tool }}</td>
                                            <td>{{ log.status }}</td>
                                            <td>{{ log.reason or '' }}</td>
                                        </tr>
                                        {% endfor %}
                                    {% else %}
                                        <tr><td colspan="5" class="text-center py-3">No activity logs found</td></tr>
                                    {% endif %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <footer class="pt-3 mt-4 text-body-secondary border-top">
            &copy; 2025 MCP-Sec Gateway | <span class="text-muted">Public Monitoring Dashboard</span>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-refresh the page every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
    """, total_requests=total_requests, allowed=allowed, denied=denied, errors=errors, formatted_logs=formatted_logs)

# API routes for tools catalog
@app.route("/api/tools")
def list_tools():
    """List all available tools in the catalog"""
    try:
        from tools_catalog.catalog import get_all_tools
        tools = get_all_tools()
        return jsonify({"tools": tools})
    except ImportError:
        # Use legacy method to find tools
        tools_dir = os.path.join("tools")
        tools = []
        if os.path.exists(tools_dir):
            for filename in os.listdir(tools_dir):
                if filename.endswith(".json"):
                    tools.append(filename.replace(".json", ""))
        return jsonify({"tools": tools})

@app.route("/api/tools/<name>")
def get_tool_schema(name):
    """Get the schema for a specific tool"""
    try:
        from tools_catalog.catalog import get_tool_metadata, get_tool_schema as get_catalog_schema
        
        metadata = get_tool_metadata(name)
        if not metadata:
            return jsonify({"error": f"Tool {name} not found"}), 404
            
        # Get input and output schemas
        input_schema = get_catalog_schema(name, "input")
        output_schema = get_catalog_schema(name, "output")
        
        # Include schemas in response
        metadata["input_schema"] = input_schema
        metadata["output_schema"] = output_schema
        
        return jsonify(metadata)
    except ImportError:
        # Legacy method
        tools_dir = os.path.join("tools")
        tool_path = os.path.join(tools_dir, f"{name}.json")
        
        if not os.path.exists(tool_path):
            return jsonify({"error": f"Tool {name} not found"}), 404
            
        with open(tool_path, 'r') as f:
            schema = json.load(f)
            
        # Extract metadata
        metadata = {
            "name": name,
            "description": schema.get("description", f"Schema for {name}"),
            "input_schema": schema,
            "output_schema": schema.get("output")
        }
        
        return jsonify(metadata)

# API endpoint for policy management
@app.route("/api/policy", methods=["GET", "POST"])
@require_api_key
def api_policy():
    """Get or update the current policy"""
    if request.method == "GET":
        # Return current policy
        try:
            policy_path = policy_engine.get_policy_path()
            with open(policy_path, "r") as f:
                policy_yaml = f.read()
            return jsonify({
                "policy": policy_engine.load_policy(),
                "policy_yaml": policy_yaml
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        # Update policy with hot-reloading
        try:
            data = request.get_json()
            if not data or "policy_yaml" not in data:
                return jsonify({"error": "Missing policy_yaml field"}), 400
            
            policy_yaml = data["policy_yaml"]
            project_id = data.get("project_id", "default")
            
            success, error = policy_engine.save_policy_yaml(policy_yaml, project_id)
            if success:
                return jsonify({
                    "success": True, 
                    "message": "Policy updated and hot-reloaded",
                    "policy": policy_engine.load_policy(project_id)
                })
            else:
                return jsonify({"error": error}), 400
        except Exception as e:
            logging.error(f"Error updating policy: {str(e)}")
            return jsonify({"error": str(e)}), 500

@app.route("/api/policy/reload", methods=["POST"])
@require_api_key
def api_policy_reload():
    """Reload policy from disk"""
    policy_engine.reload_policies()
    return jsonify({"success": True, "message": "Policies reloaded"})

@app.route("/api/schema/reload", methods=["POST"])
@require_api_key
def api_schema_reload():
    """Reload schemas from disk"""
    schema_validator.reload_schemas()
    return jsonify({"success": True, "message": "Schemas reloaded"})

@app.route("/api/policy/history")
@require_api_key
def api_policy_history():
    """Get policy version history"""
    history = policy_engine.get_policy_history()
    return jsonify({"history": history})

@app.route("/api/policy/rollback/<int:timestamp>", methods=["POST"])
@require_api_key
def api_policy_rollback(timestamp):
    """Rollback to a previous policy version"""
    success = policy_engine.rollback_policy(timestamp)
    if success:
        return jsonify({"success": True, "message": f"Rolled back to policy version at timestamp {timestamp}"})
    else:
        return jsonify({"success": False, "error": "Rollback failed"}), 400

@app.route("/api/logs/export")
@require_api_key
def api_logs_export():
    """Download CSV of recent logs."""
    import csv
    import io
    
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except:
        pass
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["Timestamp", "Session ID", "Model ID", "Tool", "Status", "Reason", "Risk Level"])
    
    # Write data
    for log in logs:
        writer.writerow([
            log.get("timestamp", ""),
            log.get("session_id", ""),
            log.get("model_id", ""),
            log.get("tool", ""),
            log.get("status", ""),
            log.get("reason", ""),
            log.get("risk_level", "")
        ])
    
    # Create response
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=mcp_sec_logs.csv"
    
    return response

@app.route("/api/get_config")
@require_api_key
def api_get_config():
    """Get current configuration"""
    return jsonify(config)

@app.route("/api/save_config", methods=["POST"])
@require_api_key
def api_save_config():
    """Save configuration"""
    global config
    
    try:
        new_config = request.get_json()
        
        # Update only known keys
        for key in ["log_level", "max_hist", "auto_refresh_ms"]:
            if key in new_config:
                config[key] = new_config[key]
        
        return jsonify({"success": True, "config": config})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/session/<session_id>")
@require_api_key
def api_session(session_id):
    """Get details of a specific session"""
    context = session_tracker.get_context(session_id)
    if not context:
        return jsonify({"error": f"Session {session_id} not found"}), 404
    
    return jsonify({"session_id": session_id, "context": context})

@app.route("/api/simulate", methods=["POST"])
@require_api_key
def api_simulate():
    """Simulate policy evaluation for a tool call"""
    try:
        data = request.get_json()
        
        model_id = data.get("model_id")
        tool_name = data.get("tool")
        session_id = data.get("session_id")
        
        if not all([model_id, tool_name, session_id]):
            return jsonify({"error": "Missing required parameters"}), 400
        
        # Get session context
        context = session_tracker.get_context(session_id)
        if not context:
            return jsonify({"error": f"Session {session_id} not found"}), 404
        
        # Simulate basic policy
        basic_result = policy_engine.check_policy(model_id, tool_name, session_id)
        
        # Simulate contextual policy
        contextual_result = policy_engine.check_policy_contextual(model_id, tool_name, session_id, context)
        
        # Simulate shadow policy
        shadow_result = policy_engine.simulate_shadow_policy(model_id, tool_name, session_id, context)
        
        return jsonify({
            "basic_policy": {
                "allowed": basic_result[0],
                "reason": basic_result[1]
            },
            "contextual_policy": contextual_result,
            "shadow_policy": shadow_result
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/shadow_policy")
@require_api_key
def api_shadow_policy():
    """Get current shadow policy"""
    try:
        shadow_path = "policies/shadow.yaml"
        if os.path.exists(shadow_path):
            with open(shadow_path, "r") as f:
                shadow_policy = yaml.safe_load(f)
            return jsonify({"policy": shadow_policy})
        else:
            return jsonify({"policy": {}})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/save_shadow_policy", methods=["POST"])
@require_api_key
def api_save_shadow_policy():
    """Save shadow policy"""
    try:
        data = request.get_json()
        policy = data.get("policy")
        
        if not policy:
            return jsonify({"error": "No policy provided"}), 400
        
        # Ensure policies directory exists
        os.makedirs("policies", exist_ok=True)
        
        # Write shadow policy
        shadow_path = "policies/shadow.yaml"
        with open(shadow_path, "w") as f:
            yaml.dump(policy, f, default_flow_style=False)
        
        return jsonify({"success": True, "message": "Shadow policy saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/projects")
@require_api_key
def api_projects():
    """Get list of available projects"""
    projects = ["default"]
    
    # Look for project-specific policy files
    policy_files = glob.glob("policies/*.yaml")
    for path in policy_files:
        project = os.path.basename(path).replace(".yaml", "")
        if project != "default" and project != "shadow":
            projects.append(project)
    
    return jsonify({"projects": projects})

# Register the MCP routes
app.register_blueprint(mcp_routes.mcp_bp)

# Generate some sample data on startup
if __name__ == "__main__":
    # Only generate sample data in development to avoid polluting production logs
    if not os.getenv("PRODUCTION"):
        generate_sample_data()
        
    app.run(debug=True, host="0.0.0.0")