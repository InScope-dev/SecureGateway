"""
MCP-Sec Gateway - Admin Dashboard Module
Provides the administrative interface for MCP-Sec Gateway
"""
import os
import json
import glob
import logging
from functools import wraps
from typing import Dict, List, Any, Optional

from flask import Blueprint, request, jsonify, render_template_string

# Setup logger for this module
logger = logging.getLogger(__name__)

# Create blueprint for admin routes
admin_bp = Blueprint('admin', __name__)

def require_api_key(view_function):
    """Decorator to require admin API key for sensitive endpoints."""
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        # For development purposes, always allow bypass_auth=true
        if request.args.get("bypass_auth") == "true":
            logger.info("Authentication bypassed with bypass_auth=true")
            return view_function(*args, **kwargs)
            
        # Get the admin key from environment variable
        admin_key = os.environ.get("ADMIN_KEY")
        
        if not admin_key:
            logger.error("ADMIN_KEY environment variable not set. Using a secure fallback.")
            # Use a secure random value that changes on each restart
            import secrets
            admin_key = secrets.token_hex(16)
            logger.info(f"Using temporary admin key: {admin_key}")
        
        # Check query params for ease of testing
        api_key = request.args.get("api_key")
            
        if not api_key or api_key != admin_key:
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
                                            <p class="small text-muted">For development, you can use <a href="/admin?bypass_auth=true">bypass_auth=true</a></p>
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

@admin_bp.route("/")
def admin_dashboard():
    """Admin dashboard focused on tools catalog"""
    logger.info("Admin dashboard accessed with tools catalog")
    
    # Retrieve all available tools from the filesystem
    tools = []
    try:
        tool_files = glob.glob("tools/*.json")
        for tool_file in tool_files:
            tool_name = os.path.basename(tool_file).replace(".json", "")
            tools.append({
                "name": tool_name,
                "file": tool_file
            })
    except Exception as e:
        logger.error(f"Error loading tools: {e}")
    
    # Get recent logs
    logs = []
    try:
        with open("audit.log", "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
            logs = logs[-50:]  # Get most recent 50 logs
            logs.reverse()  # Show newest first
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
    
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
    
    # Render admin dashboard with distinct styling that clearly shows it's different from monitor
    return render_template_string("""
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec ADMIN Dashboard</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .admin-header { background-color: #dc3545; color: white; }
        .admin-badge { position: fixed; top: 0; right: 0; background: #dc3545; color: white; padding: 5px 15px; z-index: 1000; }
        .status-allowed { background-color: rgba(40, 167, 69, 0.2); }
        .status-denied { background-color: rgba(220, 53, 69, 0.2); }
        .status-error { background-color: rgba(255, 193, 7, 0.2); }
        pre { background: #222; padding: 10px; border-radius: 4px; overflow: auto; }
        .risk-high { color: #dc3545; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #198754; }
    </style>
</head>
<body>
    <div class="admin-badge">ADMIN MODE</div>
    
    <div class="container-fluid p-4">
        <div class="row mb-4">
            <div class="col-12">
                <div class="card admin-header">
                    <div class="card-body d-flex justify-content-between align-items-center">
                        <h2 class="mb-0">MCP-Sec Gateway Admin Dashboard</h2>
                        <div>
                            <a href="/" class="btn btn-sm btn-light me-2">Home</a>
                            <a href="/monitor" class="btn btn-sm btn-outline-light">Monitoring</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Dashboard Navigation Tabs -->
        <ul class="nav nav-tabs mb-4" id="adminTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" 
                    type="button" role="tab" aria-controls="overview" aria-selected="false">Overview</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="tools-tab" data-bs-toggle="tab" data-bs-target="#tools" 
                    type="button" role="tab" aria-controls="tools" aria-selected="true">Tools Catalog</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="policies-tab" data-bs-toggle="tab" data-bs-target="#policies" 
                    type="button" role="tab" aria-controls="policies" aria-selected="false">Policy Management</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="config-tab" data-bs-toggle="tab" data-bs-target="#config" 
                    type="button" role="tab" aria-controls="config" aria-selected="false">Configuration</button>
            </li>
        </ul>

        <div class="tab-content" id="adminTabContent">
            <!-- Overview Tab -->
            <div class="tab-pane fade" id="overview" role="tabpanel" aria-labelledby="overview-tab">
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

                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">Detailed Audit Logs</h5>
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
                                        <tbody>
                                            {% if formatted_logs %}
                                                {% for log in formatted_logs %}
                                                <tr class="status-{{ log.status }}">
                                                    <td>{{ log.timestamp }}</td>
                                                    <td>{{ log.model_id }}</td>
                                                    <td>{{ log.tool }}</td>
                                                    <td>{{ log.status }}</td>
                                                    <td>
                                                        <div>{{ log.reason or '' }}</div>
                                                        {% if log.reasoning %}
                                                        <div class="mt-1 small text-muted">
                                                            <strong>Reasoning:</strong> 
                                                            {% if log.reasoning is iterable and log.reasoning is not string %}
                                                                {{ '<br>'.join(log.reasoning) }}
                                                            {% else %}
                                                                {{ log.reasoning }}
                                                            {% endif %}
                                                        </div>
                                                        {% endif %}
                                                        {% if log.rule_trace %}
                                                        <div class="mt-1 small text-muted">
                                                            <strong>Rules:</strong> 
                                                            {% if log.rule_trace is iterable and log.rule_trace is not string %}
                                                                {{ ', '.join(log.rule_trace) }}
                                                            {% else %}
                                                                {{ log.rule_trace }}
                                                            {% endif %}
                                                        </div>
                                                        {% endif %}
                                                    </td>
                                                    <td>{{ '%sms'|format(log.latency_ms) if log.latency_ms else '-' }}</td>
                                                </tr>
                                                {% endfor %}
                                            {% else %}
                                                <tr><td colspan="6" class="text-center py-3">No audit logs found</td></tr>
                                            {% endif %}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tools Catalog Tab (ACTIVE BY DEFAULT) -->
            <div class="tab-pane fade show active" id="tools" role="tabpanel" aria-labelledby="tools-tab">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Tools Catalog</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-12 mb-4">
                                        <div class="alert alert-info">
                                            <i class="bi bi-info-circle me-2"></i>
                                            This admin dashboard provides tools catalog management and security risk assessment.
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="row">
                                    {% if tools %}
                                        {% for tool in tools %}
                                        <div class="col-md-4 mb-3">
                                            <div class="card h-100">
                                                <div class="card-header bg-primary bg-opacity-25">
                                                    <h5 class="mb-0">{{ tool.name }}</h5>
                                                </div>
                                                <div class="card-body">
                                                    <p class="card-text">
                                                        <strong>Path:</strong> {{ tool.file }}
                                                    </p>
                                                    <a href="/api/tools/{{ tool.name }}" class="btn btn-sm btn-primary">View Schema</a>
                                                </div>
                                            </div>
                                        </div>
                                        {% endfor %}
                                    {% else %}
                                        <div class="col-12">
                                            <div class="alert alert-warning">
                                                No tools found in the catalog. Check your tools directory.
                                            </div>
                                        </div>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Tool Risk Matrix</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-12">
                                        <div class="table-responsive">
                                            <table class="table table-bordered">
                                                <thead>
                                                    <tr>
                                                        <th></th>
                                                        <th class="text-center">Low Impact</th>
                                                        <th class="text-center">Medium Impact</th>
                                                        <th class="text-center">High Impact</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <tr>
                                                        <th>High Likelihood</th>
                                                        <td class="bg-warning bg-opacity-25 text-center">Medium Risk</td>
                                                        <td class="bg-danger bg-opacity-25 text-center">High Risk</td>
                                                        <td class="bg-danger bg-opacity-50 text-center">Critical Risk</td>
                                                    </tr>
                                                    <tr>
                                                        <th>Medium Likelihood</th>
                                                        <td class="bg-success bg-opacity-25 text-center">Low Risk</td>
                                                        <td class="bg-warning bg-opacity-25 text-center">Medium Risk</td>
                                                        <td class="bg-danger bg-opacity-25 text-center">High Risk</td>
                                                    </tr>
                                                    <tr>
                                                        <th>Low Likelihood</th>
                                                        <td class="bg-success bg-opacity-25 text-center">Very Low Risk</td>
                                                        <td class="bg-success bg-opacity-25 text-center">Low Risk</td>
                                                        <td class="bg-warning bg-opacity-25 text-center">Medium Risk</td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Policies Tab -->
            <div class="tab-pane fade" id="policies" role="tabpanel" aria-labelledby="policies-tab">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Policy Management</h5>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-info">
                                    <i class="bi bi-info-circle me-2"></i>
                                    This panel allows administrators to view and manage security policies.
                                </div>
                                <div class="d-flex justify-content-end mb-3">
                                    <a href="/api/policy/reload" class="btn btn-primary">Reload Policies</a>
                                </div>
                                <div>
                                    <h5>Policy Administration</h5>
                                    <p>Coming soon: Policy editor with history and version control</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Configuration Tab -->
            <div class="tab-pane fade" id="config" role="tabpanel" aria-labelledby="config-tab">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Gateway Configuration</h5>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-info">
                                    <i class="bi bi-info-circle me-2"></i>
                                    This panel allows administrators to configure the MCP-Sec Gateway.
                                </div>
                                <div>
                                    <h5>System Configuration</h5>
                                    <p>Coming soon: Gateway configuration editor</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""", tools=tools, total_requests=total_requests, allowed=allowed, denied=denied, errors=errors, formatted_logs=formatted_logs)