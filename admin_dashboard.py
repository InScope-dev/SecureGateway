"""
MCP-Sec Gateway - Admin Dashboard Module
Provides the administrative interface for MCP-Sec Gateway
"""
import os
import json
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
            # This is just a fallback and will be highly secure but inconvenient
            import secrets
            admin_key = secrets.token_hex(16)
            logger.info(f"Using temporary admin key: {admin_key}")
        
        # Check query params for ease of testing
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
    """Admin dashboard with full configuration options and detailed metrics"""
    api_key = request.args.get("api_key", "")
    bypass_auth = request.args.get("bypass_auth", "false")
    
    # Skip authentication completely for troubleshooting
    logger.info("Admin dashboard accessed")
    
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
    
    # Render admin dashboard
    return render_template_string("""
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP-Sec Admin Dashboard</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <style>
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
    <div class="container-fluid p-4">
        <header class="pb-3 mb-4 border-bottom d-flex justify-content-between align-items-center">
            <h1 class="h3">MCP-Sec Gateway Admin Dashboard</h1>
            <div>
                <a href="/" class="btn btn-sm btn-outline-secondary me-2">Home</a>
                <a href="/monitor" class="btn btn-sm btn-outline-primary">Monitoring</a>
            </div>
        </header>

        <!-- Dashboard Navigation Tabs -->
        <ul class="nav nav-tabs mb-4" id="adminTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="overview-tab" data-bs-toggle="tab" data-bs-target="#overview" 
                    type="button" role="tab" aria-controls="overview" aria-selected="true">Overview</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="tools-tab" data-bs-toggle="tab" data-bs-target="#tools" 
                    type="button" role="tab" aria-controls="tools" aria-selected="false">Tools Catalog</button>
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
            <div class="tab-pane fade show active" id="overview" role="tabpanel" aria-labelledby="overview-tab">
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

            <!-- Tools Catalog Tab -->
            <div class="tab-pane fade" id="tools" role="tabpanel" aria-labelledby="tools-tab">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <ul class="nav nav-tabs card-header-tabs" id="tools-tabs" role="tablist">
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link active" id="tools-list-tab" data-bs-toggle="tab" data-bs-target="#tools-list-pane" 
                                            type="button" role="tab" aria-controls="tools-list-pane" aria-selected="true">
                                            Tools Explorer
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link" id="tools-security-tab" data-bs-toggle="tab" data-bs-target="#tools-security-pane" 
                                            type="button" role="tab" aria-controls="tools-security-pane" aria-selected="false">
                                            Risk Assessment
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link" id="tools-schema-tab" data-bs-toggle="tab" data-bs-target="#tools-schema-pane" 
                                            type="button" role="tab" aria-controls="tools-schema-pane" aria-selected="false">
                                            Schema Validation
                                        </button>
                                    </li>
                                </ul>
                            </div>
                            <div class="card-body">
                                <div class="tab-content" id="tools-tabs-content">
                                    <!-- Tools Explorer Tab -->
                                    <div class="tab-pane fade show active" id="tools-list-pane" role="tabpanel" aria-labelledby="tools-list-tab">
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
                                                <pre id="tool_detail" class="p-3 bg-dark text-light rounded" style="min-height: 300px;">Select a tool to view details</pre>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Risk Assessment Tab -->
                                    <div class="tab-pane fade" id="tools-security-pane" role="tabpanel" aria-labelledby="tools-security-tab">
                                        <div class="alert alert-info">
                                            <p class="mb-0">This matrix shows the risk categorization of each tool in the catalog.</p>
                                        </div>
                                        <div class="table-responsive">
                                            <table class="table table-hover">
                                                <thead>
                                                    <tr>
                                                        <th>Tool Name</th>
                                                        <th>Risk Level</th>
                                                        <th>Category</th>
                                                        <th>Description</th>
                                                    </tr>
                                                </thead>
                                                <tbody id="security_matrix">
                                                    <tr>
                                                        <td colspan="4" class="text-center py-3">
                                                            <div class="spinner-border spinner-border-sm text-primary" role="status">
                                                                <span class="visually-hidden">Loading...</span>
                                                            </div>
                                                            <span class="ms-2">Loading tool security data...</span>
                                                        </td>
                                                    </tr>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                    
                                    <!-- Schema Validation Tab -->
                                    <div class="tab-pane fade" id="tools-schema-pane" role="tabpanel" aria-labelledby="tools-schema-tab">
                                        <div class="alert alert-info">
                                            <p class="mb-0">All tools must have validated input and output schemas to ensure proper validation.</p>
                                        </div>
                                        <div id="schema_validation_status" class="mt-3">
                                            <div class="text-center py-3">
                                                <div class="spinner-border spinner-border-sm text-primary" role="status">
                                                    <span class="visually-hidden">Loading...</span>
                                                </div>
                                                <span class="ms-2">Loading schema validation status...</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Policy Management Tab -->
            <div class="tab-pane fade" id="policies" role="tabpanel" aria-labelledby="policies-tab">
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
                                <h5 class="mb-0">Shadow Policy Management</h5>
                                <div>
                                    <button id="viewShadowPolicy" class="btn btn-sm btn-outline-primary me-2">View Shadow Policy</button>
                                    <button id="saveShadowPolicy" class="btn btn-sm btn-success">Save Changes</button>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-info">
                                    <p class="mb-0">Shadow policies are evaluated but not enforced, allowing for policy testing without impacting production.</p>
                                </div>
                                <div id="shadowPolicyEditor" style="display: none;">
                                    <textarea id="shadowPolicyText" class="form-control" rows="10" style="font-family: monospace;"></textarea>
                                    <div class="mt-2 text-end">
                                        <button id="cancelShadowPolicy" class="btn btn-sm btn-outline-secondary">Cancel</button>
                                        <button id="updateShadowPolicy" class="btn btn-sm btn-primary ms-2">Update</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Configuration Tab -->
            <div class="tab-pane fade" id="config" role="tabpanel" aria-labelledby="config-tab">
                <div class="row">
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">Gateway Configuration</h5>
                            </div>
                            <div class="card-body">
                                <form id="configForm">
                                    <div class="mb-3">
                                        <label for="logLevel" class="form-label">Log Level</label>
                                        <select class="form-select" id="logLevel">
                                            <option value="debug">Debug</option>
                                            <option value="info" selected>Info</option>
                                            <option value="warning">Warning</option>
                                            <option value="error">Error</option>
                                        </select>
                                    </div>
                                    <div class="mb-3">
                                        <label for="maxLogRetention" class="form-label">Max Log Retention</label>
                                        <div class="input-group">
                                            <input type="number" class="form-control" id="maxLogRetention" value="500">
                                            <span class="input-group-text">entries</span>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label for="autoRefresh" class="form-label">Dashboard Auto-Refresh</label>
                                        <div class="input-group">
                                            <input type="number" class="form-control" id="autoRefresh" value="2000">
                                            <span class="input-group-text">ms</span>
                                        </div>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Save Configuration</button>
                                </form>
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
                                            <option value="default" selected>default</option>
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
            </div>
        </div>

        <footer class="pt-3 mt-4 text-body-secondary border-top">
            &copy; 2025 MCP-Sec Gateway | <span class="text-muted">Admin Dashboard</span>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Load the list of available tools
            function loadTools() {
                fetch('/api/tools')
                    .then(response => response.json())
                    .then(data => {
                        const toolList = document.getElementById('tool_list');
                        toolList.innerHTML = '';
                        
                        data.tools.forEach(tool => {
                            fetch(`/api/tools/${tool}`)
                                .then(response => response.json())
                                .then(toolData => {
                                    // Create a list item for each tool
                                    const item = document.createElement('a');
                                    item.href = '#';
                                    item.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
                                    
                                    // Add risk level indicator
                                    let riskBadge = '';
                                    if (toolData.risk_level === 'high') {
                                        riskBadge = '<span class="badge bg-danger">High Risk</span>';
                                    } else if (toolData.risk_level === 'medium') {
                                        riskBadge = '<span class="badge bg-warning text-dark">Medium Risk</span>';
                                    } else {
                                        riskBadge = '<span class="badge bg-success">Low Risk</span>';
                                    }
                                    
                                    item.innerHTML = `${tool} ${riskBadge}`;
                                    
                                    // Add click event to show tool details
                                    item.addEventListener('click', function(e) {
                                        e.preventDefault();
                                        document.querySelectorAll('#tool_list a').forEach(el => {
                                            el.classList.remove('active');
                                        });
                                        this.classList.add('active');
                                        
                                        const detail = document.getElementById('tool_detail');
                                        detail.innerText = JSON.stringify(toolData, null, 2);
                                    });
                                    
                                    toolList.appendChild(item);
                                })
                                .catch(error => console.error(`Error loading tool ${tool}:`, error));
                        });
                        
                        // Also populate the security matrix
                        populateSecurityMatrix(data.tools);
                        
                        // And schema validation status
                        populateSchemaStatus(data.tools);
                    })
                    .catch(error => {
                        console.error('Error loading tools:', error);
                        document.getElementById('tool_list').innerHTML = '<div class="alert alert-danger">Error loading tools. Please try again.</div>';
                    });
            }
            
            // Populate the security matrix table
            function populateSecurityMatrix(tools) {
                const matrix = document.getElementById('security_matrix');
                matrix.innerHTML = '<tr><td colspan="4" class="text-center">Loading tool security data...</td></tr>';
                
                // Promises array for all tool data requests
                const promises = tools.map(tool => 
                    fetch(`/api/tools/${tool}`)
                        .then(response => response.json())
                        .catch(error => console.error(`Error loading tool ${tool}:`, error))
                );
                
                Promise.all(promises)
                    .then(toolsData => {
                        matrix.innerHTML = '';
                        
                        toolsData.forEach(tool => {
                            if (!tool) return; // Skip if tool data couldn't be loaded
                            
                            const riskClass = 'risk-' + (tool.risk_level || 'low');
                            const categories = Array.isArray(tool.categories) 
                                ? tool.categories.join(', ') 
                                : (tool.category || 'General');
                                
                            const row = document.createElement('tr');
                            row.innerHTML = `
                                <td>${tool.name}</td>
                                <td><span class="${riskClass}">${tool.risk_level || 'low'}</span></td>
                                <td>${categories}</td>
                                <td>${tool.description || ''}</td>
                            `;
                            
                            matrix.appendChild(row);
                        });
                    })
                    .catch(error => {
                        console.error('Error loading security matrix:', error);
                        matrix.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Error loading security data.</td></tr>';
                    });
            }
            
            // Populate schema validation status
            function populateSchemaStatus(tools) {
                const statusDiv = document.getElementById('schema_validation_status');
                statusDiv.innerHTML = '<div class="text-center">Loading schema validation status...</div>';
                
                // Promises array for all tool data requests
                const promises = tools.map(tool => 
                    fetch(`/api/tools/${tool}`)
                        .then(response => response.json())
                        .catch(error => console.error(`Error loading tool ${tool}:`, error))
                );
                
                Promise.all(promises)
                    .then(toolsData => {
                        // Create a table to display schema status
                        let tableHtml = `
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Tool Name</th>
                                        <th>Input Schema</th>
                                        <th>Output Schema</th>
                                    </tr>
                                </thead>
                                <tbody>
                        `;
                        
                        toolsData.forEach(tool => {
                            if (!tool) return; // Skip if tool data couldn't be loaded
                            
                            const hasInputSchema = tool.input_schema ? 
                                '<span class="text-success"><i class="bi bi-check-circle"></i> Valid</span>' : 
                                '<span class="text-danger"><i class="bi bi-x-circle"></i> Missing</span>';
                                
                            const hasOutputSchema = tool.output_schema ?
                                '<span class="text-success"><i class="bi bi-check-circle"></i> Valid</span>' :
                                '<span class="text-warning"><i class="bi bi-exclamation-circle"></i> Optional</span>';
                                
                            tableHtml += `
                                <tr>
                                    <td>${tool.name}</td>
                                    <td>${hasInputSchema}</td>
                                    <td>${hasOutputSchema}</td>
                                </tr>
                            `;
                        });
                        
                        tableHtml += `
                                </tbody>
                            </table>
                        `;
                        
                        statusDiv.innerHTML = tableHtml;
                    })
                    .catch(error => {
                        console.error('Error loading schema status:', error);
                        statusDiv.innerHTML = '<div class="alert alert-danger">Error loading schema validation status.</div>';
                    });
            }
            
            // Load policy history
            function loadPolicyHistory() {
                const historyDiv = document.getElementById('policyHistory');
                
                fetch('/api/policy/history')
                    .then(response => response.json())
                    .then(data => {
                        if (!data.history || data.history.length === 0) {
                            historyDiv.innerHTML = '<div class="alert alert-info">No policy history available.</div>';
                            return;
                        }
                        
                        let tableHtml = `
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                        `;
                        
                        data.history.forEach(item => {
                            const date = new Date(item.timestamp * 1000).toLocaleString();
                            tableHtml += `
                                <tr>
                                    <td>${date}</td>
                                    <td>
                                        <form method="POST" action="/api/policy/rollback/${item.timestamp}" class="d-inline">
                                            <button type="submit" class="btn btn-sm btn-outline-warning">Rollback</button>
                                        </form>
                                    </td>
                                </tr>
                            `;
                        });
                        
                        tableHtml += `
                                    </tbody>
                                </table>
                            </div>
                        `;
                        
                        historyDiv.innerHTML = tableHtml;
                    })
                    .catch(error => {
                        historyDiv.innerHTML = `<div class="alert alert-danger">Error loading policy history: ${error.message}</div>`;
                    });
            }
            
            // Load projects
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
            
            // Shadow policy management
            const viewShadowBtn = document.getElementById('viewShadowPolicy');
            const saveShadowBtn = document.getElementById('saveShadowPolicy');
            const shadowEditor = document.getElementById('shadowPolicyEditor');
            const shadowText = document.getElementById('shadowPolicyText');
            const cancelShadowBtn = document.getElementById('cancelShadowPolicy');
            const updateShadowBtn = document.getElementById('updateShadowPolicy');
            
            viewShadowBtn.addEventListener('click', function() {
                fetch('/api/shadow_policy')
                    .then(response => response.json())
                    .then(data => {
                        shadowText.value = JSON.stringify(data.policy, null, 2);
                        shadowEditor.style.display = 'block';
                        viewShadowBtn.style.display = 'none';
                        saveShadowBtn.style.display = 'none';
                    })
                    .catch(error => {
                        alert('Error loading shadow policy: ' + error.message);
                    });
            });
            
            cancelShadowBtn.addEventListener('click', function() {
                shadowEditor.style.display = 'none';
                viewShadowBtn.style.display = 'inline-block';
                saveShadowBtn.style.display = 'inline-block';
            });
            
            updateShadowBtn.addEventListener('click', function() {
                try {
                    const policy = JSON.parse(shadowText.value);
                    
                    fetch('/api/save_shadow_policy', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({policy: policy})
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Shadow policy updated successfully.');
                            shadowEditor.style.display = 'none';
                            viewShadowBtn.style.display = 'inline-block';
                            saveShadowBtn.style.display = 'inline-block';
                        } else {
                            alert('Error updating shadow policy: ' + data.error);
                        }
                    })
                    .catch(error => {
                        alert('Error saving shadow policy: ' + error.message);
                    });
                } catch (e) {
                    alert('Invalid JSON: ' + e.message);
                }
            });
            
            // Config form submission
            const configForm = document.getElementById('configForm');
            configForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const config = {
                    log_level: document.getElementById('logLevel').value,
                    max_hist: parseInt(document.getElementById('maxLogRetention').value),
                    auto_refresh_ms: parseInt(document.getElementById('autoRefresh').value)
                };
                
                fetch('/api/save_config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(config)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Configuration saved successfully.');
                    } else {
                        alert('Error saving configuration: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('Error saving configuration: ' + error.message);
                });
            });
            
            // Project switcher form submission
            const projectForm = document.getElementById('projectSwitcher');
            projectForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const projectId = document.getElementById('projectId').value;
                window.location.href = `/admin?project=${projectId}&api_key={{ api_key }}&bypass_auth={{ bypass_auth }}`;
            });
            
            // Initialize everything when page loads
            loadTools();
            loadPolicyHistory();
            loadProjects();
            
            // Load config values from server
            fetch('/api/get_config')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('logLevel').value = data.log_level || 'info';
                    document.getElementById('maxLogRetention').value = data.max_hist || 500;
                    document.getElementById('autoRefresh').value = data.auto_refresh_ms || 2000;
                })
                .catch(error => {
                    console.error('Error loading configuration:', error);
                });
        });
    </script>
</body>
</html>
    """, total_requests=total_requests, allowed=allowed, denied=denied, errors=errors, 
        formatted_logs=formatted_logs, api_key=api_key, bypass_auth=bypass_auth)