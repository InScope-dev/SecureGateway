"""
MCP-Sec Audit Logger
Logs all activity in JSON-lines format
"""
import json
import time

LOG_HISTORY = []

def log_event(event: dict):
    """
    Log an event to the audit log
    
    Args:
        event: Dictionary containing event details
    """
    # Calculate risk level if not already provided
    if "risk_level" not in event:
        event["risk_level"] = calculate_risk_level(event)
        
    line = json.dumps(event)
    print(line, flush=True)
    with open("audit.log", "a") as f:
        f.write(line + "\n")
    LOG_HISTORY.append(event)
    if len(LOG_HISTORY) > 500:
        LOG_HISTORY.pop(0)

def calculate_risk_level(event: dict) -> str:
    """
    Calculate the risk level for an event based on various factors
    
    Args:
        event: Dictionary containing event details
    
    Returns:
        Risk level as a string: 'low', 'medium', or 'high'
    """
    # Default risk level
    risk_level = "low"
    
    # Denied events are at least medium risk
    if event.get("status") == "denied":
        risk_level = "medium"
        
        # Check for specific high-risk denial reasons
        if event.get("reason"):
            reason = event.get("reason", "").lower()
            high_risk_patterns = [
                "unauthorized", "permission", "access denied", "validation error",
                "schema validation", "rate limit", "quota exceeded", "blocked",
                "suspicious", "malicious", "token"
            ]
            
            if any(pattern in reason for pattern in high_risk_patterns):
                risk_level = "high"
    
    # Error events are medium risk
    elif event.get("status") == "error":
        risk_level = "medium"
    
    # Check for sensitive tools that should have higher risk
    sensitive_tools = ["file_write", "execute", "system", "shell", "admin", "config"]
    tool = event.get("tool", "").lower()
    
    if any(sensitive in tool for sensitive in sensitive_tools):
        # Upgrade risk level for sensitive tools
        if risk_level == "low":
            risk_level = "medium"
        elif risk_level == "medium":
            risk_level = "high"
    
    # Examine input/output for sensitive content
    sensitive_patterns = ["password", "token", "secret", "key", "credential", "auth"]
    
    # Check input data for sensitive patterns
    input_data = event.get("input", {})
    if isinstance(input_data, dict):
        input_str = json.dumps(input_data).lower()
        if any(pattern in input_str for pattern in sensitive_patterns):
            risk_level = "high"
            
    # Check output data for sensitive patterns
    output_data = event.get("output", {})
    if isinstance(output_data, dict):
        output_str = json.dumps(output_data).lower()
        if any(pattern in output_str for pattern in sensitive_patterns):
            risk_level = "high"
    
    return risk_level