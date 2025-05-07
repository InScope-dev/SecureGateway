"""
MCP-Sec Audit Logger
Logs all activity in JSON-lines format with file size management
"""
import json
import time
import os
import datetime

# Constants for log management
MAX_LOG_FILE_SIZE_MB = 10
MAX_HISTORY_ENTRIES = 1000
LOG_FILE_PATH = "audit.log"

# In-memory history of recent events
LOG_HISTORY = []

def log_event(event: dict):
    """
    Log an event to the audit log
    
    Args:
        event: Dictionary containing event details
    """
    # Add timestamp if not present
    if "timestamp" not in event:
        event["timestamp"] = datetime.datetime.utcnow().isoformat()
    
    # Calculate risk level if not already provided
    if "risk_level" not in event:
        event["risk_level"] = calculate_risk_level(event)
    
    # Convert to JSON and write to stdout
    line = json.dumps(event)
    print(line, flush=True)
    
    # Append to log file, with size management
    manage_log_file(line)
    
    # Add to in-memory history with size limit
    LOG_HISTORY.append(event)
    while len(LOG_HISTORY) > MAX_HISTORY_ENTRIES:
        LOG_HISTORY.pop(0)

def manage_log_file(log_line: str):
    """
    Write to log file with size management
    
    Args:
        log_line: JSON line to append to log
    """
    # Check if file exists and exceeds size limit
    if os.path.exists(LOG_FILE_PATH) and os.path.getsize(LOG_FILE_PATH) / (1024 * 1024) > MAX_LOG_FILE_SIZE_MB:
        # If file is too big, rotate it (rename old one with timestamp)
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        backup_path = f"{LOG_FILE_PATH}.{timestamp}"
        try:
            os.rename(LOG_FILE_PATH, backup_path)
        except Exception as e:
            print(f"Error rotating log file: {str(e)}", flush=True)
            # In case of error, truncate instead
            with open(LOG_FILE_PATH, "w") as f:
                f.write("")
    
    # Append the new log line
    try:
        with open(LOG_FILE_PATH, "a") as f:
            f.write(log_line + "\n")
    except Exception as e:
        print(f"Error writing to log file: {str(e)}", flush=True)

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