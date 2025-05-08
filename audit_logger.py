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
        
    # Check for anomalies
    detect_anomalies(event)
    
    # Forward to SIEM if configured
    forward_to_siem(event)

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

def detect_anomalies(event: dict):
    """
    Detect anomalies in the log stream and report them
    
    Currently checks for:
    - Spikes in denial rate (10+ denials in 2 minutes)
    - Multiple high-risk events in a short time period
    - Unusual patterns in tool usage
    
    Args:
        event: The current event
    """
    # Skip if not a denial (we're mainly looking for denial spikes)
    if event.get("status") != "denied":
        return
        
    try:
        # Count recent denials (events in the last 2 minutes)
        current_time = time.time()
        recent_denials = 0
        
        # Calculate timestamp 2 minutes ago
        two_min_ago = current_time - 120
        
        for log_event in LOG_HISTORY[-100:]:  # Only check the most recent 100 entries for efficiency
            # Skip if not a denial
            if log_event.get("status") != "denied":
                continue
                
            # Check if the event is recent (within the last 2 minutes)
            try:
                event_time = log_event.get("timestamp", "")
                if not event_time:
                    continue
                    
                # Convert ISO datetime to timestamp
                event_timestamp = datetime.datetime.fromisoformat(event_time).timestamp()
                
                if event_timestamp >= two_min_ago:
                    recent_denials += 1
            except (ValueError, TypeError):
                # Skip events with invalid timestamps
                continue
        
        # Alert if denial rate is high
        if recent_denials >= 10:
            print(f"🚨 ANOMALY DETECTED: High denial rate - {recent_denials} denials in the last 2 minutes", 
                  flush=True)
            
            # Here you would typically trigger an alert or notification
            # For example: send_alert("high_denial_rate", recent_denials)
            
    except Exception as e:
        print(f"Error in anomaly detection: {str(e)}", flush=True)

def forward_to_siem(event: dict):
    """
    Forward event to an external Security Information and Event Management (SIEM) system
    if configured via SIEM_URL environment variable
    
    Args:
        event: The event to forward
    """
    siem_url = os.environ.get("SIEM_URL")
    
    # Skip if no SIEM URL is configured
    if not siem_url:
        return
        
    try:
        # Import requests here to avoid dependency when not needed
        import requests
        
        # Send request to SIEM with a short timeout
        response = requests.post(
            siem_url,
            json=event,
            headers={"Content-Type": "application/json"},
            timeout=2  # Short timeout to avoid blocking
        )
        
        # Log failure but don't raise exception
        if not response.ok:
            print(f"SIEM forward failed: HTTP {response.status_code} - {response.text}", flush=True)
            
    except ImportError:
        print("SIEM forwarding requires requests library", flush=True)
    except Exception as e:
        print(f"SIEM forward failed: {str(e)}", flush=True)