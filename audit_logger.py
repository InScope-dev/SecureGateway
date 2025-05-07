"""
MCP-Sec Audit Logger
Logs all activity in JSON-lines format
"""
import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

# Setup logging
logger = logging.getLogger(__name__)

# In-memory log history (most recent entries)
LOG_HISTORY = []
MAX_HISTORY = 1000

# Path to the audit log file
LOG_FILE = "audit.log"

def log_event(event: Dict[str, Any]) -> None:
    """
    Log an event to the audit log
    
    Args:
        event: Dictionary containing event details
    """
    # Ensure timestamp is in ISO format
    if "timestamp" not in event:
        event["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Add to in-memory history (limited size)
    LOG_HISTORY.append(event)
    
    # Trim history if it exceeds maximum size
    if len(LOG_HISTORY) > MAX_HISTORY:
        LOG_HISTORY.pop(0)
    
    # Write to log file
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        logger.error(f"Failed to write to audit log: {str(e)}")
    
    # Also log to console for visibility
    logger.info(f"AUDIT: {json.dumps(event)}")

def get_recent_logs(count: int = 100) -> List[Dict[str, Any]]:
    """
    Get the most recent log entries
    
    Args:
        count: Maximum number of entries to return
    
    Returns:
        List of log entries, most recent first
    """
    return list(reversed(LOG_HISTORY[-count:]))

def get_logs_by_session(session_id: str, count: int = 100) -> List[Dict[str, Any]]:
    """
    Get log entries for a specific session
    
    Args:
        session_id: The ID of the session
        count: Maximum number of entries to return
    
    Returns:
        List of log entries for the session, most recent first
    """
    session_logs = [log for log in LOG_HISTORY if log.get("session_id") == session_id]
    return list(reversed(session_logs[-count:]))

def get_logs_by_model(model_id: str, count: int = 100) -> List[Dict[str, Any]]:
    """
    Get log entries for a specific model
    
    Args:
        model_id: The ID of the model
        count: Maximum number of entries to return
    
    Returns:
        List of log entries for the model, most recent first
    """
    model_logs = [log for log in LOG_HISTORY if log.get("model_id") == model_id]
    return list(reversed(model_logs[-count:]))

def clear_logs() -> None:
    """Clear the in-memory log history (for testing)"""
    global LOG_HISTORY
    LOG_HISTORY = []
    logger.info("In-memory log history cleared")

# Ensure log file exists
try:
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("")
except Exception as e:
    logger.error(f"Failed to create audit log file: {str(e)}")
