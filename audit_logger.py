"""
MCP-Sec Audit Logger
Logs all activity in JSON-lines format and in the database
"""
import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from flask import current_app

# Setup logging
logger = logging.getLogger(__name__)

# In-memory log history (fallback for when DB is not available)
LOG_HISTORY = []
MAX_HISTORY = 1000

# Path to the audit log file
LOG_FILE = "audit.log"

def calculate_risk_level(event: Dict[str, Any]) -> str:
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

def log_event(event: Dict[str, Any]) -> None:
    """
    Log an event to the audit log (both file and database)
    
    Args:
        event: Dictionary containing event details
    """
    # Ensure timestamp is in ISO format
    if "timestamp" not in event:
        event["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Calculate risk level if not already provided
    if "risk_level" not in event:
        event["risk_level"] = calculate_risk_level(event)
    
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
        logger.error(f"Failed to write to audit log file: {str(e)}")
    
    # Also log to console for visibility
    logger.info(f"AUDIT: {json.dumps(event)}")
    
    # Store in database if app context is available
    try:
        if current_app:
            from models import db, AuditLog
            with current_app.app_context():
                # Create a new AuditLog entry
                log_entry = AuditLog(
                    timestamp=datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%SZ") if "timestamp" in event else datetime.utcnow(),
                    model_id=event.get("model_id", ""),
                    session_id=event.get("session_id", ""),
                    tool=event.get("tool", ""),
                    status=event.get("status", ""),
                    reason=event.get("reason"),
                    latency_ms=event.get("latency_ms"),
                    risk_level=event.get("risk_level", "low"),
                    input_data=event.get("input"),
                    output_data=event.get("output")
                )
                
                db.session.add(log_entry)
                db.session.commit()
                
                logger.debug(f"Audit log entry saved to database with ID: {log_entry.id}")
    except Exception as e:
        logger.error(f"Failed to save audit log to database: {str(e)}")

def get_recent_logs(count: int = 100) -> List[Dict[str, Any]]:
    """
    Get the most recent log entries from the database
    
    Args:
        count: Maximum number of entries to return
    
    Returns:
        List of log entries, most recent first
    """
    try:
        if current_app:
            from models import AuditLog
            with current_app.app_context():
                logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(count).all()
                return [log.to_dict() for log in logs]
    except Exception as e:
        logger.error(f"Failed to retrieve logs from database: {str(e)}")
        # Fall back to in-memory logs
        logger.warning("Falling back to in-memory logs")
    
    # If database retrieval failed or no app context, use in-memory logs
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
    try:
        if current_app:
            from models import AuditLog
            with current_app.app_context():
                logs = AuditLog.query.filter_by(session_id=session_id).order_by(AuditLog.timestamp.desc()).limit(count).all()
                return [log.to_dict() for log in logs]
    except Exception as e:
        logger.error(f"Failed to retrieve session logs from database: {str(e)}")
    
    # Fall back to in-memory logs
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
    try:
        if current_app:
            from models import AuditLog
            with current_app.app_context():
                logs = AuditLog.query.filter_by(model_id=model_id).order_by(AuditLog.timestamp.desc()).limit(count).all()
                return [log.to_dict() for log in logs]
    except Exception as e:
        logger.error(f"Failed to retrieve model logs from database: {str(e)}")
    
    # Fall back to in-memory logs
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
