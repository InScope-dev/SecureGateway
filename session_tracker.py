"""
MCP-Sec Session Tracker
Maintains session state including prompts and tool usage history
"""
import time
import logging

# Setup logging
logger = logging.getLogger(__name__)

# Global session state store
SESSION_STATE = {}

def init_session(session_id, model_id, prompt=""):
    """
    Initialize or reset a session
    
    Args:
        session_id: Unique identifier for the session
        model_id: The AI model being used
        prompt: Optional initial prompt text
    """
    SESSION_STATE[session_id] = {
        "model_id": model_id,
        "prompt": prompt,
        "tool_calls": [],
        "start_time": time.time()
    }
    logger.debug(f"Session {session_id} initialized for model {model_id}")

def update_tool_call(session_id, tool_name, input_data, status, output=None, reason=None):
    """
    Record a tool call in the session history
    
    Args:
        session_id: Session identifier
        tool_name: Name of the tool called
        input_data: Input parameters to the tool
        status: Status of the call (allowed, denied, error)
        output: Optional tool result
        reason: Optional reason for denial or error
    """
    if session_id not in SESSION_STATE:
        logger.warning(f"Attempt to update non-existent session: {session_id}")
        return
        
    SESSION_STATE[session_id]["tool_calls"].append({
        "tool": tool_name,
        "input": input_data,
        "output": output,
        "status": status,
        "reason": reason,
        "timestamp": time.time()
    })
    logger.debug(f"Session {session_id} updated: {tool_name} call with status {status}")

def get_context(session_id):
    """
    Get the full context for a session
    
    Args:
        session_id: Session identifier
    
    Returns:
        Dictionary with session state or empty dict if not found
    """
    return SESSION_STATE.get(session_id, {})

def cleanup_expired_sessions(max_age_hours=24):
    """
    Remove sessions older than max_age_hours
    
    Args:
        max_age_hours: Maximum session age in hours
    """
    now = time.time()
    expired_count = 0
    
    for session_id in list(SESSION_STATE.keys()):
        session_start = SESSION_STATE[session_id].get("start_time", 0)
        if now - session_start > max_age_hours * 3600:
            del SESSION_STATE[session_id]
            expired_count += 1
    
    if expired_count > 0:
        logger.info(f"Cleaned up {expired_count} expired sessions")