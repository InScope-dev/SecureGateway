"""
MCP-Sec Session Tracker
Maintains session state including prompts and tool usage history
- Phase 5 enhancement: Risk scoring for sessions
- Phase 5 enhancement: Security impact assessment for tools
- Phase 6 enhancement: Integration with tools catalog for standardized risk assessment
"""
import time
import logging
import re
from collections import Counter
from fnmatch import fnmatch
from typing import Dict, Any, List, Optional

# Setup logging
logger = logging.getLogger(__name__)

# Create fallback catalog module
class FallbackToolCatalog:
    def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
        return None
    
    def get_tool_risk_level(self, tool_name: str) -> str:
        return "unknown"
    
    def get_tool_categories(self, tool_name: str) -> List[str]:
        return []

# Setup tools catalog integration
tool_catalog = FallbackToolCatalog()
USE_CATALOG = False

# Try to import tools catalog
try:
    # Assuming the metadata module would have similar interface
    # as our fallback catalog, adjust import path as needed
    from tools_catalog.catalog import get_tool_metadata, get_tool_risk_level, get_tool_categories
    
    # Create an adapter to use catalog functions
    class CatalogAdapter:
        def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
            return get_tool_metadata(tool_name)
        
        def get_tool_risk_level(self, tool_name: str) -> str:
            return get_tool_risk_level(tool_name)
        
        def get_tool_categories(self, tool_name: str) -> List[str]:
            return get_tool_categories(tool_name)
    
    tool_catalog = CatalogAdapter()
    USE_CATALOG = True
    logger.info("Tools catalog integration enabled")
except ImportError:
    logger.warning("Tools catalog not available, using pattern-based classification")
    pass

# Global session state store
SESSION_STATE = {}

# Tool risk categories for security impact assessment
TOOL_RISK_CATEGORIES = {
    "system": [
        "system.*",
        "shell.*",
        "os.*",
        "exec.*",
        "*.exec*", 
        "*.run*", 
        "*.system*", 
        "*.command*", 
        "*.shell*"
    ],
    "write": [
        "*.write*",
        "*.create*",
        "*.update*",
        "*.delete*",
        "*.remove*",
        "*.insert*",
        "db.*",
        "file.write",
        "document.edit"
    ],
    "read": [
        "*.read*", 
        "*.get*", 
        "*.list*", 
        "*.search*", 
        "*.find*"
    ],
    "identity": [
        "auth.*",
        "login.*",
        "user.*",
        "identity.*",
        "password.*",
        "credential.*",
        "*.auth*", 
        "*.login*", 
        "*.credential*", 
        "*.token*", 
        "*.key*"
    ],
    "network": [
        "http.*",
        "api.*",
        "request.*",
        "fetch.*",
        "url.*",
        "external.*",
        "*.http*", 
        "*.connect*", 
        "*.url*", 
        "*.download*", 
        "*.upload*"
    ],
    "data": [
        "database.*",
        "query.*",
        "*.query",
        "sql.*",
        "search.*",
        "*.search"
    ],
    "low_risk": [
        "math.*",
        "convert.*",
        "time.*",
        "date.*",
        "format.*"
    ]
}

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

def classify_tool(tool_name):
    """
    Classify a tool into risk categories
    
    Tries to use the tools catalog first for accurate classification,
    then falls back to pattern-based classification if catalog is not available
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        List of risk categories the tool belongs to
    """
    # Try to use tools catalog first
    if USE_CATALOG:
        try:
            # Get categories from catalog
            catalog_categories = tool_catalog.get_tool_categories(tool_name)
            if catalog_categories:
                return catalog_categories
        except Exception as e:
            logger.error(f"Error getting tool categories from catalog: {str(e)}")
    
    # Fall back to pattern-based classification
    categories = []
    for category, patterns in TOOL_RISK_CATEGORIES.items():
        for pattern in patterns:
            if fnmatch(tool_name, pattern):
                categories.append(category)
                break
    
    return categories

def score_session(session_id):
    """
    Calculate a risk score for a session based on its history
    
    The score is a value between 0.0 (low risk) and 1.0 (high risk)
    based on factors such as:
    - Number of tool calls
    - Tool types and risk categories
    - Denied call ratio
    - Sensitive operations
    - Tool call sequence patterns
    
    Args:
        session_id: Session identifier
        
    Returns:
        Risk score as a float between 0.0 and 1.0
    """
    ctx = get_context(session_id)
    if not ctx or not ctx.get("tool_calls"):
        return 0.0
    
    score = 0.0
    tool_calls = ctx["tool_calls"]
    
    # Factor 1: Number of calls (volume)
    call_count = len(tool_calls)
    if call_count > 20:
        score += 0.15
    elif call_count > 10:
        score += 0.1
    elif call_count > 5:
        score += 0.05
    
    # Factor 2: Denied calls ratio
    denied_calls = sum(1 for c in tool_calls if c.get("status") == "denied")
    if call_count > 0:
        denied_ratio = denied_calls / call_count
        if denied_ratio > 0.5:
            score += 0.3
        elif denied_ratio > 0.25:
            score += 0.2
        elif denied_ratio > 0.1:
            score += 0.1
    
    # Factor 3: High-risk tool categories
    category_counts = Counter()
    for call in tool_calls:
        tool_name = call.get("tool", "")
        categories = classify_tool(tool_name)
        category_counts.update(categories)
    
    # Apply risk weights for categories
    if category_counts["system"] > 0:
        score += 0.25
    if category_counts["write"] > 3:
        score += 0.15
    elif category_counts["write"] > 0:
        score += 0.1
    if category_counts["identity"] > 0:
        score += 0.2
    
    # Factor 4: Sensitive keywords in prompt
    prompt = ctx.get("prompt", "").lower()
    sensitive_terms = ["password", "key", "secret", "token", "credential", "auth", "admin"]
    matches = sum(1 for term in sensitive_terms if term in prompt)
    if matches > 2:
        score += 0.15
    elif matches > 0:
        score += 0.05
    
    # Factor 5: Rapid succession of calls (high velocity)
    if len(tool_calls) >= 2:
        timestamps = [call.get("timestamp", 0) for call in tool_calls]
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        # Check if there are multiple calls within a short time
        rapid_calls = sum(1 for interval in intervals if interval < 1.0)  # Less than 1 second
        if rapid_calls > 3:
            score += 0.15
        elif rapid_calls > 1:
            score += 0.05
    
    # Cap the score at 1.0
    return min(score, 1.0)

def get_session_stats(session_id):
    """
    Get comprehensive statistics about a session
    
    Args:
        session_id: Session identifier
        
    Returns:
        Dictionary with various session statistics
    """
    ctx = get_context(session_id)
    if not ctx:
        return {"error": "Session not found"}
    
    tool_calls = ctx.get("tool_calls", [])
    
    # Calculate basic stats
    total_calls = len(tool_calls)
    allowed_calls = sum(1 for c in tool_calls if c.get("status") == "allowed")
    denied_calls = sum(1 for c in tool_calls if c.get("status") == "denied")
    error_calls = sum(1 for c in tool_calls if c.get("status") == "error")
    
    # Tool category analysis
    tool_categories = {}
    for call in tool_calls:
        tool_name = call.get("tool", "")
        categories = classify_tool(tool_name)
        for category in categories:
            if category not in tool_categories:
                tool_categories[category] = 0
            tool_categories[category] += 1
    
    # Most common tools
    tool_counts = Counter(call.get("tool", "") for call in tool_calls)
    top_tools = tool_counts.most_common(5)
    
    # Session duration
    start_time = ctx.get("start_time", 0)
    last_time = max([call.get("timestamp", start_time) for call in tool_calls]) if tool_calls else start_time
    duration_seconds = last_time - start_time
    
    return {
        "session_id": session_id,
        "model_id": ctx.get("model_id", "unknown"),
        "start_time": start_time,
        "duration_seconds": duration_seconds,
        "prompt_length": len(ctx.get("prompt", "")),
        "total_calls": total_calls,
        "allowed_calls": allowed_calls,
        "denied_calls": denied_calls,
        "error_calls": error_calls,
        "denied_ratio": denied_calls / total_calls if total_calls > 0 else 0,
        "tool_categories": tool_categories,
        "top_tools": top_tools,
        "risk_score": score_session(session_id)
    }