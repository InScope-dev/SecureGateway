"""
MCP-Sec Policy Engine
Loads and enforces security policies from policies.yaml file
"""
import os
import re
import yaml
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional

# Setup logging
logger = logging.getLogger(__name__)

# Global policy store
POLICIES = {}

def load_policy() -> Dict[str, Any]:
    """
    Load policies from YAML file
    """
    policy_path = os.environ.get("POLICY_PATH", "policies.yaml")
    logger.info(f"Loading policies from {policy_path}")
    
    try:
        with open(policy_path, 'r') as f:
            policies = yaml.safe_load(f)
        
        # Basic validation of policy structure
        if not isinstance(policies, dict) or "rules" not in policies:
            logger.error("Invalid policy structure: missing 'rules' key")
            return {"rules": []}
        
        if not isinstance(policies["rules"], list):
            logger.error("Invalid policy structure: 'rules' must be a list")
            return {"rules": []}
        
        logger.info(f"Successfully loaded {len(policies['rules'])} policy rules")
        return policies
    
    except FileNotFoundError:
        logger.error(f"Policy file not found: {policy_path}")
        return {"rules": []}
    
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML policy file: {str(e)}")
        return {"rules": []}
    
    except Exception as e:
        logger.error(f"Unexpected error loading policies: {str(e)}")
        return {"rules": []}

# Load policies at module import
POLICIES = load_policy()

def reload_policies() -> None:
    """
    Reload policies from YAML file
    """
    global POLICIES
    POLICIES = load_policy()
    logger.info("Policies reloaded")

def check_policy(model_id: str, tool_name: str, session_id: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the given model is allowed to use the specified tool
    
    Args:
        model_id: The ID of the model
        tool_name: The name of the tool being called
        session_id: The ID of the current session
    
    Returns:
        Tuple of (allowed, reason)
    """
    # If no rules are defined, deny by default
    if not POLICIES or "rules" not in POLICIES or not POLICIES["rules"]:
        return False, "No policy rules defined"
    
    # Check each rule
    for rule in POLICIES["rules"]:
        # Check if this rule applies to this model (using wildcard matching)
        if not _match_pattern(model_id, rule.get("model", "")):
            continue
        
        # Check active hours
        active_hours = rule.get("active_hours")
        if active_hours and not _check_active_hours(active_hours):
            return False, f"Outside of active hours ({active_hours})"
        
        # Check if the tool is explicitly denied
        deny_tools = rule.get("deny_tools", [])
        for deny_pattern in deny_tools:
            if _match_pattern(tool_name, deny_pattern):
                return False, f"Tool {tool_name} is denied for model {model_id}"
        
        # Check if the tool is explicitly allowed
        allow_tools = rule.get("allow_tools", [])
        for allow_pattern in allow_tools:
            if _match_pattern(tool_name, allow_pattern):
                return True, None
        
        # If we have allow_tools but none matched, deny
        if allow_tools:
            return False, f"Tool {tool_name} is not in the allowed list for model {model_id}"
    
    # If no rule matched, deny by default
    return False, f"No policy rule matched for model {model_id} and tool {tool_name}"

def _match_pattern(value: str, pattern: str) -> bool:
    """
    Check if a value matches a pattern with wildcard support
    
    Args:
        value: The string to check
        pattern: The pattern to match against, with * as wildcard
    
    Returns:
        True if the value matches the pattern, False otherwise
    """
    # Convert wildcard pattern to regex
    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
    return bool(re.match(f"^{regex_pattern}$", value))

def _check_active_hours(active_hours: str) -> bool:
    """
    Check if the current time is within the active hours
    
    Args:
        active_hours: String in the format "HH:MM-HH:MM"
    
    Returns:
        True if current time is within active hours, False otherwise
    """
    try:
        start_str, end_str = active_hours.split("-")
        start_hour, start_minute = map(int, start_str.split(":"))
        end_hour, end_minute = map(int, end_str.split(":"))
        
        now = datetime.now()
        current_time = now.hour * 60 + now.minute  # Convert to minutes since midnight
        start_time = start_hour * 60 + start_minute
        end_time = end_hour * 60 + end_minute
        
        # Handle overnight ranges (e.g., "22:00-06:00")
        if end_time < start_time:
            return current_time >= start_time or current_time <= end_time
        else:
            return start_time <= current_time <= end_time
    
    except Exception as e:
        logger.error(f"Error parsing active hours '{active_hours}': {str(e)}")
        return False  # Fail closed
