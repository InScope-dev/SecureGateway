"""
MCP-Sec Policy Engine
Loads and enforces security policies from policies.yaml file
and contextual policies from contextual_policy.yaml
Also validates model API keys from model_keys.yaml
"""
import os
import re
import yaml
import time
import logging
from datetime import datetime
from fnmatch import fnmatch
from typing import Dict, List, Tuple, Any, Optional

# Setup logging
logger = logging.getLogger(__name__)

# Global policy stores
POLICIES = {}
CONTEXTUAL_POLICIES = []

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

def load_contextual_policies(path="contextual_policy.yaml") -> List[Dict[str, Any]]:
    """
    Load contextual policies from YAML file
    
    Args:
        path: Path to contextual policy file
        
    Returns:
        List of contextual policy rules
    """
    try:
        with open(path, 'r') as f:
            policies = yaml.safe_load(f) or []
        
        if not isinstance(policies, list):
            logger.error("Invalid contextual policy structure: root must be a list")
            return []
        
        logger.info(f"Successfully loaded {len(policies)} contextual policy rules")
        return policies
        
    except FileNotFoundError:
        logger.error(f"Contextual policy file not found: {path}")
        return []
        
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML contextual policy file: {str(e)}")
        return []
        
    except Exception as e:
        logger.error(f"Unexpected error loading contextual policies: {str(e)}")
        return []

# Global model keys store
MODEL_KEYS = {}

def load_model_keys(path="model_keys.yaml") -> Dict[str, Any]:
    """
    Load model API keys and permissions from YAML file
    
    Args:
        path: Path to model keys file
        
    Returns:
        Dict containing model keys and permissions
    """
    try:
        with open(path, 'r') as f:
            keys_data = yaml.safe_load(f)
        
        if not isinstance(keys_data, dict) or "models" not in keys_data:
            logger.error("Invalid model keys structure: missing 'models' key")
            return {"models": {}}
        
        logger.info(f"Successfully loaded keys for {len(keys_data['models'])} models")
        return keys_data
    
    except FileNotFoundError:
        logger.error(f"Model keys file not found: {path}")
        return {"models": {}}
    
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML model keys file: {str(e)}")
        return {"models": {}}
    
    except Exception as e:
        logger.error(f"Unexpected error loading model keys: {str(e)}")
        return {"models": {}}

# Load policies at module import
POLICIES = load_policy()
CONTEXTUAL_POLICIES = load_contextual_policies()
MODEL_KEYS = load_model_keys()

def reload_policies() -> None:
    """
    Reload basic and contextual policies from YAML files
    """
    global POLICIES, CONTEXTUAL_POLICIES, MODEL_KEYS
    POLICIES = load_policy()
    CONTEXTUAL_POLICIES = load_contextual_policies()
    MODEL_KEYS = load_model_keys()
    logger.info("All policies and model keys reloaded")

def validate_model_key(model_id: str, provided_key: str, tool_name: str) -> Tuple[bool, str]:
    """
    Validate a model's API key and check if it has permission to use the specified tool
    
    Args:
        model_id: The ID of the model
        provided_key: The API key provided in the request
        tool_name: The name of the tool being called
    
    Returns:
        Tuple of (is_valid, reason)
    """
    try:
        # Check if model ID exists
        if model_id not in MODEL_KEYS.get("models", {}):
            return False, f"Unknown model: {model_id}"
        
        # Get model config
        model_config = MODEL_KEYS["models"][model_id]
        
        # Check if API key matches
        if not provided_key or model_config.get("key") != provided_key:
            return False, "Invalid model API key"
        
        # Check if API key has expired
        if "expires" in model_config:
            try:
                expiry_time = datetime.fromisoformat(model_config["expires"]).timestamp()
                if time.time() > expiry_time:
                    return False, f"API key expired on {model_config['expires']}"
            except (ValueError, TypeError) as e:
                logger.error(f"Error parsing expiry date: {e}")
                return False, "Invalid expiry date format in configuration"
        
        # Check if tool is allowed for this model
        tool_patterns = model_config.get("tools", [])
        if not any(fnmatch(tool_name, pattern) for pattern in tool_patterns):
            return False, f"Tool '{tool_name}' not in allowed scope for this model"
        
        # All checks passed
        return True, ""
        
    except Exception as e:
        logger.error(f"Error validating model key: {str(e)}")
        return False, f"Key validation error: {str(e)}"

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

def check_policy_contextual(model_id: str, tool_name: str, session_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if the tool call is allowed based on session context
    
    This performs advanced policy checks that consider the entire session history:
    - Prompt content
    - Prior denials
    - Tool usage sequence
    
    Args:
        model_id: The ID of the model
        tool_name: The name of the tool being called
        session_id: The ID of the current session
        context: Session context data
        
    Returns:
        Dict with keys: 'allowed' (bool) and optionally 'reason' (str)
    """
    # If no contextual rules are defined, allow by default (basic policy already checked)
    if not CONTEXTUAL_POLICIES:
        return {"allowed": True}
    
    prompt = context.get("prompt", "")
    calls = context.get("tool_calls", [])
    
    for rule in CONTEXTUAL_POLICIES:
        # Check if this rule applies to this tool
        when_tool = rule.get("when_tool", "")
        if when_tool and not re.fullmatch(when_tool, tool_name):
            continue
        
        # Block if prompt contains any forbidden phrases
        for phrase in rule.get("block_if_prompt_contains", []):
            if phrase.lower() in prompt.lower():
                return {"allowed": False, "reason": f"Prompt contains blocked phrase: '{phrase}'"}
        
        # Block if N or more previous denials in session
        if "block_if_previous_denials" in rule:
            max_denials = rule["block_if_previous_denials"]
            denials = sum(1 for c in calls if c.get("status") == "denied")
            if denials >= max_denials:
                return {"allowed": False, "reason": f"Too many prior denials in session ({denials})"}
        
        # Block if required prior tool not used successfully
        if "require_prior_successful_tool" in rule:
            required_tool = rule["require_prior_successful_tool"]
            found = any(c.get("tool") == required_tool and c.get("status") == "allowed" 
                       for c in calls)
            if not found:
                return {"allowed": False, "reason": f"Missing required prior tool: {required_tool}"}
    
    # All contextual rules passed
    return {"allowed": True}

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