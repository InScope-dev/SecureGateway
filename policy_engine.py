"""
MCP-Sec Policy Engine
Loads and enforces security policies from policies/*.yaml files
and contextual policies from contextual_policy.yaml
Also validates model API keys from model_keys.yaml

Supports:
- Multi-project policies (policies/{project_id}.yaml)
- Policy versioning and rollbacks via history directory
- Contextual policy enforcement
- Per-model API key validation
"""
import os
import re
import yaml
import time
import shutil
import logging
import glob
from datetime import datetime
from fnmatch import fnmatch
from typing import Dict, List, Tuple, Any, Optional

# Setup logging
logger = logging.getLogger(__name__)

# Global policy stores
POLICIES = {}
CONTEXTUAL_POLICIES = []
MODEL_KEYS = {}

# Ensure directories exist
os.makedirs("history", exist_ok=True)
os.makedirs("policies", exist_ok=True)
os.makedirs("policies/default", exist_ok=True)

def backup_policy(path: str):
    """
    Create a timestamped backup of the policy file
    
    Args:
        path: Path to the policy file to backup
    """
    if not os.path.exists(path):
        return
        
    # Create backup with timestamp
    ts = int(time.time())
    backup_dir = "history"
    filename = os.path.basename(path)
    backup_path = f"{backup_dir}/{filename}.{ts}"
    
    try:
        shutil.copy(path, backup_path)
        logger.info(f"Created backup of {path} at {backup_path}")
    except Exception as e:
        logger.error(f"Failed to create backup: {str(e)}")

def get_policy_history() -> List[Dict[str, Any]]:
    """
    Get a list of all available policy backups
    
    Returns:
        List of dictionaries with 'timestamp' and 'path' keys
    """
    history = []
    
    # Find all policy backups
    for path in glob.glob("history/*.yaml.*"):
        try:
            # Extract timestamp from filename
            ts = int(path.split(".")[-1])
            dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            history.append({
                "timestamp": ts,
                "datetime": dt,
                "path": path,
                "filename": os.path.basename(path)
            })
        except (ValueError, IndexError):
            continue
    
    # Sort by timestamp (newest first)
    history.sort(key=lambda x: x["timestamp"], reverse=True)
    return history

def rollback_policy(timestamp: int) -> bool:
    """
    Rollback to a specific policy version
    
    Args:
        timestamp: Unix timestamp of the backup to restore
        
    Returns:
        True if successful, False otherwise
    """
    # Find the backup file
    backup_files = glob.glob(f"history/*.yaml.{timestamp}")
    if not backup_files:
        logger.error(f"No backup found with timestamp {timestamp}")
        return False
    
    try:
        # Extract the original filename from the backup
        backup_path = backup_files[0]
        original_filename = ".".join(os.path.basename(backup_path).split(".")[:-1])
        original_path = original_filename
        
        # Ensure we still have a backup of the current file
        backup_policy(original_path)
        
        # Restore from backup
        shutil.copy(backup_path, original_path)
        logger.info(f"Restored {original_path} from {backup_path}")
        
        # Reload policies
        reload_policies()
        return True
    except Exception as e:
        logger.error(f"Failed to rollback: {str(e)}")
        return False

def get_policy_path(project_id: str = "default") -> str:
    """
    Get the path to the policy file for a specific project
    
    Args:
        project_id: The project ID
        
    Returns:
        Path to the policy file
    """
    # First check for project-specific policy
    project_path = f"policies/{project_id}.yaml"
    if os.path.exists(project_path):
        return project_path
        
    # Then check for default policy locations
    if os.path.exists("policies.yaml"):
        return "policies.yaml"
    
    # Otherwise return the default project policy
    return "policies/default.yaml"

def load_policy(project_id: str = "default") -> Dict[str, Any]:
    """
    Load policies from YAML file for a specific project
    
    Args:
        project_id: The project ID
        
    Returns:
        The loaded policy
    """
    policy_path = get_policy_path(project_id)
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
    # If environment variable is set to bypass key checks (for development/testing)
    if os.environ.get("BYPASS_MODEL_KEY_CHECK"):
        logger.warning(f"Bypassing model key validation for {model_id} (BYPASS_MODEL_KEY_CHECK is set)")
        return True, ""
        
    # If provided_key is None, handle it properly
    if provided_key is None:
        logger.warning(f"Missing API key for model {model_id}")
        return False, f"API key is required for model {model_id}"
    
    try:
        # Check if model ID exists
        if model_id not in MODEL_KEYS.get("models", {}):
            logger.warning(f"Unknown model attempted access: {model_id}")
            return False, f"Unknown model: {model_id}"
        
        # Get model config
        model_config = MODEL_KEYS["models"][model_id]
        
        # Get expected key from the configuration
        expected_key = model_config.get("key")
        
        # Check if the expected key is properly configured
        if not expected_key:
            logger.error(f"Model {model_id} has no API key configured")
            return False, f"Configuration error: No API key configured for {model_id}"
        
        # Check if API key matches (using constant-time comparison to prevent timing attacks)
        import hmac
        if not hmac.compare_digest(str(expected_key), str(provided_key)):
            logger.warning(f"Invalid API key provided for model {model_id}")
            return False, "Invalid model API key"
        
        # Check if API key has expired
        if "expires" in model_config:
            try:
                expiry_time = datetime.fromisoformat(model_config["expires"]).timestamp()
                if time.time() > expiry_time:
                    logger.warning(f"Expired API key used for model {model_id}")
                    return False, f"API key expired on {model_config['expires']}"
            except (ValueError, TypeError) as e:
                logger.error(f"Error parsing expiry date for model {model_id}: {e}")
                return False, "Invalid expiry date format in configuration"
        
        # Check if tool is allowed for this model
        tool_patterns = model_config.get("tools", [])
        if not tool_patterns:
            logger.error(f"No tools configured for model {model_id}")
            return False, f"No tools configured for model {model_id}"
            
        if not any(fnmatch(tool_name, pattern) for pattern in tool_patterns):
            logger.warning(f"Tool '{tool_name}' access denied for model {model_id}")
            return False, f"Tool '{tool_name}' not in allowed scope for this model"
        
        # All checks passed
        logger.debug(f"API key validated successfully for {model_id} using tool {tool_name}")
        return True, ""
        
    except Exception as e:
        logger.error(f"Error validating model key: {str(e)}")
        return False, "Key validation error: Internal server error"

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
    - Session risk score
    
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
        if when_tool and not _match_pattern(tool_name, when_tool):
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
        
        # Check for call rate limits per session
        if "max_calls_per_session" in rule:
            max_calls = rule["max_calls_per_session"]
            matching_calls = sum(1 for c in calls if _match_pattern(c.get("tool", ""), when_tool))
            if matching_calls >= max_calls:
                return {"allowed": False, "reason": f"Exceeded maximum calls per session ({max_calls}) for this tool type"}
        
        # Check for call rate limits per minute
        if "max_calls_per_minute" in rule:
            max_calls = rule["max_calls_per_minute"]
            now = time.time()
            one_minute_ago = now - 60
            recent_matching_calls = sum(1 for c in calls if 
                                      _match_pattern(c.get("tool", ""), when_tool) and 
                                      c.get("timestamp", 0) >= one_minute_ago)
            if recent_matching_calls >= max_calls:
                return {"allowed": False, "reason": f"Rate limit exceeded: maximum {max_calls} calls per minute"}
        
        # Check session risk score if available
        if "block_if_session_risk_above" in rule:
            # Import here to avoid circular imports
            from session_tracker import score_session
            risk_threshold = rule["block_if_session_risk_above"]
            session_risk = score_session(session_id)
            if session_risk > risk_threshold:
                return {"allowed": False, "reason": f"Session risk score too high: {session_risk:.2f} > {risk_threshold}"}
    
    # All contextual rules passed
    return {"allowed": True}

def simulate_shadow_policy(model_id: str, tool_name: str, session_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulate policy decisions using shadow mode rules
    
    These rules are evaluated but not enforced, allowing for:
    - Testing new rules before enforcement
    - Collecting metrics on potential policy changes
    - Adaptive policy refinement
    - Identifying false positives/negatives
    
    Args:
        model_id: The ID of the model
        tool_name: The name of the tool being called
        session_id: The ID of the current session
        context: Session context data
        
    Returns:
        Dict with simulation results
    """
    # Load shadow policies from preview file
    try:
        with open("contextual_policy.preview.yaml", "r") as f:
            shadow_policies = yaml.safe_load(f)
            if shadow_policies is None:
                shadow_policies = []
    except Exception as e:
        logger.error(f"Error loading shadow policies: {str(e)}")
        return {"simulated": False, "error": str(e)}
    
    prompt = context.get("prompt", "")
    calls = context.get("tool_calls", [])
    results = {"simulated": True, "would_allow": True, "triggered_rules": []}
    
    for rule in shadow_policies:
        # Skip rules that don't apply to this tool
        when_tool = rule.get("when_tool", "")
        if when_tool and not _match_pattern(tool_name, when_tool):
            continue
        
        rule_name = rule.get("name", "Unnamed rule")
        triggered = False
        trigger_reason = ""
        
        # Check all the same conditions as in check_policy_contextual
        # Block if prompt contains any forbidden phrases
        for phrase in rule.get("block_if_prompt_contains", []):
            if phrase.lower() in prompt.lower():
                triggered = True
                trigger_reason = f"Prompt contains blocked phrase: '{phrase}'"
                break
        
        # Block if N or more previous denials in session
        if not triggered and "block_if_previous_denials" in rule:
            max_denials = rule["block_if_previous_denials"]
            denials = sum(1 for c in calls if c.get("status") == "denied")
            if denials >= max_denials:
                triggered = True
                trigger_reason = f"Too many prior denials in session ({denials})"
        
        # Block if required prior tool not used successfully
        if not triggered and "require_prior_successful_tool" in rule:
            required_tool = rule["require_prior_successful_tool"]
            found = any(c.get("tool") == required_tool and c.get("status") == "allowed" 
                       for c in calls)
            if not found:
                triggered = True
                trigger_reason = f"Missing required prior tool: {required_tool}"
        
        # Check for call rate limits per session
        if not triggered and "max_calls_per_session" in rule:
            max_calls = rule["max_calls_per_session"]
            matching_calls = sum(1 for c in calls if _match_pattern(c.get("tool", ""), when_tool))
            if matching_calls >= max_calls:
                triggered = True
                trigger_reason = f"Exceeded maximum calls per session ({max_calls}) for this tool type"
        
        # Check for call rate limits per minute
        if not triggered and "max_calls_per_minute" in rule:
            max_calls = rule["max_calls_per_minute"]
            now = time.time()
            one_minute_ago = now - 60
            recent_matching_calls = sum(1 for c in calls if 
                                      _match_pattern(c.get("tool", ""), when_tool) and 
                                      c.get("timestamp", 0) >= one_minute_ago)
            if recent_matching_calls >= max_calls:
                triggered = True
                trigger_reason = f"Rate limit exceeded: maximum {max_calls} calls per minute"
        
        # Check session risk score if available
        if not triggered and "block_if_session_risk_above" in rule:
            # Import here to avoid circular imports
            from session_tracker import score_session
            risk_threshold = rule["block_if_session_risk_above"]
            session_risk = score_session(session_id)
            if session_risk > risk_threshold:
                triggered = True
                trigger_reason = f"Session risk score too high: {session_risk:.2f} > {risk_threshold}"
        
        # Record triggered rules
        if triggered:
            results["would_allow"] = False
            results["triggered_rules"].append({
                "rule": rule_name,
                "reason": trigger_reason
            })
    
    return results

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
        
def is_model_permitted_to_propose(model_id: str) -> bool:
    """
    Check if a model is permitted to propose policy changes
    
    Args:
        model_id: The ID of the model
        
    Returns:
        True if the model is permitted to propose policy changes, False otherwise
    """
    if not model_id:
        return False
        
    model_config = MODEL_KEYS.get("models", {}).get(model_id, {})
    return model_config.get("can_propose", False)

def is_safe_policy(policy: Dict[str, Any]) -> bool:
    """
    Check if a proposed policy is safe to automatically approve
    
    This function implements guardrails to prevent dangerous changes like:
    - Adding highly privileged tools
    - Removing important restrictions
    - Changing security-critical settings
    
    Args:
        policy: The policy to check
        
    Returns:
        True if the policy is safe, False otherwise
    """
    # If there's no policy, it's not safe
    if not policy:
        return False
        
    # Check rules
    rules = policy.get("rules", [])
    
    # Extract all tool patterns that would be allowed
    all_tools = []
    for rule in rules:
        tools = rule.get("allow_tools", [])
        all_tools.extend(tools)
    
    # Check for dangerous patterns
    dangerous_patterns = [
        "db.write", "db.delete", "file.write", "file.delete", 
        "exec", "execute", "system", "shell", "admin", 
        "network.external", "ssh", "credential", "password",
        "auth.change", "security.bypass"
    ]
    
    # Check if any dangerous patterns are in the allowed tools
    for tool in all_tools:
        for pattern in dangerous_patterns:
            if pattern in tool:
                return False
    
    # Safe patterns that are always allowed to be proposed
    safe_patterns = [
        "search", "query", "read", "view", "calendar", "email.read",
        "calculate", "weather", "location.get", "translate"
    ]
    
    # If all tools match safe patterns, approve automatically
    all_safe = True
    for tool in all_tools:
        tool_is_safe = False
        for pattern in safe_patterns:
            if pattern in tool:
                tool_is_safe = True
                break
        if not tool_is_safe:
            all_safe = False
            break
    
    return all_safe

def sign_policy(yaml_str: str, key: Optional[str] = None) -> str:
    """
    Sign a policy YAML string
    
    Args:
        yaml_str: The YAML string to sign
        key: The key to use for signing. Defaults to ADMIN_KEY env variable
        
    Returns:
        The signature as a hexadecimal string
    """
    import hmac
    import hashlib
    
    signing_key = key if key is not None else os.environ.get("ADMIN_KEY", "supersecret")
        
    return hmac.new(signing_key.encode(), yaml_str.encode(), hashlib.sha256).hexdigest()
    
def merge_policy_yaml(target_path: str, new_policy: Dict[str, Any]) -> bool:
    """
    Merge a new policy into an existing policy file
    
    Args:
        target_path: Path to the existing policy file
        new_policy: The new policy to merge
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # First, make a backup
        backup_policy(target_path)
        
        # Read existing policy
        existing_policy = {}
        if os.path.exists(target_path):
            with open(target_path, "r") as f:
                existing_policy = yaml.safe_load(f) or {}
        
        # Merge the policies
        if "rules" in new_policy:
            if "rules" not in existing_policy:
                existing_policy["rules"] = []
            existing_policy["rules"].extend(new_policy["rules"])
        
        # Write merged policy
        with open(target_path, "w") as f:
            yaml.dump(existing_policy, f, default_flow_style=False)
            
        return True
    except Exception as e:
        logger.error(f"Error merging policy: {str(e)}")
        return False