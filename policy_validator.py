"""
MCP-Sec Policy Validator
Validates policy YAML files against JSON Schema definitions
"""
import json
import os
import sys
import logging
from typing import Dict, Any, Tuple, Optional

import yaml
import jsonschema

# Setup logger
logger = logging.getLogger(__name__)

def validate_policy(policy_path: str, schema_path: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a policy file against a JSON schema
    
    Args:
        policy_path: Path to the policy YAML file
        schema_path: Path to the JSON schema file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Load the schema
        with open(schema_path, 'r') as f:
            schema = json.load(f)
            
        # Load the policy
        with open(policy_path, 'r') as f:
            policy = yaml.safe_load(f)
            if policy is None:
                return False, f"Policy file {policy_path} is empty or has invalid YAML"
                
        # Validate the policy against the schema
        jsonschema.validate(instance=policy, schema=schema)
        return True, None
        
    except FileNotFoundError as e:
        return False, f"File not found: {str(e)}"
    except yaml.YAMLError as e:
        return False, f"YAML parsing error in {policy_path}: {str(e)}"
    except json.JSONDecodeError as e:
        return False, f"JSON parsing error in {schema_path}: {str(e)}"
    except jsonschema.ValidationError as e:
        return False, f"Policy validation error: {e.message}"
    except Exception as e:
        return False, f"Unexpected error validating policy: {str(e)}"

def validate_policies_on_startup() -> bool:
    """
    Validate all policy files on startup
    
    Returns:
        True if all policies are valid, False otherwise
    """
    policies_valid = True
    error_messages = []
    
    # Validate main policy
    if os.path.exists("policies.yaml"):
        is_valid, error = validate_policy("policies.yaml", "schemas/policy_schema.json")
        if not is_valid:
            policies_valid = False
            error_messages.append(f"Main policy (policies.yaml): {error}")
    else:
        logger.warning("Main policy file (policies.yaml) not found")
    
    # Validate contextual policy
    if os.path.exists("contextual_policy.yaml"):
        is_valid, error = validate_policy("contextual_policy.yaml", "schemas/contextual_policy_schema.json")
        if not is_valid:
            policies_valid = False
            error_messages.append(f"Contextual policy: {error}")
    
    # Validate shadow policy (if exists)
    if os.path.exists("contextual_policy.preview.yaml"):
        is_valid, error = validate_policy("contextual_policy.preview.yaml", "schemas/contextual_policy_schema.json")
        if not is_valid:
            policies_valid = False
            error_messages.append(f"Shadow policy: {error}")
    
    # Validate all project-specific policies
    if os.path.exists("policies"):
        policy_files = [f for f in os.listdir("policies") if f.endswith(".yaml")]
        for policy_file in policy_files:
            is_valid, error = validate_policy(f"policies/{policy_file}", "schemas/policy_schema.json")
            if not is_valid:
                policies_valid = False
                error_messages.append(f"Project policy {policy_file}: {error}")
    
    # Log results
    if policies_valid:
        logger.info("All policy files validated successfully")
    else:
        for error in error_messages:
            logger.error(error)
    
    return policies_valid

if __name__ == "__main__":
    # Setup logging for standalone use
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Run validation
    if not validate_policies_on_startup():
        sys.exit(1)  # Exit with error if policies are invalid
    sys.exit(0)  # Exit successfully if all policies are valid