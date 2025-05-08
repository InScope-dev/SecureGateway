"""
MCP Tools Catalog
A catalog of MCP tool definitions, schemas, and metadata
"""

import os
import json
import yaml
import logging
from typing import Dict, List, Optional, Any

# Set up logging
logger = logging.getLogger(__name__)

# Define base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEMAS_DIR = os.path.join(BASE_DIR, "schemas")
METADATA_DIR = os.path.join(BASE_DIR, "metadata")

# Cache for tool definitions
_tool_schema_cache: Dict[str, Dict[str, Any]] = {}
_tool_metadata_cache: Dict[str, Dict[str, Any]] = {}


def load_schema(tool_name: str, schema_type: str = "input") -> Optional[Dict[str, Any]]:
    """
    Load a tool's JSON schema
    
    Args:
        tool_name: Name of the tool
        schema_type: Type of schema ('input' or 'output')
        
    Returns:
        Dict containing the schema or None if not found
    """
    cache_key = f"{tool_name}_{schema_type}"
    if cache_key in _tool_schema_cache:
        return _tool_schema_cache[cache_key]
    
    # Check for tool-specific schema
    schema_path = os.path.join(SCHEMAS_DIR, schema_type, f"{tool_name}.json")
    if os.path.exists(schema_path):
        try:
            with open(schema_path, 'r') as f:
                schema = json.load(f)
                _tool_schema_cache[cache_key] = schema
                return schema
        except Exception as e:
            logger.error(f"Error loading schema for {tool_name}: {str(e)}")
    
    # Check for wildcarded schemas (e.g., calendar.* -> calendar.json)
    base_name = tool_name.split('.')[0]
    if base_name != tool_name:
        wildcarded_path = os.path.join(SCHEMAS_DIR, schema_type, f"{base_name}.json")
        if os.path.exists(wildcarded_path):
            try:
                with open(wildcarded_path, 'r') as f:
                    schema = json.load(f)
                    _tool_schema_cache[cache_key] = schema
                    return schema
            except Exception as e:
                logger.error(f"Error loading wildcarded schema for {tool_name}: {str(e)}")
    
    # No schema found
    return None


def load_metadata(tool_name: str) -> Dict[str, Any]:
    """
    Load a tool's metadata
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Dict containing the metadata or default metadata if not found
    """
    if tool_name in _tool_metadata_cache:
        return _tool_metadata_cache[tool_name]
    
    # Default metadata
    default_metadata = {
        "name": tool_name,
        "description": f"Tool: {tool_name}",
        "risk_level": "medium",
        "risk_categories": ["unknown"],
        "permission_level": "standard",
        "required_api_key": False
    }
    
    # Check for tool-specific metadata
    metadata_path = os.path.join(METADATA_DIR, f"{tool_name}.yaml")
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r') as f:
                metadata = yaml.safe_load(f)
                _tool_metadata_cache[tool_name] = {**default_metadata, **metadata}
                return _tool_metadata_cache[tool_name]
        except Exception as e:
            logger.error(f"Error loading metadata for {tool_name}: {str(e)}")
    
    # Check for wildcarded metadata (e.g., calendar.* -> calendar.yaml)
    base_name = tool_name.split('.')[0]
    if base_name != tool_name:
        wildcarded_path = os.path.join(METADATA_DIR, f"{base_name}.yaml")
        if os.path.exists(wildcarded_path):
            try:
                with open(wildcarded_path, 'r') as f:
                    metadata = yaml.safe_load(f)
                    _tool_metadata_cache[tool_name] = {**default_metadata, **metadata}
                    return _tool_metadata_cache[tool_name]
            except Exception as e:
                logger.error(f"Error loading wildcarded metadata for {tool_name}: {str(e)}")
    
    # No metadata found, use default
    _tool_metadata_cache[tool_name] = default_metadata
    return default_metadata


def get_tool_risk_level(tool_name: str) -> str:
    """
    Get a tool's risk level
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Risk level as string ('low', 'medium', or 'high')
    """
    metadata = load_metadata(tool_name)
    return metadata.get("risk_level", "medium")


def get_tool_risk_categories(tool_name: str) -> List[str]:
    """
    Get a tool's risk categories
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        List of risk categories
    """
    metadata = load_metadata(tool_name)
    return metadata.get("risk_categories", ["unknown"])


def get_all_tools() -> List[Dict[str, Any]]:
    """
    Get all tools in the catalog
    
    Returns:
        List of tool metadata dictionaries
    """
    tools = []
    
    # Load tools from schema directories
    for schema_type in ["input", "output"]:
        schema_dir = os.path.join(SCHEMAS_DIR, schema_type)
        if os.path.exists(schema_dir):
            for filename in os.listdir(schema_dir):
                if filename.endswith(".json"):
                    tool_name = filename[:-5]  # Remove .json extension
                    tools.append(load_metadata(tool_name))
    
    # Load tools from metadata directory
    if os.path.exists(METADATA_DIR):
        for filename in os.listdir(METADATA_DIR):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                tool_name = filename.rsplit('.', 1)[0]  # Remove extension
                if not any(t["name"] == tool_name for t in tools):
                    tools.append(load_metadata(tool_name))
    
    return tools


def clear_cache() -> None:
    """
    Clear all caches
    """
    _tool_schema_cache.clear()
    _tool_metadata_cache.clear()