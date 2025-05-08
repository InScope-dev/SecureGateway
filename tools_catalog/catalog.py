"""
Tools Catalog Module

This module provides access to standardized tool definitions and metadata.
It serves as a central repository for all MCP tool schemas.
"""
import os
import json
from typing import Dict, List, Any, Optional

# Cache for loaded schemas and metadata
_schema_cache = {}
_metadata_cache = {}
_tools_list = None

def get_all_tools() -> List[str]:
    """
    Get a list of all available tools
    
    Returns:
        List of tool names
    """
    global _tools_list
    
    if _tools_list is not None:
        return _tools_list
    
    # Read from the tools directory
    tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
    
    if not os.path.exists(tools_dir):
        return []
    
    # Get all JSON files
    _tools_list = []
    for filename in os.listdir(tools_dir):
        if filename.endswith(".json"):
            _tools_list.append(filename.replace(".json", ""))
    
    return _tools_list

def get_tool_schema(tool_name: str, schema_type: str = "input") -> Optional[Dict[str, Any]]:
    """
    Get the JSON schema for a tool
    
    Args:
        tool_name: Name of the tool
        schema_type: Type of schema to get (input or output)
        
    Returns:
        Schema definition or None if not found
    """
    cache_key = f"{tool_name}_{schema_type}"
    
    # Check cache first
    if cache_key in _schema_cache:
        return _schema_cache[cache_key]
    
    # Look for the schema file
    tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
    schema_path = os.path.join(tools_dir, f"{tool_name}.json")
    
    if not os.path.exists(schema_path):
        return None
    
    # Load the schema
    try:
        with open(schema_path, 'r') as f:
            schema = json.load(f)
            
        # For output schemas, we need to look for output definitions
        if schema_type == "output" and "output" in schema:
            result = schema["output"]
        else:
            # For input schemas, we use the main schema
            result = schema
            
        # Cache and return
        _schema_cache[cache_key] = result
        return result
    except Exception as e:
        print(f"Error loading schema for {tool_name}: {e}")
        return None

def get_tool_metadata(tool_name: str) -> Optional[Dict[str, Any]]:
    """
    Get metadata for a tool
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Tool metadata or None if not found
    """
    # Check cache first
    if tool_name in _metadata_cache:
        return _metadata_cache[tool_name]
    
    # Get the schema to extract metadata
    schema = get_tool_schema(tool_name)
    if not schema:
        return None
    
    # Extract metadata or use defaults
    metadata = {
        "name": tool_name,
        "description": schema.get("description", f"Schema for {tool_name}"),
        "version": schema.get("version", "1.0"),
        "category": get_tool_categories(tool_name)[0],
        "risk_level": get_tool_risk_level(tool_name)
    }
    
    # Cache and return
    _metadata_cache[tool_name] = metadata
    return metadata

def get_tool_risk_level(tool_name: str) -> str:
    """
    Determine the risk level for a tool
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Risk level: 'high', 'medium', or 'low'
    """
    # High risk patterns
    high_risk_patterns = [
        "file", "exec", "admin", "delete", "rm", "remove", 
        "system", "command", "shell", "sudo", "root"
    ]
    
    # Medium risk patterns
    medium_risk_patterns = [
        "write", "update", "modify", "create", "insert", 
        "database", "db", "sql", "credential"
    ]
    
    # Check for high risk patterns
    for pattern in high_risk_patterns:
        if pattern in tool_name.lower():
            return "high"
    
    # Check for medium risk patterns
    for pattern in medium_risk_patterns:
        if pattern in tool_name.lower():
            return "medium"
    
    # Default to low risk
    return "low"

def get_tool_categories(tool_name: str) -> List[str]:
    """
    Determine categories for a tool based on name patterns
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        List of category strings
    """
    # Define category patterns
    categories = {
        "file_system": ["file", "directory", "folder", "path"],
        "network": ["http", "url", "web", "fetch", "api"],
        "database": ["db", "sql", "query", "database"],
        "email": ["email", "mail", "smtp"],
        "calendar": ["calendar", "event", "schedule"],
        "system": ["exec", "system", "command", "shell"],
        "auth": ["auth", "login", "credential", "token"]
    }
    
    # Find matching categories
    matching_categories = []
    for category, patterns in categories.items():
        for pattern in patterns:
            if pattern in tool_name.lower():
                matching_categories.append(category)
                break
    
    # Default to "utility" if no categories match
    if not matching_categories:
        return ["utility"]
    
    return matching_categories

def clear_cache():
    """Clear all caches"""
    global _schema_cache, _metadata_cache, _tools_list
    _schema_cache = {}
    _metadata_cache = {}
    _tools_list = None
