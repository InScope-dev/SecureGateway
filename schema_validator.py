"""
MCP-Sec Schema Validator
Validates JSON payloads against JSON Schema definitions

Uses the tools_catalog module to access schemas and metadata
"""
import os
import json
import logging
import jsonschema
from typing import Dict, Any, Union, Optional

# Create a fallback catalog module
class FallbackCatalog:
    def load_schema(self, tool_name: str, schema_type: str) -> Optional[Dict[str, Any]]:
        return None
    
    def clear_cache(self) -> None:
        pass

# Set up catalog integration
catalog = FallbackCatalog()
USE_CATALOG = False

# Try to import tools catalog
try:
    from tools_catalog import catalog
    USE_CATALOG = True
except ImportError:
    # Module not available
    pass

# Setup logging
logger = logging.getLogger(__name__)

# Global schema cache for backward compatibility
SCHEMAS = {}

class SchemaValidationError(Exception):
    """Exception raised when a schema validation fails"""
    pass

def _load_schema(tool_name: str, schema_type: str = "input") -> Optional[Dict[str, Any]]:
    """
    Load JSON schema for a tool from file
    
    Args:
        tool_name: Name of the tool
        schema_type: Type of schema to load ('input' or 'output')
    
    Returns:
        Schema dict or None if not found
    """
    # Try to load from tools catalog first
    if USE_CATALOG:
        try:
            schema = catalog.load_schema(tool_name, schema_type)
            if schema:
                return schema
            # If not found, fall back to legacy method
        except Exception as e:
            logger.error(f"Error loading schema from catalog: {str(e)}")
    
    # Legacy schema loading from schemas directory
    # Generate cache key for this schema
    cache_key = f"{schema_type}.{tool_name}"
    
    # Check if schema is already in cache
    if cache_key in SCHEMAS:
        return SCHEMAS[cache_key]
    
    # Try to load schema from file
    schema_path = f"schemas/{schema_type}/{tool_name}.json"
    
    try:
        with open(schema_path, 'r') as f:
            schema = json.load(f)
        
        # Cache the schema
        SCHEMAS[cache_key] = schema
        return schema
    
    except FileNotFoundError:
        logger.warning(f"Schema file not found for tool: {tool_name}")
        return None
    
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing schema JSON for tool {tool_name}: {str(e)}")
        return None
    
    except Exception as e:
        logger.error(f"Unexpected error loading schema for tool {tool_name}: {str(e)}")
        return None

def validate_input(tool_name: str, payload: Dict[str, Any]) -> None:
    """
    Validate tool input against JSON schema
    
    Args:
        tool_name: Name of the tool
        payload: Input data to validate
    
    Raises:
        SchemaValidationError: If validation fails
    """
    schema = _load_schema(tool_name, "input")
    
    if not schema:
        raise SchemaValidationError(f"No schema found for tool: {tool_name}")
    
    try:
        jsonschema.validate(instance=payload, schema=schema)
    
    except jsonschema.ValidationError as e:
        error_path = '.'.join(str(p) for p in e.path)
        message = f"Input validation failed at {error_path}: {e.message}"
        logger.warning(message)
        raise SchemaValidationError(message)
    
    except Exception as e:
        logger.error(f"Unexpected error during input validation: {str(e)}")
        raise SchemaValidationError(f"Validation error: {str(e)}")

def validate_output(tool_name: str, payload: Dict[str, Any]) -> None:
    """
    Validate tool output against JSON schema
    
    Args:
        tool_name: Name of the tool
        payload: Output data to validate
    
    Raises:
        SchemaValidationError: If validation fails
    """
    schema = _load_schema(tool_name, "output")
    
    if not schema:
        raise SchemaValidationError(f"No schema found for tool: {tool_name}")
    
    try:
        jsonschema.validate(instance=payload, schema=schema)
    
    except jsonschema.ValidationError as e:
        error_path = '.'.join(str(p) for p in e.path)
        message = f"Output validation failed at {error_path}: {e.message}"
        logger.warning(message)
        raise SchemaValidationError(message)
    
    except Exception as e:
        logger.error(f"Unexpected error during output validation: {str(e)}")
        raise SchemaValidationError(f"Validation error: {str(e)}")

def reload_schemas() -> None:
    """Clear the schema cache to force reloading from disk"""
    global SCHEMAS
    SCHEMAS = {}
    
    # Clear catalog cache if using the tools catalog
    if USE_CATALOG:
        try:
            catalog.clear_cache()
            logger.info("Tools catalog cache cleared")
        except Exception as e:
            logger.error(f"Error clearing tools catalog cache: {str(e)}")
    
    logger.info("Schema cache cleared")

# Ensure schemas directory exists
os.makedirs("schemas", exist_ok=True)
