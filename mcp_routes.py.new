"""
MCP-Sec Gateway - Core request handler for Flask
This module provides the routes for handling MCP traffic
"""
import time
import logging
from flask import Blueprint, request, jsonify

from policy_engine import check_policy
from rate_limiter import check_limit, RateLimitError
from schema_validator import validate_input, validate_output, SchemaValidationError
from audit_logger import log_event

# Setup logging
logger = logging.getLogger(__name__)

# Create the blueprint
mcp_bp = Blueprint("mcp", __name__)

@mcp_bp.route("/mcp/toolcall", methods=["POST"])
def tool_call():
    """
    Process a tool call from an AI model
    
    This endpoint enforces policy checks, rate limits, and schema validation.
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "allowed": False,
                "status": "error",
                "reason": "Invalid JSON body"
            }), 400
            
        # Validate required fields
        for field in ["model_id", "session_id", "tool_name", "input"]:
            if field not in data:
                return jsonify({
                    "allowed": False,
                    "status": "error",
                    "reason": f"Missing required field: {field}"
                }), 400
        
        model_id = data["model_id"]
        session_id = data["session_id"]
        tool_name = data["tool_name"]
        input_data = data["input"]
        
        response = {
            "allowed": False,
            "status": "denied",
            "reason": None
        }
        
        # Check policy
        allowed, reason = check_policy(model_id, tool_name, session_id)
        if not allowed:
            response["reason"] = reason
            # Log the denied event
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": reason,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            return jsonify(response)
        
        # Check rate limits
        try:
            check_limit(model_id, session_id)
        except RateLimitError as e:
            response["reason"] = str(e)
            # Log the rate-limited event
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": str(e),
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            return jsonify(response)
        
        # Validate schema
        try:
            validate_input(tool_name, input_data)
        except SchemaValidationError as e:
            response["reason"] = f"Schema validation error: {str(e)}"
            # Log the validation error
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": f"Schema validation error: {str(e)}",
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            return jsonify(response)
        
        # If we've made it this far, the request is allowed
        response["allowed"] = True
        response["status"] = "allowed"
        
        # Log the allowed event
        latency_ms = int((time.time() - start_time) * 1000)
        log_event({
            "model_id": model_id,
            "session_id": session_id,
            "tool": tool_name,
            "input": input_data,
            "status": "allowed",
            "latency_ms": latency_ms
        })
        
        response["latency_ms"] = latency_ms
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error processing tool call: {str(e)}")
        # Log the error
        try:
            error_data = {
                "model_id": "unknown",
                "session_id": "unknown",
                "tool": "unknown",
                "input": {},
                "status": "error",
                "reason": f"Internal error: {str(e)}",
                "latency_ms": int((time.time() - start_time) * 1000)
            }
            
            # Try to get data from request if available
            try:
                req_data = request.get_json()
                if req_data:
                    error_data["model_id"] = req_data.get("model_id", "unknown")
                    error_data["session_id"] = req_data.get("session_id", "unknown")
                    error_data["tool"] = req_data.get("tool_name", "unknown")
                    error_data["input"] = req_data.get("input", {})
            except:
                # If we can't get JSON data, continue with defaults
                pass
                
            log_event(error_data)
        except:
            # If logging fails too, just continue
            pass
        return jsonify({
            "allowed": False,
            "status": "error",
            "reason": f"Internal server error: {str(e)}"
        }), 500

@mcp_bp.route("/mcp/toolresult", methods=["POST"])
def tool_result():
    """
    Process a tool result from an external tool
    
    This endpoint validates the result schema and logs the output.
    """
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "allowed": False,
                "status": "error",
                "reason": "Invalid JSON body"
            }), 400
            
        # Validate required fields
        for field in ["model_id", "session_id", "tool_name", "output"]:
            if field not in data:
                return jsonify({
                    "allowed": False,
                    "status": "error",
                    "reason": f"Missing required field: {field}"
                }), 400
        
        model_id = data["model_id"]
        session_id = data["session_id"]
        tool_name = data["tool_name"]
        output_data = data["output"]
        
        response = {
            "allowed": False,
            "status": "denied",
            "reason": None
        }
        
        # Validate output schema
        try:
            validate_output(tool_name, output_data)
        except SchemaValidationError as e:
            response["reason"] = f"Schema validation error: {str(e)}"
            # Log the validation error
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "output": output_data,
                "status": "denied",
                "reason": f"Schema validation error: {str(e)}",
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            return jsonify(response)
        
        # If we've made it this far, the result is allowed
        response["allowed"] = True
        response["status"] = "allowed"
        response["result"] = output_data
        
        # Log the allowed event
        latency_ms = int((time.time() - start_time) * 1000)
        log_event({
            "model_id": model_id,
            "session_id": session_id,
            "tool": tool_name,
            "output": output_data,
            "status": "allowed",
            "latency_ms": latency_ms
        })
        
        response["latency_ms"] = latency_ms
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error processing tool result: {str(e)}")
        # Log the error
        try:
            error_data = {
                "model_id": "unknown",
                "session_id": "unknown",
                "tool": "unknown",
                "output": {},
                "status": "error",
                "reason": f"Internal error: {str(e)}",
                "latency_ms": int((time.time() - start_time) * 1000)
            }
            
            # Try to get data from request if available
            try:
                req_data = request.get_json()
                if req_data:
                    error_data["model_id"] = req_data.get("model_id", "unknown")
                    error_data["session_id"] = req_data.get("session_id", "unknown")
                    error_data["tool"] = req_data.get("tool_name", "unknown")
                    error_data["output"] = req_data.get("output", {})
            except:
                # If we can't get JSON data, continue with defaults
                pass
                
            log_event(error_data)
        except:
            # If logging fails too, just continue
            pass
        return jsonify({
            "allowed": False,
            "status": "error",
            "reason": f"Internal server error: {str(e)}"
        }), 500