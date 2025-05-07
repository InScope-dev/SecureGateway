"""
MCP-Sec Gateway - Core request handler
This module provides the main FastAPI router with endpoints for handling MCP traffic
"""
import time
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

from policy_engine import check_policy
from rate_limiter import check_limit, RateLimitError
from schema_validator import validate_input, validate_output, SchemaValidationError
from audit_logger import log_event

# Setup logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/mcp",
    tags=["mcp"],
)

# Models for request validation
class ToolCallRequest(BaseModel):
    model_id: str
    session_id: str
    tool_name: str
    input: Dict[str, Any]

class ToolResultRequest(BaseModel):
    model_id: str
    session_id: str
    tool_name: str
    output: Dict[str, Any]

class GatewayResponse(BaseModel):
    allowed: bool
    status: str = "success"
    reason: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    latency_ms: Optional[int] = None

# Tool call endpoint
@router.post("/toolcall", response_model=GatewayResponse)
async def tool_call(request: ToolCallRequest):
    """
    Process a tool call from an AI model
    
    This endpoint enforces policy checks, rate limits, and schema validation.
    """
    start_time = time.time()
    model_id = request.model_id
    session_id = request.session_id
    tool_name = request.tool_name
    input_data = request.input
    
    response = {
        "allowed": False,
        "status": "denied",
        "reason": None
    }
    
    try:
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
            return response
        
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
            return response
        
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
            return response
        
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
        return response
    
    except Exception as e:
        logger.error(f"Error processing tool call: {str(e)}")
        # Log the error
        log_event({
            "model_id": model_id,
            "session_id": session_id,
            "tool": tool_name,
            "input": input_data,
            "status": "error",
            "reason": f"Internal error: {str(e)}",
            "latency_ms": int((time.time() - start_time) * 1000)
        })
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Tool result endpoint
@router.post("/toolresult", response_model=GatewayResponse)
async def tool_result(request: ToolResultRequest):
    """
    Process a tool result from an external tool
    
    This endpoint validates the result schema and logs the output.
    """
    start_time = time.time()
    model_id = request.model_id
    session_id = request.session_id
    tool_name = request.tool_name
    output_data = request.output
    
    response = {
        "allowed": False,
        "status": "denied",
        "reason": None
    }
    
    try:
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
            return response
        
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
        return response
    
    except Exception as e:
        logger.error(f"Error processing tool result: {str(e)}")
        # Log the error
        log_event({
            "model_id": model_id,
            "session_id": session_id,
            "tool": tool_name,
            "output": output_data,
            "status": "error",
            "reason": f"Internal error: {str(e)}",
            "latency_ms": int((time.time() - start_time) * 1000)
        })
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
