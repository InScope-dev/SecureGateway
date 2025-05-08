"""
MCP-Sec Gateway - Core request handler for Flask
This module provides the routes for handling MCP traffic

- Phase 4 enhancement: Federation support for forwarding requests to trusted peer gateways
- Phase 5 enhancement: Shadow mode policy simulation and session risk scoring
"""
import time
import os
import uuid
import yaml
import logging
import requests
from flask import Blueprint, request, jsonify
from fnmatch import fnmatch
from typing import Dict, Any, Tuple, Optional

import policy_engine
from policy_engine import check_policy, check_policy_contextual, validate_model_key, simulate_shadow_policy
from rate_limiter import check_limit, RateLimitError
from schema_validator import validate_input, validate_output, SchemaValidationError
from audit_logger import log_event
from session_tracker import init_session, update_tool_call, get_context, score_session

# Set up logger
logger = logging.getLogger(__name__)

# Configure tool server URL - default to internal mock endpoints
TOOL_SERVER_URL = os.getenv("TOOL_SERVER_URL", None)

def load_trusted_peers() -> Dict[str, Dict[str, str]]:
    """
    Load trusted peer gateways from configuration file
    
    Returns:
        Dictionary of peer configurations
    """
    try:
        with open("trusted_peers.yaml", "r") as f:
            config = yaml.safe_load(f)
            if not config or "peers" not in config:
                logger.warning("No trusted peers found in configuration")
                return {}
            return config["peers"]
    except FileNotFoundError:
        logger.warning("trusted_peers.yaml not found")
        return {}
    except Exception as e:
        logger.error(f"Error loading trusted peers: {str(e)}")
        return {}

def forward_toolcall(peer_id: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """
    Forward a tool call to a trusted peer gateway
    
    Args:
        peer_id: ID of the peer gateway
        payload: Request payload to forward
        
    Returns:
        Tuple of (status_code, response_json)
    """
    peers = load_trusted_peers()
    if peer_id not in peers:
        logger.error(f"Attempted to forward to unknown peer: {peer_id}")
        return 404, {"status": "error", "reason": f"Unknown peer: {peer_id}"}
    
    peer = peers[peer_id]
    trace_id = str(uuid.uuid4())
    headers = {
        "X-Gateway-Key": peer["key"],
        "X-Trace-Id": payload.get("trace_id", trace_id),
        "Content-Type": "application/json"
    }
    
    try:
        logger.info(f"Forwarding request to peer {peer_id} at {peer['url']}")
        res = requests.post(
            peer["url"],
            json=payload,
            headers=headers,
            timeout=10  # Longer timeout for inter-gateway communication
        )
        return res.status_code, res.json()
    except requests.RequestException as e:
        logger.error(f"Error forwarding to peer {peer_id}: {str(e)}")
        return 500, {"status": "error", "reason": f"Forward error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in forward: {str(e)}")
        return 500, {"status": "error", "reason": "Internal forward error"}

def call_tool_api(tool_name, payload):
    """Call external tool service if allowed."""
    # For testing: if TOOL_SERVER_URL is not set, use internal mock implementations
    if not TOOL_SERVER_URL:
        return _mock_tool_response(tool_name, payload)
        
    # Otherwise use the external tool server
    endpoint = f"{TOOL_SERVER_URL}/{tool_name}"
    res = requests.post(endpoint, json=payload, timeout=5)
    if not res.ok:
        raise Exception(f"Tool {tool_name} error: {res.status_code} {res.text}")
    return res.json()

def _mock_tool_response(tool_name, payload):
    """Mock implementations of tools for testing"""
    # Add extra logging to track what's happening
    logger.debug(f"Mock tool response for {tool_name}")
    logger.debug(f"Payload: {payload}")
    
    # Make sure payload is a dictionary
    if not isinstance(payload, dict):
        logger.error(f"Payload is not a dictionary: {payload}")
        payload = {} if payload is None else {"input": str(payload)}
        
    # Calendar create event mock
    if tool_name == "calendar.create_event":
        title = payload.get("title", "Untitled")
        start_time = payload.get("start_time", "2025-01-01T00:00:00Z")
        return {
            "status": "ok",
            "id": "ev-" + title.lower().replace(" ", "-"),
            "status": "confirmed",
            "calendar_link": f"https://calendar.example.com/events/ev-{title.lower().replace(' ', '-')}"
        }
    # DB write mock - always denied for sensitive DB
    elif tool_name == "db.write_sensitive":
        raise Exception("Write to sensitive DB denied")
    # Search query mock
    elif tool_name == "search.query" or tool_name == "search.web":
        query = payload.get("q", "")
        return {
            "results": ["result 1", "result 2"],
            "query": query
        }
    # Default fallback for other tools
    else:
        return {
            "status": "ok",
            "tool": tool_name,
            "mock": True,
            "input": payload
        }

# Use the logger already defined above

# Create the blueprint
mcp_bp = Blueprint("mcp", __name__)

@mcp_bp.route("/mcp/prompt", methods=["POST"])
def prompt():
    """
    Process a prompt from an AI model and initialize the session
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "status": "error",
                "reason": "Invalid JSON body"
            }), 400
            
        # Validate required fields
        for field in ["model_id", "session_id", "prompt"]:
            if field not in data:
                return jsonify({
                    "status": "error",
                    "reason": f"Missing required field: {field}"
                }), 400
        
        model_id = data["model_id"]
        session_id = data["session_id"]
        prompt_text = data["prompt"]
        
        # Validate model API key - less strict for prompt endpoint
        # but still verify the model exists if API key validation is enabled
        bypass_check = os.environ.get("BYPASS_MODEL_KEY_CHECK") == "true"
        if not bypass_check:
            model_key = request.headers.get("X-Model-Key")
            
            # Only verify model exists and key if provided
            if model_key:
                is_valid, reason = validate_model_key(model_id, model_key, "prompt")
                if not is_valid:
                    logger.warning(f"Invalid model API key for prompt: {reason}")
                    return jsonify({
                        "status": "error",
                        "reason": f"Invalid model API key: {reason}"
                    }), 401
            elif model_id not in policy_engine.MODEL_KEYS.get("models", {}):
                logger.warning(f"Unknown model attempted access: {model_id}")
                return jsonify({
                    "status": "error",
                    "reason": f"Unknown model: {model_id}"
                }), 401
        
        # Initialize session
        init_session(session_id, model_id, prompt_text)
        
        # Log the prompt event
        log_event({
            "model_id": model_id,
            "session_id": session_id,
            "event_type": "prompt",
            "prompt": prompt_text[:200] + "..." if len(prompt_text) > 200 else prompt_text,
            "status": "recorded"
        })
        
        return jsonify({"status": "recorded"})
        
    except Exception as e:
        logger.error(f"Error processing prompt: {str(e)}")
        return jsonify({
            "status": "error",
            "reason": f"Internal server error: {str(e)}"
        }), 500

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
        
        # Validate model API key
        model_key = request.headers.get("X-Model-Key")
        
        # Special case for testing - if BYPASS_MODEL_KEY_CHECK is set, skip validation
        bypass_check = os.environ.get("BYPASS_MODEL_KEY_CHECK") == "true"
        if not bypass_check:
            # If key is missing completely, return 401
            if model_key is None:
                reason = f"Missing model API key for {model_id}"
                response["reason"] = reason
                
                # Log the denied event with appropriate details
                log_event({
                    "model_id": model_id,
                    "session_id": session_id,
                    "tool": tool_name,
                    "input": input_data,
                    "status": "denied",
                    "reason": reason,
                    "latency_ms": int((time.time() - start_time) * 1000)
                })
                
                # Update session tracker
                update_tool_call(session_id, tool_name, input_data, "denied", reason=reason)
                return jsonify(response), 401
            
            # Validate the key that was provided
            is_valid, reason = validate_model_key(model_id, model_key, tool_name)
            if not is_valid:
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
                # Update session tracker
                update_tool_call(session_id, tool_name, input_data, "denied", reason=reason)
                return jsonify(response), 401
        
        # Get session context for contextual policy checks
        context = get_context(session_id)
        if not context:
            # Initialize session if it doesn't exist
            init_session(session_id, model_id)
            context = get_context(session_id)
        
        # 1. Basic policy check
        allowed, reason = check_policy(model_id, tool_name, session_id)
        if not allowed:
            response["reason"] = reason
            
            # Add explanations and reasoning for denial
            reasoning = []
            rule_trace = []
            
            # Basic policy denial details
            reason_text = reason or ""  # Handle None case
            if "not allowed" in reason_text:
                reasoning.append(f"Model {model_id} is not permitted to use {tool_name}")
                rule_trace.append("check_tool_whitelist")
            elif "inactive hours" in reason_text:
                reasoning.append(f"Tool {tool_name} is only available during specific hours")
                rule_trace.append("check_active_hours")
            else:
                reasoning.append(reason_text)
                rule_trace.append("basic_policy_check")
                
            response["reasoning"] = reasoning
            response["rule_trace"] = rule_trace
            
            # Log the denied event with reasoning
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": reason,
                "reasoning": reasoning,
                "rule_trace": rule_trace,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            # Update session tracker
            update_tool_call(session_id, tool_name, input_data, "denied", reason=reason)
            return jsonify(response)
        
        # 2. Contextual policy check (only if basic check passed)
        contextual_decision = check_policy_contextual(model_id, tool_name, session_id, context)
        if not contextual_decision.get("allowed", True):
            reason = contextual_decision.get("reason", "Denied by contextual policy")
            response["reason"] = reason
            
            # Add explanations and reasoning for contextual denial
            reasoning = []
            rule_trace = []
            
            # Get detailed reasoning if available
            detailed_reasoning = contextual_decision.get("reasoning", [])
            detailed_rule_trace = contextual_decision.get("rule_trace", [])
            
            # If detailed reasoning is provided, use it
            if detailed_reasoning and detailed_rule_trace:
                reasoning = detailed_reasoning
                rule_trace = detailed_rule_trace
            else:
                # Otherwise generate generic explanations based on reason text
                reason_text = reason or ""  # Handle None case
                if "suspicious pattern" in reason_text:
                    reasoning.append("Detected suspicious sequence of tool usage")
                    rule_trace.append("check_suspicious_patterns")
                elif "risk score" in reason_text:
                    reasoning.append(f"Session risk score exceeded threshold")
                    rule_trace.append("check_session_risk")
                elif "multiple failed attempts" in reason_text:
                    reasoning.append("Too many denied requests in this session")
                    rule_trace.append("check_denial_history")
                else:
                    reasoning.append(reason_text)
                    rule_trace.append("contextual_policy_check")
            
            response["reasoning"] = reasoning
            response["rule_trace"] = rule_trace
            
            # Log the denied event with reasoning
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": reason,
                "reasoning": reasoning,
                "rule_trace": rule_trace,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            # Update session tracker
            update_tool_call(session_id, tool_name, input_data, "denied", reason=reason)
            return jsonify(response)
        
        # 3. Check rate limits
        try:
            check_limit(model_id, session_id)
        except RateLimitError as e:
            reason = str(e)
            response["reason"] = reason
            
            # Add explanations for rate limit denial
            reasoning = []
            rule_trace = []
            
            # Detailed reasoning about rate limits
            reasoning.append(f"Rate limit exceeded for session")
            reasoning.append(f"Error: {reason}")
            rule_trace.append("check_rate_limits")
            
            response["reasoning"] = reasoning
            response["rule_trace"] = rule_trace
            
            # Log the rate-limited event with reasoning
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": reason,
                "reasoning": reasoning,
                "rule_trace": rule_trace,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            # Update session tracker
            update_tool_call(session_id, tool_name, input_data, "denied", reason=reason)
            return jsonify(response)
        
        # 4. Validate schema
        try:
            validate_input(tool_name, input_data)
        except SchemaValidationError as e:
            reason = f"Schema validation error: {str(e)}"
            response["reason"] = reason
            
            # Add explanations for schema validation errors
            reasoning = []
            rule_trace = []
            
            # Detailed reasoning about schema validation
            error_msg = str(e)
            reasoning.append(f"Input validation failed for tool '{tool_name}'")
            
            # Provide more specific explanations based on common errors
            if "required property" in error_msg:
                reasoning.append("Missing required field in request")
            elif "is not of type" in error_msg:
                reasoning.append("Data type mismatch in request field")
            elif "does not match" in error_msg:
                reasoning.append("Input value does not match required pattern")
            elif "is greater than the maximum" in error_msg or "is less than the minimum" in error_msg:
                reasoning.append("Input value outside allowed range")
            
            # Add the detailed error message
            reasoning.append(f"Error: {error_msg}")
            rule_trace.append("validate_schema")
            
            response["reasoning"] = reasoning
            response["rule_trace"] = rule_trace
            
            # Log the validation error with reasoning
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "denied",
                "reason": reason,
                "reasoning": reasoning,
                "rule_trace": rule_trace,
                "latency_ms": int((time.time() - start_time) * 1000)
            })
            # Update session tracker
            update_tool_call(session_id, tool_name, input_data, "denied", reason=reason)
            return jsonify(response)
        
        # If we've made it this far, the request is allowed
        response["allowed"] = True
        response["status"] = "allowed"
        
        # 5. Run shadow policy simulation (non-blocking)
        shadow_results = simulate_shadow_policy(model_id, tool_name, session_id, context)
        
        # 6. Add session risk score
        risk_score = score_session(session_id)
        response["risk_score"] = risk_score
        
        # 7. Add explanations and reasoning for decision
        reasoning = []
        rule_trace = []
        
        # Add reasoning about basic policy check
        if "calendar" in tool_name:
            reasoning.append(f"Model is allowed to use calendar.*")
            rule_trace.append("check_tool_whitelist")
        else:
            reasoning.append(f"Model is permitted to use {tool_name}")
            rule_trace.append("check_tool_permissions")
        
        # Schema validation passed
        reasoning.append("No schema validation errors")
        rule_trace.append("validate_schema")
        
        # Rate limits
        reasoning.append("Session within rate limits")
        rule_trace.append("check_rate_limits")
        
        # Risk level explanation
        if risk_score < 0.2:
            reasoning.append(f"Session score: low risk ({risk_score:.2f})")
        elif risk_score < 0.5:
            reasoning.append(f"Session score: medium risk ({risk_score:.2f})")
        else:
            reasoning.append(f"Session score: high risk ({risk_score:.2f})")
        rule_trace.append("calculate_risk_score")
        
        # Add reasoning and rule trace to response
        response["reasoning"] = reasoning
        response["rule_trace"] = rule_trace
        
        # 7. Check if we need to forward to another gateway
        forward_to = request.headers.get("X-Forward-To")
        if forward_to:
            logger.info(f"Forwarding tool call to peer gateway: {forward_to}")
            
            # Prepare the forwarded payload
            forward_payload = {
                "model_id": model_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "input": input_data,
                "trace_id": str(uuid.uuid4()),
                "original_decision": {
                    "allowed": True,
                    "risk_score": risk_score,
                    "shadow_results": shadow_results
                }
            }
            
            # Forward the request
            status_code, remote_response = forward_toolcall(forward_to, forward_payload)
            
            # Handle the response
            if status_code == 200 and remote_response.get("allowed", False):
                # Merge remote response with our response
                response.update(remote_response)
                
                # Log the forwarded event
                latency_ms = int((time.time() - start_time) * 1000)
                log_event({
                    "model_id": model_id,
                    "session_id": session_id,
                    "tool": tool_name,
                    "input": input_data,
                    "status": "forwarded",
                    "forwarded_to": forward_to,
                    "remote_response": remote_response,
                    "risk_score": risk_score,
                    "shadow_results": shadow_results,
                    "latency_ms": latency_ms
                })
                # Update session tracker
                update_tool_call(session_id, tool_name, input_data, "forwarded", 
                                output=remote_response.get("result"))
                
                response["latency_ms"] = int((time.time() - start_time) * 1000)
                return jsonify(response)
            else:
                # Remote gateway denied or error
                response["allowed"] = False
                response["status"] = "denied"
                response["reason"] = f"Remote gateway denied: {remote_response.get('reason', 'Unknown reason')}"
                
                # Log the denied forward
                latency_ms = int((time.time() - start_time) * 1000)
                log_event({
                    "model_id": model_id,
                    "session_id": session_id,
                    "tool": tool_name,
                    "input": input_data,
                    "status": "denied",
                    "forward_attempted": True,
                    "forwarded_to": forward_to,
                    "reason": response["reason"],
                    "risk_score": risk_score,
                    "shadow_results": shadow_results,
                    "latency_ms": latency_ms
                })
                # Update session tracker
                update_tool_call(session_id, tool_name, input_data, "denied", 
                                reason=response["reason"])
                
                response["latency_ms"] = int((time.time() - start_time) * 1000)
                return jsonify(response)
        
        # 8. Call the tool API
        try:
            tool_result = call_tool_api(tool_name, input_data)
            response["result"] = tool_result
            
            # Log the allowed event with tool result and additional data
            latency_ms = int((time.time() - start_time) * 1000)
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "allowed",
                "tool_result": tool_result,
                "risk_score": risk_score,
                "shadow_results": shadow_results,
                "reasoning": reasoning,
                "rule_trace": rule_trace,
                "latency_ms": latency_ms
            })
            # Update session tracker
            update_tool_call(session_id, tool_name, input_data, "allowed", output=tool_result)
        except Exception as e:
            reason = f"Tool error: {str(e)}"
            response["status"] = "error"
            response["reason"] = reason
            
            # Log the tool error with additional data
            latency_ms = int((time.time() - start_time) * 1000)
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "input": input_data,
                "status": "error",
                "reason": reason,
                "risk_score": risk_score,
                "shadow_results": shadow_results,
                "latency_ms": latency_ms
            })
            # Update session tracker
            update_tool_call(session_id, tool_name, input_data, "error", reason=reason)
        
        response["latency_ms"] = int((time.time() - start_time) * 1000)
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
            reason = f"Schema validation error: {str(e)}"
            response["reason"] = reason
            # Log the validation error
            log_event({
                "model_id": model_id,
                "session_id": session_id,
                "tool": tool_name,
                "output": output_data,
                "status": "denied",
                "reason": reason,
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