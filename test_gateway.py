#!/usr/bin/env python3
"""
MCP-Sec Gateway Test Utility
Simple test script to verify API functionality
"""
import os
import sys
import json
import requests
import argparse
from datetime import datetime
from uuid import uuid4

# Default settings
URL = "http://localhost:5000"  # Default to local development server
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # Get from environment variable
MODEL_KEY = "modelkey-abc123"  # Default model key for testing
MODEL_ID = "gpt-4o"  # Default model ID for testing

def make_request(endpoint, method="GET", data=None, headers=None, verbose=True):
    """Make an HTTP request to the gateway API"""
    full_url = f"{URL}{endpoint}"
    
    if headers is None:
        headers = {}
    
    if verbose:
        print(f"\n[{method}] {full_url}")
        if data:
            print(f"Request data: {json.dumps(data, indent=2)}")
    
    try:
        if method.upper() == "GET":
            response = requests.get(full_url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(full_url, json=data, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        if verbose:
            print(f"Status: {response.status_code}")
            if response.status_code != 204:  # No content
                try:
                    print(f"Response: {json.dumps(response.json(), indent=2)}")
                except:
                    print(f"Response: {response.text}")
        
        return response
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def test_prompt(model_id=MODEL_ID, custom_prompt=None):
    """Test the /mcp/prompt endpoint"""
    session_id = str(uuid4())
    
    prompt = custom_prompt or "This is a test prompt for model context protocol testing."
    data = {
        "model_id": model_id,
        "session_id": session_id,
        "prompt": prompt
    }
    
    print(f"\n=== Testing /mcp/prompt with session {session_id} ===")
    response = make_request("/mcp/prompt", method="POST", data=data)
    
    if response and response.status_code == 200:
        print(f"✅ Prompt test successful! Session ID: {session_id}")
        return session_id
    else:
        print("❌ Prompt test failed")
        return None

def test_tool_call(model_id=MODEL_ID, session_id=None, tool_name="search.query", 
                  input_data=None, model_key=MODEL_KEY):
    """Test the /mcp/toolcall endpoint"""
    if session_id is None:
        session_id = str(uuid4())
    
    if input_data is None:
        input_data = {"q": "test search query"}
    
    data = {
        "model_id": model_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "input": input_data
    }
    
    headers = {"X-Model-Key": model_key}
    
    print(f"\n=== Testing /mcp/toolcall with tool {tool_name} ===")
    response = make_request("/mcp/toolcall", method="POST", data=data, headers=headers)
    
    if response and response.status_code in (200, 401, 403):
        status = response.json().get("status")
        if status == "allowed":
            print(f"✅ Tool call allowed: {tool_name}")
        else:
            reason = response.json().get("reason", "Unknown reason")
            print(f"ℹ️ Tool call {status}: {reason}")
        return response.json()
    else:
        print("❌ Tool call test failed")
        return None

def test_full_flow(model_id=MODEL_ID, tool_name="search.query", model_key=MODEL_KEY):
    """Test a full flow: prompt -> tool call"""
    # Start with a prompt
    session_id = test_prompt(model_id)
    if not session_id:
        return False
    
    # Then make a tool call
    if tool_name == "search.query":
        input_data = {"q": "test search query for full flow test"}
    elif tool_name == "calendar.create_event":
        input_data = {
            "title": "Test Meeting",
            "start_time": datetime.now().isoformat()
        }
    else:
        input_data = {"test": "data"}
    
    result = test_tool_call(model_id, session_id, tool_name, input_data, model_key)
    
    if result and result.get("status") == "allowed":
        print("\n✅ Full flow test completed successfully!")
        return True
    else:
        print("\n❌ Full flow test failed")
        return False

def main():
    """Main entry point with command-line argument parsing"""
    parser = argparse.ArgumentParser(description="MCP-Sec Gateway Test Utility")
    parser.add_argument("-u", "--url", help=f"Gateway URL (default: {URL})")
    parser.add_argument("-a", "--admin-key", help="Admin API key")
    parser.add_argument("-m", "--model-key", help=f"Model API key (default: {MODEL_KEY})")
    parser.add_argument("-id", "--model-id", help=f"Model ID (default: {MODEL_ID})")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Prompt test command
    prompt_parser = subparsers.add_parser("prompt", help="Test prompt endpoint")
    prompt_parser.add_argument("prompt_text", nargs="?", help="Custom prompt text")
    
    # Tool call test command
    tool_parser = subparsers.add_parser("tool", help="Test tool call endpoint")
    tool_parser.add_argument("tool_name", nargs="?", default="search.query", 
                            help="Tool name to call (default: search.query)")
    tool_parser.add_argument("--session", help="Session ID (creates new if not provided)")
    tool_parser.add_argument("--input", help="JSON input string for the tool")
    
    # Full flow test command
    flow_parser = subparsers.add_parser("flow", help="Test full flow (prompt -> tool call)")
    flow_parser.add_argument("tool_name", nargs="?", default="search.query", 
                             help="Tool name to call (default: search.query)")
    
    args = parser.parse_args()
    
    # Update global settings if provided
    global URL, ADMIN_KEY, MODEL_KEY, MODEL_ID
    
    if args.url:
        URL = args.url
    if args.admin_key:
        ADMIN_KEY = args.admin_key
    if args.model_key:
        MODEL_KEY = args.model_key
    if args.model_id:
        MODEL_ID = args.model_id
    
    # Run the appropriate command
    if args.command == "prompt":
        test_prompt(MODEL_ID, args.prompt_text)
    elif args.command == "tool":
        input_data = None
        if args.input:
            try:
                input_data = json.loads(args.input)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON input: {args.input}")
                return 1
        
        test_tool_call(MODEL_ID, args.session, args.tool_name, input_data, MODEL_KEY)
    elif args.command == "flow":
        test_full_flow(MODEL_ID, args.tool_name, MODEL_KEY)
    else:
        # Default behavior: run full flow test
        print("Running default full flow test...")
        test_full_flow()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())