# MCP-Sec Gateway

A zero-trust security gateway that validates, controls, and logs Model Context Protocol (MCP) traffic between AI models and external tools.

## Overview

MCP-Sec Gateway is a Flask-based middleware that enforces security policies on API requests between AI models and external tools. It includes:

- Policy enforcement based on model ID, tool name, and session
- JSON schema validation for request/response payloads
- Rate limiting to prevent abuse
- Comprehensive audit logging
- Interactive dashboard for monitoring traffic

## Key Components

- **Policy Engine**: Enforces rules defined in YAML configuration files
- **Schema Validator**: Validates request/response payloads against JSON schemas
- **Rate Limiter**: Prevents abuse by limiting calls per session
- **Audit Logger**: Records all activity with risk level assessment
- **Web Dashboard**: Visualizes traffic with color-coded risk levels

### Run in Replit
1. Click **Run** (Replit installs `requirements.txt` automatically).
2. Open the webview pane → `/dash` to see live audit logs.
3. Test with:
   ```bash
   curl -X POST $REPLIT_URL/mcp/toolcall \
     -H "Content-Type: application/json" \
     -d '{"model_id":"gpt-4o","session_id":"abc","tool_name":"calendar.create_event","input":{"title":"sync","start_time":"2025-05-08T09:00:00Z"}}'
   ```