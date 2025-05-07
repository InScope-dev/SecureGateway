# 📊 MCP-Sec Audit Log Format

Every model-tool interaction, allowed or denied, is logged in structured JSON for compliance, monitoring, and analysis.

## ✅ Logged Events
- ToolCall: model → tool
- ToolResult: server → model
- Denials (blocked by policy)
- Validation errors
- Anomalies (rate limit, unexpected input)

## 📄 Example Log Entry (Allowed ToolCall)
```json
{
  "timestamp": "2025-06-24T15:23:10Z",
  "model_id": "claude-3-opus",
  "session_id": "abc123",
  "tool": "calendar.create_event",
  "input": {
    "title": "MCP sync",
    "start_time": "2025-06-25T09:00:00Z"
  },
  "status": "allowed",
  "latency_ms": 87
}
```

## 🚫 Example Log Entry (Denied ToolCall)
```json
{
  "timestamp": "2025-06-24T15:24:01Z",
  "model_id": "mistral-open",
  "tool": "db.write_sensitive",
  "reason": "model not authorized for this tool",
  "status": "denied"
}
```

## 🔧 Delivery
- Local log file (JSON lines)
- Optional: stream to syslog, HTTP endpoint, SIEM (e.g., Datadog, Splunk)