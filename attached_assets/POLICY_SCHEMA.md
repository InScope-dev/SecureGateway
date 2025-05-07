# 🧾 MCP-Sec Policy Schema

Policies are defined in YAML or JSON and control:
- Which models can use which tools
- When and how often tools can be used
- What schemas are enforced for inputs/outputs

## Example Policy (YAML)
```yaml
rules:
  - model: "claude-3-opus"
    allow_tools:
      - "weather.*"
    deny_tools:
      - "db.write*"
    max_calls_per_session: 5
    active_hours: "09:00-18:00"
```

## Tool Schema (JSON)
```json
{
  "name": "calendar.create_event",
  "input": {
    "type": "object",
    "required": ["title", "start_time"],
    "properties": {
      "title": { "type": "string" },
      "start_time": { "type": "string", "format": "date-time" }
    }
  }
}
```