# 📄 MCP Support Matrix for MCP-Sec Gateway

## ✅ Supported MCP Methods
- `Prompts` – prompt forwarding and monitoring
- `ToolCall` – tool invocation filtering
- `ToolResult` – result handling and logging
- `Resources` – context injection tracking

## ⛔ Not Yet Supported
- `Sampling` – advanced token completion (planned)
- `Custom plugins` – third-party auth extensions (planned)

## 💬 Transports
- JSON-RPC via stdin/stdout ✅
- JSON-RPC over HTTP ✅
- Server-Sent Events (SSE) streaming ✅

## 🛠 Tool Compatibility
- Tool schema required (JSON Schema v7)
- Result must conform to declared schema