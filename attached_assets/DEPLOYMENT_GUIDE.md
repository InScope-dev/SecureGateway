# 🚀 MCP-Sec Deployment Guide

MCP-Sec can be deployed in three primary ways.

## 🐳 Docker
1. Clone repo
2. Define `.env` and `policies.yaml`
3. Run:
```bash
docker build -t mcp-sec .
docker run -p 9000:9000 --env-file .env mcp-sec
```

## 🌐 Render / Railway
- Connect GitHub repo
- Set environment variables
- Use Procfile:
```
web: uvicorn gateway:app --host 0.0.0.0 --port $PORT
```

## 🧩 Inline (Python)
If embedding in MCP server:
```python
from mcp_sec import SecureRouter
app.include_router(SecureRouter(policy_path="policies.yaml"))
```

## 🔑 Required Environment Variables
- `POLICY_PATH`
- `LOG_LEVEL`
- `REDIS_URL` (if using rate limiting)