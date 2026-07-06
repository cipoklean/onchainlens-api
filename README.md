# OnchainLens — Token Security Audit API
#
# A2MCP-compatible endpoint for real-time token security scanning.
# Free tier, no API keys needed. Powered by GoPlus Security.
#
# Endpoints:
#   POST /audit  — scan a token contract
#   GET  /health — service status
#
# Deploy to Render (free): https://render.com
#   - Runtime: Python 3
#   - Build: pip install -r requirements.txt
#   - Start: uvicorn main:app --host 0.0.0.0 --port $PORT
#
# Example:
#   curl -X POST https://your-app.onrender.com/audit \
#     -H "Content-Type: application/json" \
#     -d '{"contract_address": "0x...", "chain": "ethereum"}'
