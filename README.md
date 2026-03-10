# Vargate Proxy — Prototype

AI agent supervision gateway. Intercepts every tool call an autonomous AI agent 
makes, evaluates it against OPA policy, and logs every decision to a hash-chained 
append-only audit log.

## Quick Start

```bash
# Start the services
docker-compose up --build

# In another terminal, run the test demo
pip install requests
python test_demo.py
```

## Architecture

```
Agent → [POST /mcp/tools/call] → Vargate Gateway → [OPA Policy Check] → Allow/Block
                                        ↓
                              Hash-Chained SQLite Audit Log
```

### Services

| Service   | Port | Description                              |
|-----------|------|------------------------------------------|
| `gateway` | 8000 | FastAPI MCP proxy server                 |
| `opa`     | 8181 | Open Policy Agent with Vargate policies  |

### Endpoints

| Method | Path               | Description                          |
|--------|-------------------|--------------------------------------|
| POST   | `/mcp/tools/call` | Submit a tool call for evaluation    |
| GET    | `/audit/verify`   | Verify hash chain integrity          |
| GET    | `/audit/log`      | Retrieve audit records               |
| GET    | `/health`         | Gateway health check                 |

## Policy Rules

The OPA policy evaluates each tool call against these rules:

- **High-value transactions**: Blocks amounts ≥ £5,000 without approval
- **Competitor contacts**: Blocks emails to known competitor domains
- **GDPR PII residency**: Blocks PII leaving the EU
- **Anomaly detection**: Blocks calls with anomaly score > 0.7
- **Out-of-hours**: Blocks high-value actions outside business hours

## Session 1 Scope

This prototype covers:
- ✅ MCP proxy server (FastAPI)
- ✅ OPA policy evaluation (Rego)
- ✅ Hash-chained SQLite audit log
- ✅ Test demo script

## License

Proprietary — Vargate.ai
