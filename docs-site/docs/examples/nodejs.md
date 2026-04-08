# Node.js Integration

Full working example using native `fetch` (Node 18+). No external dependencies required.

---

## Prerequisites

- Node.js 18+ (for native `fetch`)

---

## Complete Example

```javascript
const VARGATE_URL = process.env.VARGATE_URL || "https://vargate.ai/api";
const API_KEY = process.env.VARGATE_API_KEY; // Never hardcode

async function governedToolCall(tool, method, params) {
  const response = await fetch(`${VARGATE_URL}/mcp/tools/call`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
    },
    body: JSON.stringify({
      agent_id: "my-agent-v1",
      agent_type: "autonomous",
      agent_version: "1.0.0",
      tool,
      method,
      params,
    }),
  });

  if (response.status === 200) {
    const data = await response.json();
    console.log("Allowed:", data.action_id);
    return data;
  } else if (response.status === 403) {
    const { detail } = await response.json();
    console.log("Denied:", detail.violations);
    throw new Error(`Denied: ${detail.violations.join(", ")}`);
  } else if (response.status === 202) {
    const data = await response.json();
    console.log("Pending approval:", data.action_id);
    return data;
  } else {
    throw new Error(`Vargate error: ${response.status} ${await response.text()}`);
  }
}

async function checkAuditIntegrity() {
  const response = await fetch(`${VARGATE_URL}/audit/verify`, {
    headers: { "X-API-Key": API_KEY },
  });
  return response.json();
}

async function getMerkleProof(recordHash) {
  const response = await fetch(
    `${VARGATE_URL}/audit/merkle/proof/${recordHash}`,
    { headers: { "X-API-Key": API_KEY } }
  );
  if (!response.ok) {
    throw new Error(`Vargate error: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function replayDecision(actionId) {
  const response = await fetch(`${VARGATE_URL}/audit/replay`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
    },
    body: JSON.stringify({ action_id: actionId }),
  });
  return response.json();
}

// Usage
(async () => {
  try {
    // Send a governed action
    const result = await governedToolCall("http", "GET", {
      url: "https://api.example.com/data",
    });

    // Verify audit integrity
    const integrity = await checkAuditIntegrity();
    console.log(`Chain valid: ${integrity.valid}, records: ${integrity.record_count}`);

    // Replay the decision
    if (result.action_id) {
      const replay = await replayDecision(result.action_id);
      console.log(`Replay consistent: ${replay.consistent}`);
    }
  } catch (err) {
    console.error("Error:", err.message);
  }
})();
```

---

## Error Handling

```javascript
try {
  const result = await governedToolCall("stripe", "create_transfer", {
    amount: 50000,
    destination: "acct_xyz",
  });
} catch (err) {
  if (err.message.includes("Denied")) {
    console.log("Policy blocked this action");
  } else if (err.message.includes("429")) {
    console.log("Rate limited — back off and retry");
  } else {
    throw err;
  }
}
```

---

## TypeScript Types

```typescript
interface ToolCallRequest {
  agent_id: string;
  agent_type: string;
  agent_version: string; // semver
  tool: string;
  method: string;
  params: Record<string, unknown>;
}

interface AllowedResponse {
  status: "allowed";
  action_id: string;
  execution_mode?: "agent_direct" | "vargate_brokered";
  execution_result?: Record<string, unknown>;
}

interface DeniedResponse {
  detail: {
    action_id: string;
    violations: string[];
    severity: "none" | "low" | "medium" | "high" | "critical";
    alert_tier: string;
  };
}

interface PendingResponse {
  status: "pending_approval";
  action_id: string;
  message: string;
}
```
