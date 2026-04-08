/**
 * Vargate Node.js Integration Example
 *
 * Submit a governed tool call to the Vargate proxy.
 * No external dependencies required (uses native fetch, Node 18+).
 */

const VARGATE_URL = "https://vargate.ai/api";
const API_KEY = "your-api-key-here"; // From signup or /api-keys/rotate

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

  if (!response.ok) {
    throw new Error(`Vargate error: ${response.status} ${await response.text()}`);
  }

  const result = await response.json();

  if (result.status === "blocked") {
    console.log("Action denied:", result.detail?.violations);
  } else if (result.status === "pending_approval") {
    console.log("Requires human approval:", result.action_id);
  } else {
    console.log("Action allowed:", result.action_id);
  }

  return result;
}

async function checkAuditIntegrity() {
  const response = await fetch(`${VARGATE_URL}/audit/verify`, {
    headers: { "X-API-Key": API_KEY },
  });
  return response.json();
}

// Example usage
(async () => {
  const result = await governedToolCall("http", "GET", {
    url: "https://api.example.com/data",
  });
  console.log(result);

  const integrity = await checkAuditIntegrity();
  console.log("Chain valid:", integrity.valid);
})();
