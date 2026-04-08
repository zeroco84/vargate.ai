/**
 * Centralised API helpers for the Vargate dashboard.
 * All endpoints go through the /api/ prefix (nginx proxy).
 */

const API = '/api';

// Public tenant slug — set when viewing a public dashboard without auth
let _publicTenantSlug = null;

export function setPublicTenantSlug(slug) {
  _publicTenantSlug = slug;
}

export function getPublicTenantSlug() {
  return _publicTenantSlug;
}

function getAuthHeaders() {
  // Public dashboard viewer — no auth token, use public tenant header
  if (_publicTenantSlug) {
    return { 'X-Vargate-Public-Tenant': _publicTenantSlug };
  }
  const token = localStorage.getItem('vargate_session');
  if (token && token !== 'pin') {
    return { 'Authorization': `Bearer ${token}` };
  }
  return {};
}

export async function fetchJSON(path, options = {}) {
  try {
    const headers = { ...getAuthHeaders(), ...(options.headers || {}) };
    const resp = await fetch(`${API}${path}`, { ...options, headers });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  } catch (e) {
    console.warn(`[API] ${path} failed:`, e.message);
    return null;
  }
}

export async function checkPublicDashboard(slug) {
  try {
    const resp = await fetch(`${API}/dashboard/public/${slug}`);
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

// ── Audit ────────────────────────────────────────────────────────────────────

export async function fetchAuditLog(limit = 200) {
  return fetchJSON(`/audit/log?limit=${limit}`);
}

export async function fetchChainVerify() {
  return fetchJSON('/audit/verify');
}

export async function fetchAuditSubjects() {
  return fetchJSON('/audit/subjects');
}

export async function tamperSimulate(recordNumber) {
  return fetchJSON('/audit/tamper-simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ record_number: recordNumber }),
  });
}

export async function tamperRestore() {
  return fetchJSON('/audit/tamper-restore', { method: 'POST' });
}

export async function replayAction(actionId) {
  return fetchJSON('/audit/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_id: actionId }),
  });
}

export async function eraseSubject(subjectId) {
  return fetchJSON(`/audit/erase/${subjectId}`, { method: 'POST' });
}

export async function verifyErasure(subjectId) {
  return fetchJSON(`/audit/erase/${subjectId}/verify`);
}

// ── Policy ───────────────────────────────────────────────────────────────────

export async function fetchBundleStatus() {
  return fetchJSON('/bundles/vargate/status');
}

export async function fetchPolicyRules() {
  return fetchJSON('/policy/rules');
}

// ── Blockchain ───────────────────────────────────────────────────────────────

export async function fetchAnchorStatus() {
  return fetchJSON('/anchor/status');
}

export async function fetchAnchorLog() {
  return fetchJSON('/anchor/log');
}

export async function fetchAnchorVerify() {
  return fetchJSON('/anchor/verify');
}

export async function triggerAnchor() {
  return fetchJSON('/anchor/trigger', { method: 'POST' });
}

// ── Merkle Trees (Sprint 5) ──────────────────────────────────────────────────

export async function fetchMerkleRoots(limit = 100) {
  return fetchJSON(`/audit/merkle/roots?limit=${limit}`);
}

export async function fetchMerkleProof(recordHash) {
  return fetchJSON(`/audit/merkle/proof/${recordHash}`);
}

export async function fetchMerkleConsistency(treeN, treeM) {
  return fetchJSON(`/audit/merkle/consistency/${treeN}/${treeM}`);
}

export async function fetchMerkleVerify() {
  return fetchJSON('/audit/merkle/verify');
}

// ── Credentials ──────────────────────────────────────────────────────────────

export async function fetchCredentials() {
  return fetchJSON('/credentials');
}

export async function fetchCredentialAccessLog() {
  return fetchJSON('/credentials/access-log');
}

export async function registerCredential(toolId, name, value) {
  return fetchJSON('/credentials/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool_id: toolId, name, value }),
  });
}

export async function deleteCredential(toolId, name) {
  return fetchJSON(`/credentials/${toolId}/${name}`, { method: 'DELETE' });
}

// ── HSM / Subjects ───────────────────────────────────────────────────────────

export async function fetchSubjectKeyStatus(subjectId) {
  return fetchJSON(`/hsm/keys/${subjectId}/status`);
}

// ── Agent ────────────────────────────────────────────────────────────────────

export async function fetchAgentAnomalyScore(agentId) {
  return fetchJSON(`/agents/${agentId}/anomaly_score`);
}

// ── Auth & Dashboard (Sprint 3) ─────────────────────────────────────────────

export async function fetchDashboardMe() {
  return fetchJSON('/dashboard/me');
}

export async function updateSettings(settings) {
  return fetchJSON('/dashboard/settings', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
}

export async function rotateApiKey() {
  return fetchJSON('/api-keys/rotate', { method: 'POST' });
}

// ── Tenant switching ────────────────────────────────────────────────────────

export async function fetchMyTenants() {
  return fetchJSON('/auth/my-tenants');
}

export async function switchTenant(tenantId) {
  return fetchJSON('/auth/switch-tenant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant_id: tenantId }),
  });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

export function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return '—'; }
}

export function timeAgo(iso) {
  if (!iso) return '—';
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function truncate(s, n) {
  if (!s) return '—';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

export function parseBundleRevision(rev) {
  if (!rev) return { version: '—', since: '—' };
  const parts = rev.split('-');
  if (parts.length >= 2) {
    const ts = parseInt(parts[parts.length - 1], 10);
    if (!isNaN(ts)) {
      const d = new Date(ts * 1000);
      return {
        version: parts.slice(0, -1).join('-'),
        since: d.toLocaleString('en-GB', { hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short' }),
      };
    }
  }
  return { version: rev, since: '—' };
}
