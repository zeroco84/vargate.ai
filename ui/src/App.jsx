import React, { useState, useEffect, useCallback, useRef } from 'react';

const API = '/api';

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return '—'; }
}

function truncate(s, n) {
  if (!s) return '—';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── Top Bar ─────────────────────────────────────────────────────────────────

function TopBar({ chain, liveMode, setLiveMode, anchorStatus }) {
  const valid = chain?.valid;
  const count = chain?.record_count ?? 0;
  const failedId = chain?.failed_at_action_id;
  const latestBlock = anchorStatus?.latest_block;
  const anchorConnected = anchorStatus?.blockchain_connected;

  return (
    <header className="fixed top-0 left-0 right-0 z-50 h-16 bg-navy-950/90 backdrop-blur-xl border-b border-navy-800/60 flex items-center justify-between px-6">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-vargate to-blue-400 flex items-center justify-center">
            <span className="text-white text-xs font-bold">V</span>
          </div>
          <span className="text-xl font-extrabold tracking-tight text-white">VARGATE</span>
        </div>
        <span className="text-navy-400 text-sm font-medium ml-2 hidden sm:inline">Audit Dashboard</span>
      </div>
      <div className="flex items-center gap-5">
        <div className="flex items-center gap-2">
          <span className={`inline-block w-2.5 h-2.5 rounded-full ${valid ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'}`} />
          {valid ? (
            <span className="text-emerald-300 text-sm font-medium">Chain: VALID <span className="text-navy-400">({count} records)</span></span>
          ) : (
            <span className="text-red-400 text-sm font-semibold">BROKEN — tampered at record #{failedId ? failedId.slice(0, 8) : '?'}</span>
          )}
        </div>
        {anchorConnected && (
          <div className="flex items-center gap-1.5 text-sm">
            <span className="text-amber-400">⛓</span>
            <span className="text-amber-300 font-medium">
              {latestBlock != null ? `Anchored: block #${latestBlock}` : 'No anchors'}
            </span>
          </div>
        )}
        <button
          onClick={() => setLiveMode(m => !m)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold transition-all duration-300 ${
            liveMode
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-[0_0_12px_rgba(52,211,153,0.15)]'
              : 'bg-navy-800 text-navy-400 border border-navy-700 hover:border-navy-600'
          }`}
        >
          <span className={`inline-block w-1.5 h-1.5 rounded-full ${liveMode ? 'bg-emerald-400 chain-pulse' : 'bg-navy-600'}`} />
          {liveMode ? '⟳ Live' : '⟳ Live'}
        </button>
      </div>
    </header>
  );
}

// ── Stats Card ──────────────────────────────────────────────────────────────

function StatsCard({ value, label, sublabel, variant = 'default' }) {
  const bg = {
    default: 'from-navy-900/80 to-navy-900/40 border-navy-800/50',
    success: 'from-emerald-900/20 to-navy-900/40 border-emerald-800/30',
    danger: 'from-red-900/20 to-navy-900/40 border-red-800/30',
    info: 'from-blue-900/20 to-navy-900/40 border-blue-800/30',
  }[variant];

  const valueColor = {
    default: 'text-white',
    success: 'text-emerald-300',
    danger: 'text-red-300',
    info: 'text-blue-300',
  }[variant];

  return (
    <div className={`bg-gradient-to-br ${bg} border rounded-xl p-5 backdrop-blur-sm`}>
      <div className={`text-3xl font-bold ${valueColor} font-mono`}>{value}</div>
      <div className="text-navy-300 text-sm font-medium mt-1">{label}</div>
      {sublabel && <div className="text-navy-500 text-xs mt-0.5">{sublabel}</div>}
    </div>
  );
}

function StatsRow({ records, policy }) {
  const total = records.length;
  const allowed = records.filter(r => r.decision === 'allow').length;
  const blocked = records.filter(r => r.decision === 'deny').length;
  const rev = policy?.revision || '—';

  return (
    <div className="grid grid-cols-4 gap-4">
      <StatsCard value={total} label="Total Actions" variant="default" />
      <StatsCard value={allowed} label="Allowed" variant="success" />
      <StatsCard value={blocked} label="Blocked" variant={blocked > 0 ? 'danger' : 'default'} />
      <StatsCard value={truncate(rev, 18)} label="Active Policy" variant="info" />
    </div>
  );
}

// ── Decision Pill ───────────────────────────────────────────────────────────

function DecisionPill({ decision }) {
  if (decision === 'allow') {
    return <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-300 text-xs font-semibold border border-emerald-500/20">✓ ALLOW</span>;
  }
  return <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-red-500/15 text-red-300 text-xs font-semibold border border-red-500/20">✗ BLOCK</span>;
}

// ── Severity Badge ──────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const styles = {
    critical: 'bg-red-500/15 text-red-300 border-red-500/25',
    high: 'bg-orange-500/15 text-orange-300 border-orange-500/25',
    medium: 'bg-amber-500/15 text-amber-300 border-amber-500/25',
    none: 'bg-navy-800/50 text-navy-500 border-navy-700/50',
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${styles[severity] || styles.none}`}>
      {severity}
    </span>
  );
}

// ── Pass Indicator ──────────────────────────────────────────────────────────

function PassPill({ pass }) {
  if (pass === 2) {
    return <span className="inline-flex items-center justify-center w-6 h-6 rounded-md bg-blue-500/20 text-blue-300 text-xs font-bold border border-blue-500/30">2</span>;
  }
  return <span className="inline-flex items-center justify-center w-6 h-6 rounded-md bg-navy-800/60 text-navy-500 text-xs font-medium border border-navy-700/40">1</span>;
}

// ── Chain Status Icon ───────────────────────────────────────────────────────

function ChainIcon({ valid }) {
  if (valid) return <span className="text-emerald-400 text-sm">✓</span>;
  return <span className="text-red-400 text-sm font-bold">✗</span>;
}

// ── Expanded Row Detail Panel ───────────────────────────────────────────────

function ExecutionModePill({ mode }) {
  if (mode === 'vargate_brokered') {
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wide bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">🔒 BROKERED</span>;
  }
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wide bg-navy-700/30 text-navy-400 border border-navy-600/30">DIRECT</span>;
}

function ExecutionTimeline({ rec }) {
  if (rec.execution_mode !== 'vargate_brokered' || !rec.execution_latency_ms) return null;
  const opaMs = rec.opa_input ? '~' : '?';
  const totalMs = rec.execution_latency_ms;
  const credential = rec.credential_accessed || '—';
  return (
    <div className="mt-3 pt-3 border-t border-navy-800/40">
      <div className="text-navy-400 text-xs font-semibold uppercase tracking-wider mb-2">Execution Timeline</div>
      <div className="flex items-center gap-1 flex-wrap">
        <span className="inline-flex items-center px-2 py-1 bg-blue-500/10 text-blue-300 text-[10px] font-mono rounded border border-blue-500/20">OPA Eval</span>
        <span className="text-navy-600">→</span>
        <span className="inline-flex items-center px-2 py-1 bg-purple-500/10 text-purple-300 text-[10px] font-mono rounded border border-purple-500/20">HSM Fetch</span>
        <span className="text-navy-600">→</span>
        <span className="inline-flex items-center px-2 py-1 bg-emerald-500/10 text-emerald-300 text-[10px] font-mono rounded border border-emerald-500/20">Tool Execute {totalMs}ms</span>
        <span className="text-navy-600">→</span>
        <span className="inline-flex items-center px-2 py-1 bg-navy-700/30 text-navy-300 text-[10px] font-mono rounded border border-navy-600/30">Result</span>
      </div>
      <div className="mt-2 text-[10px] text-navy-500">Credential: <code className="text-navy-400">{credential}</code></div>
      {rec.execution_result && (
        <pre className="mt-2 p-2 bg-navy-950/80 rounded text-[10px] text-emerald-200 font-mono overflow-x-auto border border-navy-800/50 max-h-32">
          {JSON.stringify(rec.execution_result, null, 2)}
        </pre>
      )}
    </div>
  );
}

function RecordDetail({ rec, chainValid, onReplay }) {
  return (
    <tr>
      <td colSpan={9} className="p-0">
        <div className="animate-slide-down overflow-hidden bg-navy-900/50 border-x border-b border-navy-800/40">
          <div className="p-5 grid grid-cols-2 gap-6">
            <div className="space-y-3">
              <DetailRow label="Action ID" value={rec.action_id} mono />
              <DetailRow label="Agent" value={`${rec.agent_id}`} />
              <DetailRow label="Tool / Method" value={`${rec.tool} / ${rec.method}`} />
              <div>
                <span className="text-navy-500 text-xs font-medium uppercase tracking-wider">Parameters</span>
                <pre className="mt-1 p-3 bg-navy-950/80 rounded-lg text-xs text-blue-200 font-mono overflow-x-auto border border-navy-800/50 max-h-40">
                  {JSON.stringify(rec.params, null, 2)}
                </pre>
              </div>
            </div>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="text-navy-500 text-xs font-medium uppercase tracking-wider w-28">Decision</span>
                <DecisionPill decision={rec.decision} />
              </div>
              <DetailRow label="Violations" value={rec.violations?.length ? rec.violations.join(', ') : '—'} />
              <div className="flex items-center gap-3">
                <span className="text-navy-500 text-xs font-medium uppercase tracking-wider w-28">Severity</span>
                <SeverityBadge severity={rec.severity} />
              </div>
              <DetailRow label="Alert Tier" value={rec.alert_tier} />
              <DetailRow label="Evaluation" value={rec.evaluation_pass === 2 ? 'Pass 2 (enriched — Redis behavioral history)' : 'Pass 1 (fast path — no Redis lookup)'} />
              <DetailRow label="Anomaly Score" value={`${(rec.anomaly_score_at_eval || 0).toFixed(4)} at time of evaluation`} />
              <DetailRow label="Bundle" value={rec.bundle_revision} mono />
              <div className="mt-3 pt-3 border-t border-navy-800/40">
                <div className="text-navy-400 text-xs font-semibold uppercase tracking-wider mb-2">Chain Integrity</div>
                <div className="space-y-1.5">
                  <div className="flex items-start gap-2">
                    <span className="text-navy-500 text-[10px] font-mono w-20 shrink-0 pt-0.5">Prev Hash</span>
                    <code className="text-[10px] text-navy-300 font-mono break-all">{rec.prev_hash?.slice(0, 32)}…</code>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-navy-500 text-[10px] font-mono w-20 shrink-0 pt-0.5">This Hash</span>
                    <code className="text-[10px] text-navy-300 font-mono break-all">{rec.record_hash?.slice(0, 32)}…</code>
                    <ChainIcon valid={chainValid} />
                  </div>
                </div>
              </div>
              {rec.opa_input && (
                <button
                  onClick={(e) => { e.stopPropagation(); onReplay?.(rec.action_id); }}
                  className="mt-3 px-3 py-1.5 bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 text-xs font-semibold rounded-lg border border-blue-500/30 transition-all flex items-center gap-1.5"
                >
                  🔁 Replay Decision
                </button>
              )}
              <ExecutionTimeline rec={rec} />
            </div>
          </div>
        </div>
      </td>
    </tr>
  );
}

function DetailRow({ label, value, mono }) {
  return (
    <div className="flex items-start gap-3">
      <span className="text-navy-500 text-xs font-medium uppercase tracking-wider w-28 shrink-0 pt-0.5">{label}</span>
      <span className={`text-sm text-navy-200 ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  );
}

// ── Audit Log Table ─────────────────────────────────────────────────────────

function AuditTable({ records, chain, newIds, onReplay }) {
  const [expandedId, setExpandedId] = useState(null);

  // Build chain validity map: recompute from verify result
  const chainMap = {};
  if (chain?.valid) {
    records.forEach(r => { chainMap[r.id] = true; });
  } else if (chain?.failed_at_action_id) {
    // All records before the failed one are valid
    let foundBroken = false;
    // records are newest-first, but we need id-order to find break point
    const sorted = [...records].sort((a, b) => a.id - b.id);
    for (const r of sorted) {
      if (r.action_id === chain.failed_at_action_id) foundBroken = true;
      chainMap[r.id] = !foundBroken;
    }
  } else if (!chain?.valid && chain?.record_count != null) {
    records.forEach(r => { chainMap[r.id] = false; });
  }

  return (
    <div className="bg-navy-900/40 rounded-xl border border-navy-800/40 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-navy-800/50">
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">#</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Time</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Agent</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Tool</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Decision</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Mode</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Violations</th>
              <th className="text-center px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Pass</th>
              <th className="text-left px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Severity</th>
              <th className="text-center px-4 py-3 text-navy-500 text-xs font-semibold uppercase tracking-wider">Chain</th>
            </tr>
          </thead>
          <tbody>
            {records.map((rec) => {
              const isNew = newIds.has(rec.action_id);
              const isBlock = rec.decision === 'deny';
              const isExpanded = expandedId === rec.id;
              const chainOk = chainMap[rec.id] ?? true;
              const wasJustBroken = !chainOk && chainMap[rec.id] === false;
              const hasPii = rec.contains_pii === 1;
              const isErased = rec.erasure_status === 'erased';

              return (
                <React.Fragment key={rec.id}>
                  <tr
                    onClick={() => setExpandedId(isExpanded ? null : rec.id)}
                    className={`
                      cursor-pointer border-b border-navy-800/20 transition-colors duration-200
                      ${isNew ? 'animate-fade-in' : ''}
                      ${wasJustBroken ? 'animate-pulse-red' : ''}
                      ${isBlock && chainOk ? 'bg-red-950/20 border-l-[3px] border-l-red-500/60' : ''}
                      ${!chainOk ? 'bg-red-950/15' : ''}
                      ${isErased ? 'opacity-60' : ''}
                      ${isExpanded ? 'bg-navy-800/30' : 'hover:bg-navy-800/20'}
                    `}
                  >
                    <td className="px-4 py-2.5 text-navy-500 font-mono text-xs">{rec.id}</td>
                    <td className="px-4 py-2.5 text-navy-300 font-mono text-xs">{formatTime(rec.created_at)}</td>
                    <td className="px-4 py-2.5 text-navy-200 text-xs" title={rec.agent_id}>
                      {hasPii && <span title={isErased ? `Erased: ${rec.pii_subject_id}` : `PII: ${rec.pii_subject_id}`} className="mr-1">{isErased ? '🔓' : '🔒'}</span>}
                      {truncate(rec.agent_id, 26)}
                    </td>
                    <td className="px-4 py-2.5 text-navy-200 text-xs">{rec.tool}</td>
                    <td className="px-4 py-2.5"><DecisionPill decision={rec.decision} /></td>
                    <td className="px-4 py-2.5"><ExecutionModePill mode={rec.execution_mode} /></td>
                    <td className="px-4 py-2.5 text-navy-400 text-xs" title={rec.violations?.join(', ')}>
                      {rec.violations?.length ? truncate(rec.violations[0], 32) : <span className="text-navy-600">—</span>}
                    </td>
                    <td className="px-4 py-2.5 text-center"><PassPill pass={rec.evaluation_pass} /></td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={rec.severity} /></td>
                    <td className="px-4 py-2.5 text-center"><ChainIcon valid={chainOk} /></td>
                  </tr>
                  {isExpanded && <RecordDetail rec={rec} chainValid={chainOk} onReplay={onReplay} />}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tamper Simulation Panel ─────────────────────────────────────────────────

function TamperPanel({ records, chain, onRefresh }) {
  const [selectedRecord, setSelectedRecord] = useState('');
  const [tampered, setTampered] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);

  // Default to first BLOCK record
  useEffect(() => {
    if (!selectedRecord && records.length) {
      const blockRec = [...records].sort((a, b) => a.id - b.id).find(r => r.decision === 'deny');
      if (blockRec) setSelectedRecord(String(blockRec.id));
      else if (records.length) setSelectedRecord(String(records[records.length - 1].id));
    }
  }, [records, selectedRecord]);

  const sorted = [...records].sort((a, b) => a.id - b.id);

  const handleTamper = async () => {
    if (!selectedRecord) return;
    setLoading(true);
    try {
      // Find the sequential position (1-indexed)
      const recNum = sorted.findIndex(r => r.id === parseInt(selectedRecord)) + 1;
      const resp = await fetch(`${API}/audit/tamper-simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record_number: recNum }),
      });
      const data = await resp.json();
      setTampered(true);
      setStatus({ type: 'broken', message: `⚠ Tamper detected at record #${recNum}. Chain broken. ${data.records_affected} records affected.` });
      onRefresh();
    } catch (e) {
      setStatus({ type: 'error', message: `Error: ${e.message}` });
    }
    setLoading(false);
  };

  const handleRestore = async () => {
    setLoading(true);
    try {
      const resp = await fetch(`${API}/audit/tamper-restore`, { method: 'POST' });
      const data = await resp.json();
      setTampered(false);
      setStatus({ type: 'ok', message: `● Chain restored and verified. All ${data.record_count} records intact.` });
      onRefresh();
    } catch (e) {
      setStatus({ type: 'error', message: `Error: ${e.message}` });
    }
    setLoading(false);
  };

  return (
    <div className="bg-navy-900/40 rounded-xl border border-navy-800/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-navy-800/40 flex items-center gap-3">
        <span className="text-lg">🔬</span>
        <span className="text-white text-sm font-semibold">Tamper Simulation</span>
        <span className="text-navy-500 text-xs ml-1">— Demo Mode Only</span>
      </div>
      <div className="p-5">
        <p className="text-navy-400 text-xs mb-4 leading-relaxed">
          Simulates an insider modifying an audit record — for example, changing a BLOCK to an ALLOW to hide a policy violation. Watch the chain break.
        </p>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-navy-500 text-xs font-medium">Target record:</span>
            <select
              value={selectedRecord}
              onChange={e => setSelectedRecord(e.target.value)}
              disabled={tampered || loading}
              className="bg-navy-950 border border-navy-700 text-navy-200 text-xs rounded-lg px-3 py-1.5 focus:border-vargate focus:ring-1 focus:ring-vargate/30 outline-none disabled:opacity-40"
            >
              {sorted.map((r) => (
                <option key={r.id} value={r.id}>
                  #{r.id} — {r.agent_id.slice(0, 20)} / {r.tool} / {r.decision.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={handleTamper}
            disabled={tampered || loading || !selectedRecord}
            className="px-4 py-1.5 bg-red-600/80 hover:bg-red-600 text-white text-xs font-semibold rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1.5"
          >
            💥 Tamper Record
          </button>
          <button
            onClick={handleRestore}
            disabled={!tampered || loading}
            className="px-4 py-1.5 bg-emerald-600/80 hover:bg-emerald-600 text-white text-xs font-semibold rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1.5"
          >
            ↩ Restore
          </button>
        </div>
        {status && (
          <div className={`mt-3 text-xs font-medium px-3 py-2 rounded-lg ${
            status.type === 'broken' ? 'bg-red-500/10 text-red-300 border border-red-500/20' :
            status.type === 'ok' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20' :
            'bg-amber-500/10 text-amber-300 border border-amber-500/20'
          }`}>
            {status.message}
          </div>
        )}
        {!status && (
          <div className="mt-3 text-xs text-navy-500 px-3 py-2 rounded-lg bg-navy-950/30">
            ● Chain intact. All {records.length} records verified.
          </div>
        )}
      </div>
    </div>
  );
}

// ── Policy Version Timeline ─────────────────────────────────────────────────

function PolicyTimeline({ records }) {
  if (!records.length) return null;

  // Group consecutive records by bundle_revision (oldest first)
  const sorted = [...records].sort((a, b) => a.id - b.id);
  const groups = [];
  let currentGroup = null;

  for (const rec of sorted) {
    if (!currentGroup || currentGroup.revision !== rec.bundle_revision) {
      currentGroup = {
        revision: rec.bundle_revision,
        firstTime: rec.created_at,
        count: 1,
      };
      groups.push(currentGroup);
    } else {
      currentGroup.count++;
    }
  }

  if (groups.length === 0) return null;

  return (
    <div className="bg-navy-900/40 rounded-xl border border-navy-800/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-navy-800/40">
        <span className="text-white text-sm font-semibold">Policy Version History</span>
      </div>
      <div className="p-5 overflow-x-auto">
        <div className="flex items-center min-w-max">
          {groups.map((g, i) => (
            <React.Fragment key={i}>
              <div className="flex flex-col items-center relative">
                {/* Node */}
                <div className="w-4 h-4 rounded-full bg-gradient-to-br from-vargate to-blue-400 border-2 border-navy-900 shadow-[0_0_10px_rgba(59,130,246,0.4)] z-10" />
                {/* Info above */}
                <div className="absolute bottom-7 flex flex-col items-center whitespace-nowrap">
                  <span className="text-blue-300 text-[10px] font-mono font-semibold">{truncate(g.revision, 22)}</span>
                </div>
                {/* Info below */}
                <div className="absolute top-7 flex flex-col items-center whitespace-nowrap">
                  <span className="text-navy-500 text-[10px] font-mono">{formatTime(g.firstTime)}</span>
                  <span className="text-navy-600 text-[9px]">{g.count} record{g.count !== 1 ? 's' : ''}</span>
                </div>
              </div>
              {/* Connector line */}
              {i < groups.length - 1 && (
                <div className="h-[2px] bg-gradient-to-r from-vargate/40 to-blue-400/40 flex-1 min-w-[100px] mx-1" />
              )}
            </React.Fragment>
          ))}
          {/* Arrow at end */}
          <div className="ml-2 text-navy-600">▶</div>
        </div>
      </div>
    </div>
  );
}

// ── Policy Replay Panel ────────────────────────────────────────────────────

function ReplayPanel({ replayActionId, setReplayActionId }) {
  const [actionId, setActionId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [bulkResult, setBulkResult] = useState(null);

  // Auto-trigger when action ID is set from expanded row
  useEffect(() => {
    if (replayActionId) {
      setActionId(replayActionId);
      doReplay(replayActionId);
      setReplayActionId('');
    }
  }, [replayActionId]);

  const doReplay = async (id) => {
    const targetId = id || actionId;
    if (!targetId) return;
    setLoading(true);
    setResult(null);
    setBulkResult(null);
    try {
      const resp = await fetch(`${API}/audit/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: targetId }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        setResult({ error: err.detail || `HTTP ${resp.status}` });
      } else {
        setResult(await resp.json());
      }
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  const doLastBlock = async () => {
    setLoading(true);
    setResult(null);
    setBulkResult(null);
    try {
      const resp = await fetch(`${API}/audit/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ last_block: true }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        setResult({ error: err.detail || `HTTP ${resp.status}` });
      } else {
        const data = await resp.json();
        setActionId(data.action_id || '');
        setResult(data);
      }
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  const doVerifyLast20 = async () => {
    setLoading(true);
    setResult(null);
    setBulkResult(null);
    try {
      const resp = await fetch(`${API}/audit/replay-bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: 20 }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        setResult({ error: err.detail || `HTTP ${resp.status}` });
      } else {
        setBulkResult(await resp.json());
      }
    } catch (e) {
      setResult({ error: e.message });
    }
    setLoading(false);
  };

  return (
    <div className="bg-navy-900/40 rounded-xl border border-navy-800/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-navy-800/40 flex items-center gap-3">
        <span className="text-lg">🔁</span>
        <span className="text-white text-sm font-semibold">Policy Replay</span>
        <span className="text-navy-500 text-xs ml-1">— Verify Any Decision</span>
      </div>
      <div className="p-5">
        <p className="text-navy-400 text-xs mb-4 leading-relaxed">
          Enter an Action ID to replay the policy decision from the original input document and policy bundle.
        </p>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <span className="text-navy-500 text-xs font-medium shrink-0">Action ID:</span>
            <input
              type="text"
              value={actionId}
              onChange={e => setActionId(e.target.value)}
              placeholder="e.g. def456-7890-abcd-..."
              className="flex-1 bg-navy-950 border border-navy-700 text-navy-200 text-xs font-mono rounded-lg px-3 py-1.5 focus:border-vargate focus:ring-1 focus:ring-vargate/30 outline-none placeholder-navy-700 min-w-0"
            />
          </div>
          <button
            onClick={() => doReplay()}
            disabled={loading || !actionId}
            className="px-4 py-1.5 bg-blue-600/80 hover:bg-blue-600 text-white text-xs font-semibold rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {loading ? '⏳' : '🔁'} Replay
          </button>
        </div>
        <div className="flex items-center gap-3 mt-3">
          <span className="text-navy-600 text-xs">— or —</span>
          <button
            onClick={doLastBlock}
            disabled={loading}
            className="px-3 py-1 bg-navy-800 hover:bg-navy-700 text-navy-300 text-xs font-semibold rounded-lg border border-navy-700 transition-all disabled:opacity-30"
          >
            Replay Last Block
          </button>
          <button
            onClick={doVerifyLast20}
            disabled={loading}
            className="px-3 py-1 bg-navy-800 hover:bg-navy-700 text-navy-300 text-xs font-semibold rounded-lg border border-navy-700 transition-all disabled:opacity-30"
          >
            Verify Last 20
          </button>
        </div>

        {/* Single replay result */}
        {result && !result.error && (
          <div className={`mt-4 p-4 rounded-lg border ${
            result.replay_status === 'MATCH'
              ? 'bg-emerald-500/5 border-emerald-500/20'
              : 'bg-red-500/5 border-red-500/20'
          }`}>
            <div className="flex items-center gap-2 mb-3">
              {result.replay_status === 'MATCH' ? (
                <span className="text-emerald-300 text-sm font-semibold">✅ VERIFIED — Decision reproducible</span>
              ) : (
                <span className="text-red-300 text-sm font-semibold">⚠ MISMATCH DETECTED</span>
              )}
            </div>
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center gap-3">
                <span className="text-navy-500 w-20">Action</span>
                <span className="text-navy-200">{result.original?.bundle_revision && `${result.opa_input_used?.action?.tool || '?'} / ${result.opa_input_used?.action?.method || '?'}`}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-navy-500 w-20">Agent</span>
                <span className="text-navy-200">{result.opa_input_used?.agent?.id || '?'}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-navy-500 w-20">Policy</span>
                <span className="text-navy-200 font-mono text-[10px]">{result.original?.bundle_revision}</span>
              </div>
              <div className="mt-2 pt-2 border-t border-navy-800/40 space-y-1">
                <div className="flex items-center gap-3">
                  <span className="text-navy-500 w-20">Original</span>
                  <DecisionPill decision={result.original?.decision} />
                  <span className="text-navy-400">{result.original?.violations?.join(', ') || '—'}</span>
                  <SeverityBadge severity={result.original?.severity} />
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-navy-500 w-20">Replayed</span>
                  <DecisionPill decision={result.replayed?.decision} />
                  <span className="text-navy-400">{result.replayed?.violations?.join(', ') || '—'}</span>
                  <SeverityBadge severity={result.replayed?.severity} />
                </div>
              </div>
              <div className="mt-2 pt-2 border-t border-navy-800/40 flex items-center gap-4 flex-wrap">
                {['decision', 'violations', 'severity', 'bundle_revision'].map(f => (
                  <span key={f} className={`text-xs font-medium ${
                    result.match?.[f] ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {f.replace('_', ' ').replace(/^\w/, c => c.toUpperCase())} {result.match?.[f] ? '✓' : '✗'}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Error */}
        {result?.error && (
          <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300 text-xs">
            Error: {result.error}
          </div>
        )}

        {/* Bulk verification results */}
        {bulkResult && (
          <div className="mt-4 p-4 rounded-lg border bg-navy-950/40 border-navy-800/40">
            <div className="text-sm font-semibold text-white mb-3">
              Bulk Verification — {bulkResult.summary.total} records
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-navy-800/40">
                    <th className="text-left py-1.5 px-2 text-navy-500">#</th>
                    <th className="text-left py-1.5 px-2 text-navy-500">Action ID</th>
                    <th className="text-left py-1.5 px-2 text-navy-500">Decision</th>
                    <th className="text-left py-1.5 px-2 text-navy-500">Violations</th>
                    <th className="text-center py-1.5 px-2 text-navy-500">Match</th>
                  </tr>
                </thead>
                <tbody>
                  {bulkResult.results.map((r, i) => (
                    <tr key={i} className="border-b border-navy-800/20">
                      <td className="py-1 px-2 text-navy-600">{i + 1}</td>
                      <td className="py-1 px-2 text-navy-300 font-mono">{r.action_id?.slice(0, 14)}…</td>
                      <td className="py-1 px-2">
                        {r.replay_status === 'ERROR' ? (
                          <span className="text-amber-400">ERROR</span>
                        ) : (
                          <span className={r.original?.decision === 'allow' ? 'text-emerald-400' : 'text-red-400'}>
                            {r.original?.decision?.toUpperCase()}
                          </span>
                        )}
                      </td>
                      <td className="py-1 px-2 text-navy-400">
                        {r.original?.violations?.length ? r.original.violations[0]?.slice(0, 28) : '—'}
                      </td>
                      <td className="py-1 px-2 text-center">
                        {r.replay_status === 'MATCH' ? (
                          <span className="text-emerald-400">✓</span>
                        ) : r.replay_status === 'ERROR' ? (
                          <span className="text-amber-400">⚠</span>
                        ) : (
                          <span className="text-red-400 font-bold">✗</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 pt-2 border-t border-navy-800/40 text-xs">
              <span className={bulkResult.summary.mismatched === 0 ? 'text-emerald-400' : 'text-red-400'}>
                {bulkResult.summary.matched}/{bulkResult.summary.total} records verified.
                {bulkResult.summary.mismatched > 0 && ` ${bulkResult.summary.mismatched} mismatches.`}
              </span>
              {bulkResult.summary.mismatched === 0 && (
                <span className="text-navy-500 ml-2">All decisions reproducible from archived policy bundles.</span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Erasure Panel ───────────────────────────────────────────────────────────

function ErasurePanel({ onErasureComplete }) {
  const [subjects, setSubjects] = useState([]);
  const [subjectInput, setSubjectInput] = useState('');
  const [statusResult, setStatusResult] = useState(null);
  const [eraseResult, setEraseResult] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchSubjects = useCallback(async () => {
    try {
      const r = await fetch(`${API}/audit/subjects`);
      const data = await r.json();
      setSubjects(data.subjects || []);
    } catch {}
  }, []);

  useEffect(() => { fetchSubjects(); }, [fetchSubjects]);

  const checkStatus = async () => {
    if (!subjectInput.trim()) return;
    setLoading(true);
    try {
      const r = await fetch(`${API}/hsm/keys/${subjectInput}/status`);
      const data = await r.json();
      setStatusResult(data);
      setEraseResult(null);
      setVerifyResult(null);
    } catch (e) { setStatusResult({ error: e.message }); }
    setLoading(false);
  };

  const executeErasure = async (subjectId) => {
    const id = subjectId || subjectInput.trim();
    if (!id || !window.confirm(`Execute GDPR erasure for "${id}"?\n\nThis will PERMANENTLY delete the encryption key.\nPII in ${subjects.find(s => s.subject_id === id)?.record_count || '?'} records will become irrecoverable.\n\nThis cannot be undone.`)) return;
    setLoading(true);
    try {
      const r = await fetch(`${API}/audit/erase/${id}`, { method: 'POST' });
      const data = await r.json();
      setEraseResult(data);
      setStatusResult(null);
      setVerifyResult(null);
      fetchSubjects();
      if (onErasureComplete) onErasureComplete();
    } catch (e) { setEraseResult({ error: e.message }); }
    setLoading(false);
  };

  const verifyErasure = async (subjectId) => {
    const id = subjectId || subjectInput.trim();
    if (!id) return;
    setLoading(true);
    try {
      const r = await fetch(`${API}/audit/erase/${id}/verify`);
      const data = await r.json();
      setVerifyResult(data);
    } catch (e) { setVerifyResult({ error: e.message }); }
    setLoading(false);
  };

  return (
    <div className="bg-navy-900/50 rounded-2xl border border-navy-800/50 p-6">
      <div className="flex items-center gap-3 mb-2">
        <span className="text-xl">🗑</span>
        <h2 className="text-white font-bold text-base">Erasure Management</h2>
        <span className="text-navy-500 text-xs">— GDPR Right to Erasure</span>
      </div>
      <p className="text-navy-500 text-xs mb-4">
        Delete a subject's HSM encryption key to render their PII irrecoverable. Audit records and hash chain integrity are preserved.
      </p>

      {/* Subject input */}
      <div className="flex items-center gap-2 mb-4">
        <label className="text-navy-400 text-xs">Subject ID:</label>
        <input
          type="text"
          value={subjectInput}
          onChange={e => setSubjectInput(e.target.value)}
          placeholder="user-eu-demo-001"
          className="flex-1 bg-navy-950 border border-navy-700 text-white rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-vargate"
        />
        <button
          onClick={checkStatus}
          disabled={loading || !subjectInput.trim()}
          className="px-3 py-2 bg-navy-800 text-navy-300 rounded-lg text-xs font-medium border border-navy-700 hover:bg-navy-700 disabled:opacity-50 transition-colors"
        >Check Status</button>
        <button
          onClick={() => executeErasure()}
          disabled={loading || !subjectInput.trim()}
          className="px-3 py-2 bg-red-900/80 text-red-200 rounded-lg text-xs font-semibold border border-red-700/60 hover:bg-red-800 disabled:opacity-50 transition-colors"
        >🗑 Execute Erasure</button>
      </div>

      {/* Subject list */}
      {subjects.length > 0 && (
        <div className="space-y-1 mb-4">
          <div className="text-navy-500 text-xs font-semibold uppercase tracking-wider mb-2">Subjects with encrypted PII</div>
          {subjects.map(s => (
            <div key={s.subject_id} className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs ${s.erasure_status === 'erased' ? 'bg-navy-950/50 opacity-60' : 'bg-navy-800/30'}`}>
              <span>{s.erasure_status === 'erased' ? '🔓' : '🔒'}</span>
              <span className="text-white font-mono flex-1">{s.subject_id}</span>
              <span className="text-navy-400">{s.record_count} record{s.record_count !== 1 ? 's' : ''}</span>
              {s.erasure_status === 'erased' ? (
                <span className="flex items-center gap-1">
                  <span className="text-navy-500">Erased ✓</span>
                  <button
                    onClick={() => verifyErasure(s.subject_id)}
                    className="px-2 py-1 bg-navy-700/50 text-navy-400 rounded text-[10px] hover:bg-navy-700 transition-colors"
                  >Verify</button>
                </span>
              ) : (
                <button
                  onClick={() => executeErasure(s.subject_id)}
                  disabled={loading}
                  className="px-2 py-1 bg-red-900/60 text-red-300 rounded text-[10px] font-medium hover:bg-red-800 disabled:opacity-50 transition-colors"
                >Erase</button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Status result */}
      {statusResult && (
        <div className="bg-navy-950/60 rounded-lg p-3 text-xs mb-3 border border-navy-800/40">
          <div className="text-navy-400 font-semibold mb-1">Key Status</div>
          <div className="text-white font-mono">
            {statusResult.key_exists ? (
              <span className="text-emerald-400">🔒 Key active — {statusResult.key_id}</span>
            ) : statusResult.erased_at ? (
              <span className="text-red-400">🔓 Key erased at {formatTime(statusResult.erased_at)}</span>
            ) : (
              <span className="text-navy-500">No key found</span>
            )}
          </div>
        </div>
      )}

      {/* Erasure result */}
      {eraseResult && !eraseResult.error && (
        <div className="bg-red-950/30 rounded-lg p-4 text-xs border border-red-800/40">
          <div className="text-red-300 font-bold mb-2">✓ Erasure Complete</div>
          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <span className="text-navy-500">Subject</span>
            <span className="text-white font-mono">{eraseResult.subject_id}</span>
            <span className="text-navy-500">Records</span>
            <span className="text-white">{eraseResult.records_affected} marked erased</span>
            <span className="text-navy-500">Certificate</span>
            <span className="text-amber-400 font-mono break-all">{eraseResult.erasure_certificate}</span>
            <span className="text-navy-500">Erased at</span>
            <span className="text-white">{eraseResult.erased_at}</span>
          </div>
          <p className="text-navy-400 mt-2 text-[11px]">{eraseResult.interpretation}</p>
        </div>
      )}

      {/* Verify result */}
      {verifyResult && (
        <div className={`rounded-lg p-3 text-xs border mt-3 ${verifyResult.decryption_result === 'failed'
          ? 'bg-emerald-950/30 border-emerald-800/40'
          : 'bg-amber-950/30 border-amber-800/40'
        }`}>
          <div className={`font-bold mb-1 ${verifyResult.decryption_result === 'failed' ? 'text-emerald-400' : 'text-amber-400'}`}>
            {verifyResult.decryption_result === 'failed' ? '✅ Erasure Verified' : '⚠️ Key Still Active'}
          </div>
          <p className="text-navy-400">{verifyResult.interpretation}</p>
          {verifyResult.error && <p className="text-navy-500 mt-1 font-mono">Error: {verifyResult.error}</p>}
        </div>
      )}
    </div>
  );
}

// ── Credential Vault Panel (Stage 8) ────────────────────────────────────────

function VaultPanel() {
  const [credentials, setCredentials] = useState([]);
  const [accessLog, setAccessLog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toolId, setToolId] = useState('');
  const [credName, setCredName] = useState('api_key');
  const [credValue, setCredValue] = useState('');
  const [status, setStatus] = useState(null);
  const [showLog, setShowLog] = useState(false);

  const fetchVault = async () => {
    try {
      const [credResp, logResp] = await Promise.all([
        fetch(`${API}/credentials`),
        fetch(`${API}/credentials/access-log`),
      ]);
      const credData = await credResp.json();
      const logData = await logResp.json();
      setCredentials(credData.credentials || []);
      setAccessLog(logData.entries || []);
    } catch (e) {
      console.error('Failed to fetch vault data:', e);
    }
    setLoading(false);
  };

  useEffect(() => { fetchVault(); const i = setInterval(fetchVault, 5000); return () => clearInterval(i); }, []);

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!toolId || !credValue) return;
    setStatus(null);
    try {
      const resp = await fetch(`${API}/credentials/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool_id: toolId, name: credName, value: credValue }),
      });
      const data = await resp.json();
      setStatus({ type: 'ok', message: `✓ Credential registered for ${toolId}/${credName}` });
      setToolId('');
      setCredValue('');
      fetchVault();
    } catch (e) {
      setStatus({ type: 'error', message: `Error: ${e.message}` });
    }
  };

  const handleDelete = async (tid, name) => {
    try {
      await fetch(`${API}/credentials/${tid}/${name}`, { method: 'DELETE' });
      fetchVault();
    } catch (e) {
      console.error('Delete failed:', e);
    }
  };

  const toolColors = {
    gmail: 'from-red-500/20 to-red-600/10 border-red-500/30 text-red-300',
    salesforce: 'from-blue-500/20 to-blue-600/10 border-blue-500/30 text-blue-300',
    stripe: 'from-purple-500/20 to-purple-600/10 border-purple-500/30 text-purple-300',
    slack: 'from-amber-500/20 to-amber-600/10 border-amber-500/30 text-amber-300',
  };

  return (
    <div className="bg-navy-900/40 rounded-xl border border-navy-800/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-navy-800/40 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-lg">🔐</span>
          <span className="text-white text-sm font-semibold">Credential Vault</span>
          <span className="text-navy-500 text-xs ml-1">— HSM-Encrypted Tool Credentials</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-emerald-400 text-xs font-mono">{credentials.length} registered</span>
          <button
            onClick={() => setShowLog(!showLog)}
            className="px-2 py-1 text-[10px] font-semibold text-navy-400 hover:text-navy-200 bg-navy-800/30 rounded border border-navy-700/30 transition-colors"
          >
            {showLog ? 'Hide Log' : 'Access Log'}
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Registered credentials grid */}
        {credentials.length > 0 ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {credentials.map((c, i) => (
              <div key={i} className={`relative p-3 rounded-lg bg-gradient-to-br border ${toolColors[c.tool_id] || 'from-navy-700/20 to-navy-800/10 border-navy-600/30 text-navy-300'}`}>
                <div className="text-xs font-bold uppercase tracking-wider">{c.tool_id}</div>
                <div className="text-[10px] opacity-70 font-mono mt-0.5">{c.name}</div>
                <div className="text-[9px] opacity-50 mt-1">{formatTime(c.created_at)}</div>
                <button
                  onClick={() => handleDelete(c.tool_id, c.name)}
                  className="absolute top-2 right-2 text-[10px] opacity-40 hover:opacity-100 transition-opacity"
                  title="Delete credential"
                >✕</button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-4 text-navy-500 text-xs">
            No credentials registered. Register tool credentials below.
          </div>
        )}

        {/* Registration form */}
        <form onSubmit={handleRegister} className="flex items-end gap-3 flex-wrap">
          <div>
            <label className="text-navy-500 text-[10px] font-semibold uppercase tracking-wider block mb-1">Tool ID</label>
            <select
              value={toolId}
              onChange={e => setToolId(e.target.value)}
              className="bg-navy-950 border border-navy-700 text-navy-200 text-xs rounded-lg px-3 py-1.5 focus:border-vargate focus:ring-1 focus:ring-vargate/30 outline-none"
            >
              <option value="">Select tool...</option>
              <option value="gmail">Gmail</option>
              <option value="salesforce">Salesforce</option>
              <option value="stripe">Stripe</option>
              <option value="slack">Slack</option>
            </select>
          </div>
          <div>
            <label className="text-navy-500 text-[10px] font-semibold uppercase tracking-wider block mb-1">Name</label>
            <input
              type="text"
              value={credName}
              onChange={e => setCredName(e.target.value)}
              className="bg-navy-950 border border-navy-700 text-navy-200 text-xs rounded-lg px-3 py-1.5 w-28 focus:border-vargate focus:ring-1 focus:ring-vargate/30 outline-none"
            />
          </div>
          <div>
            <label className="text-navy-500 text-[10px] font-semibold uppercase tracking-wider block mb-1">Secret Value</label>
            <input
              type="password"
              value={credValue}
              onChange={e => setCredValue(e.target.value)}
              placeholder="••••••••"
              className="bg-navy-950 border border-navy-700 text-navy-200 text-xs rounded-lg px-3 py-1.5 w-40 focus:border-vargate focus:ring-1 focus:ring-vargate/30 outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={!toolId || !credValue}
            className="px-4 py-1.5 bg-emerald-600/80 hover:bg-emerald-600 text-white text-xs font-semibold rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Register
          </button>
        </form>

        {status && (
          <div className={`text-xs font-medium px-3 py-2 rounded-lg ${
            status.type === 'ok' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20' :
            'bg-red-500/10 text-red-300 border border-red-500/20'
          }`}>
            {status.message}
          </div>
        )}

        {/* Access log */}
        {showLog && (
          <div className="mt-2">
            <div className="text-navy-400 text-xs font-semibold uppercase tracking-wider mb-2">Credential Access Log</div>
            {accessLog.length > 0 ? (
              <div className="max-h-40 overflow-y-auto">
                <table className="w-full text-[10px]">
                  <thead>
                    <tr className="border-b border-navy-800/30">
                      <th className="text-left px-2 py-1 text-navy-500">Time</th>
                      <th className="text-left px-2 py-1 text-navy-500">Tool</th>
                      <th className="text-left px-2 py-1 text-navy-500">Name</th>
                      <th className="text-left px-2 py-1 text-navy-500">Agent</th>
                      <th className="text-left px-2 py-1 text-navy-500">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {accessLog.map((entry, i) => (
                      <tr key={i} className="border-b border-navy-800/20">
                        <td className="px-2 py-1 text-navy-400 font-mono">{formatTime(entry.accessed_at)}</td>
                        <td className="px-2 py-1 text-navy-200">{entry.tool_id}</td>
                        <td className="px-2 py-1 text-navy-300 font-mono">{entry.name}</td>
                        <td className="px-2 py-1 text-navy-400" title={entry.agent_id}>{truncate(entry.agent_id, 20)}</td>
                        <td className="px-2 py-1 text-navy-400 font-mono" title={entry.action_id}>{entry.action_id?.slice(0, 8)}…</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-navy-600 text-xs py-2">No access events recorded yet.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Blockchain Anchors Panel ────────────────────────────────────────────────

function BlockchainAnchorsPanel() {
  const [anchorLog, setAnchorLog] = useState([]);
  const [anchorVerify, setAnchorVerify] = useState(null);
  const [anchorStatus, setAnchorStatusLocal] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [logR, verifyR, statusR] = await Promise.all([
        fetch(`${API}/anchor/log`),
        fetch(`${API}/anchor/verify`),
        fetch(`${API}/anchor/status`),
      ]);
      setAnchorLog((await logR.json()).anchors || []);
      setAnchorVerify(await verifyR.json());
      setAnchorStatusLocal(await statusR.json());
    } catch {}
  }, []);

  useEffect(() => { fetchData(); const i = setInterval(fetchData, 15000); return () => clearInterval(i); }, [fetchData]);

  const triggerAnchor = async () => {
    setLoading(true);
    try {
      await fetch(`${API}/anchor/trigger`, { method: 'POST' });
      await fetchData();
    } catch {}
    setLoading(false);
  };

  const connected = anchorStatus?.blockchain_connected;
  const match = anchorVerify?.match;

  return (
    <div className="bg-navy-900/50 rounded-2xl border border-navy-800/50 p-6">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <span className="text-xl">⛓</span>
          <h2 className="text-white font-bold text-base">Blockchain Anchors</h2>
        </div>
        <button
          onClick={triggerAnchor}
          disabled={loading || !connected}
          className="px-4 py-2 bg-amber-900/60 text-amber-200 rounded-lg text-xs font-semibold border border-amber-700/50 hover:bg-amber-800 disabled:opacity-50 transition-colors"
        >⛓ Anchor Now</button>
      </div>
      <div className="flex items-center gap-4 text-xs text-navy-400 mb-4">
        {anchorStatus?.contract_address && (
          <span>Contract: <span className="text-navy-300 font-mono">{anchorStatus.contract_address.slice(0, 10)}...{anchorStatus.contract_address.slice(-4)}</span></span>
        )}
        {anchorStatus?.network && <span>• {anchorStatus.network}</span>}
        {anchorStatus?.anchor_count != null && <span>• {anchorStatus.anchor_count} anchors</span>}
      </div>

      {/* Anchor table */}
      {anchorLog.length > 0 && (
        <div className="overflow-x-auto mb-4">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-navy-800/40">
                <th className="text-left px-3 py-2 text-navy-500 font-semibold">#</th>
                <th className="text-left px-3 py-2 text-navy-500 font-semibold">Block</th>
                <th className="text-left px-3 py-2 text-navy-500 font-semibold">Records</th>
                <th className="text-left px-3 py-2 text-navy-500 font-semibold">Chain Tip</th>
                <th className="text-left px-3 py-2 text-navy-500 font-semibold">Timestamp</th>
                <th className="text-left px-3 py-2 text-navy-500 font-semibold">Tx Hash</th>
              </tr>
            </thead>
            <tbody>
              {anchorLog.slice(0, 10).reverse().map(a => (
                <tr key={a.id} className="border-b border-navy-800/20 hover:bg-navy-800/20">
                  <td className="px-3 py-2 text-navy-400">{a.anchor_index}</td>
                  <td className="px-3 py-2 text-amber-300 font-mono">#{a.block_number}</td>
                  <td className="px-3 py-2 text-white">{a.record_count}</td>
                  <td className="px-3 py-2 text-navy-300 font-mono">{a.chain_tip_hash?.slice(0, 16)}...</td>
                  <td className="px-3 py-2 text-navy-400">{formatTime(a.anchored_at)}</td>
                  <td className="px-3 py-2 text-navy-300 font-mono">0x{a.tx_hash?.slice(0, 16)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Status */}
      {anchorVerify && (
        <div className={`rounded-lg px-4 py-2 text-xs ${
          match
            ? 'bg-emerald-950/30 border border-emerald-800/40 text-emerald-400'
            : anchorVerify.latest_anchor
              ? 'bg-amber-950/30 border border-amber-800/40 text-amber-400'
              : 'bg-navy-950/50 border border-navy-800/40 text-navy-400'
        }`}>
          {match ? '✓ ' : anchorVerify.latest_anchor ? '⏳ ' : '— '}
          {anchorVerify.interpretation}
        </div>
      )}
    </div>
  );
}

// ── Main App ────────────────────────────────────────────────────────────────

export default function App() {
  const [records, setRecords] = useState([]);
  const [chain, setChain] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [liveMode, setLiveMode] = useState(false);
  const [newIds, setNewIds] = useState(new Set());
  const [replayActionId, setReplayActionId] = useState('');
  const [anchorStatus, setAnchorStatus] = useState(null);
  const knownIds = useRef(new Set());

  const fetchData = useCallback(async () => {
    try {
      const [logResp, verifyResp, policyResp, anchorResp] = await Promise.all([
        fetch(`${API}/audit/log?limit=200`),
        fetch(`${API}/audit/verify`),
        fetch(`${API}/bundles/vargate/status`),
        fetch(`${API}/anchor/status`).catch(() => null),
      ]);

      const logData = await logResp.json();
      const verifyData = await verifyResp.json();
      const policyData = await policyResp.json();
      if (anchorResp?.ok) setAnchorStatus(await anchorResp.json());

      // Track new records for fade-in animation
      const incoming = logData.records || [];
      const incomingNewIds = new Set();
      for (const r of incoming) {
        if (!knownIds.current.has(r.action_id)) {
          incomingNewIds.add(r.action_id);
          knownIds.current.add(r.action_id);
        }
      }
      if (incomingNewIds.size > 0 && records.length > 0) {
        setNewIds(incomingNewIds);
        setTimeout(() => setNewIds(new Set()), 1000);
      }

      setRecords(incoming);
      setChain(verifyData);
      setPolicy(policyData);
    } catch (e) {
      console.error('Fetch error:', e);
    }
  }, [records.length]);

  // Initial fetch
  useEffect(() => {
    fetchData();
  }, []);

  // Live mode polling
  useEffect(() => {
    if (!liveMode) return;
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, [liveMode, fetchData]);

  const handleReplayFromRow = (actionId) => {
    setReplayActionId(actionId);
    // Scroll to replay panel
    setTimeout(() => {
      document.getElementById('replay-panel')?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  return (
    <div className="min-h-screen bg-navy-950 text-white font-sans">
      <TopBar chain={chain} liveMode={liveMode} setLiveMode={setLiveMode} anchorStatus={anchorStatus} />

      <main className="pt-20 pb-12 px-6 max-w-[1600px] mx-auto space-y-6">
        <StatsRow records={records} policy={policy} />
        <AuditTable records={records} chain={chain} newIds={newIds} onReplay={handleReplayFromRow} />
        <VaultPanel />
        <TamperPanel records={records} chain={chain} onRefresh={fetchData} />
        <div id="replay-panel">
          <ReplayPanel replayActionId={replayActionId} setReplayActionId={setReplayActionId} />
        </div>
        <ErasurePanel onErasureComplete={fetchData} />
        <BlockchainAnchorsPanel />
        <PolicyTimeline records={records} />
      </main>
    </div>
  );
}
