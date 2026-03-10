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

function TopBar({ chain, liveMode, setLiveMode }) {
  const valid = chain?.valid;
  const count = chain?.record_count ?? 0;
  const failedId = chain?.failed_at_action_id;

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

function RecordDetail({ rec, chainValid }) {
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

function AuditTable({ records, chain, newIds }) {
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
                      ${isExpanded ? 'bg-navy-800/30' : 'hover:bg-navy-800/20'}
                    `}
                  >
                    <td className="px-4 py-2.5 text-navy-500 font-mono text-xs">{rec.id}</td>
                    <td className="px-4 py-2.5 text-navy-300 font-mono text-xs">{formatTime(rec.created_at)}</td>
                    <td className="px-4 py-2.5 text-navy-200 text-xs" title={rec.agent_id}>{truncate(rec.agent_id, 28)}</td>
                    <td className="px-4 py-2.5 text-navy-200 text-xs">{rec.tool}</td>
                    <td className="px-4 py-2.5"><DecisionPill decision={rec.decision} /></td>
                    <td className="px-4 py-2.5 text-navy-400 text-xs" title={rec.violations?.join(', ')}>
                      {rec.violations?.length ? truncate(rec.violations[0], 32) : <span className="text-navy-600">—</span>}
                    </td>
                    <td className="px-4 py-2.5 text-center"><PassPill pass={rec.evaluation_pass} /></td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={rec.severity} /></td>
                    <td className="px-4 py-2.5 text-center"><ChainIcon valid={chainOk} /></td>
                  </tr>
                  {isExpanded && <RecordDetail rec={rec} chainValid={chainOk} />}
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

// ── Main App ────────────────────────────────────────────────────────────────

export default function App() {
  const [records, setRecords] = useState([]);
  const [chain, setChain] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [liveMode, setLiveMode] = useState(false);
  const [newIds, setNewIds] = useState(new Set());
  const knownIds = useRef(new Set());

  const fetchData = useCallback(async () => {
    try {
      const [logResp, verifyResp, policyResp] = await Promise.all([
        fetch(`${API}/audit/log?limit=200`),
        fetch(`${API}/audit/verify`),
        fetch(`${API}/bundles/vargate/status`),
      ]);

      const logData = await logResp.json();
      const verifyData = await verifyResp.json();
      const policyData = await policyResp.json();

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

  return (
    <div className="min-h-screen bg-navy-950 text-white font-sans">
      <TopBar chain={chain} liveMode={liveMode} setLiveMode={setLiveMode} />

      <main className="pt-20 pb-12 px-6 max-w-[1600px] mx-auto space-y-6">
        <StatsRow records={records} policy={policy} />
        <AuditTable records={records} chain={chain} newIds={newIds} />
        <TamperPanel records={records} chain={chain} onRefresh={fetchData} />
        <PolicyTimeline records={records} />
      </main>
    </div>
  );
}
