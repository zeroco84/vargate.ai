import React, { useState, useEffect } from 'react';
import { fetchSessionStatus, fetchSessionAudit, fetchSessionCompliance, interruptSession, replaySession, formatTime, timeAgo } from '../api';

const SOURCE_STYLES = {
  mcp_governed:  { color: '#22c55e', bg: 'rgba(34,197,94,0.08)',  label: 'Governed',  icon: '\u25cf' },
  mcp_observed:  { color: '#3b82f6', bg: 'rgba(59,130,246,0.08)', label: 'Observed',  icon: '\u25cb' },
  control_plane: { color: '#8b5cf6', bg: 'rgba(139,92,246,0.08)', label: 'Control',   icon: '\u25c6' },
  direct:        { color: '#94a3b8', bg: 'rgba(148,163,184,0.08)', label: 'Direct',    icon: '\u25cb' },
};

const DECISION_STYLES = {
  allow:            { color: '#22c55e', label: 'Allowed' },
  deny:             { color: '#ef4444', label: 'Denied' },
  observed:         { color: '#3b82f6', label: 'Observed' },
  pending_approval: { color: '#f59e0b', label: 'Pending' },
};

export default function ManagedSessionDetail({ sessionId, onBack }) {
  const [status, setStatus] = useState(null);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);
  const [interruptReason, setInterruptReason] = useState('');
  const [showInterrupt, setShowInterrupt] = useState(false);
  const [replayResult, setReplayResult] = useState(null);
  const [filterSource, setFilterSource] = useState('all');
  const [filterDecision, setFilterDecision] = useState('all');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [sessionId]);

  async function loadData() {
    const [s, a] = await Promise.all([
      fetchSessionStatus(sessionId),
      fetchSessionAudit(sessionId),
    ]);
    if (s) setStatus(s);
    if (a?.records) setAudit(a.records);
    setLoading(false);
  }

  async function handleInterrupt() {
    if (!interruptReason.trim()) return;
    const result = await interruptSession(sessionId, interruptReason);
    if (result) {
      setShowInterrupt(false);
      setInterruptReason('');
      loadData();
    }
  }

  async function handleReplay() {
    const result = await replaySession(sessionId);
    if (result) setReplayResult(result);
  }

  async function handleExport() {
    const data = await fetchSessionCompliance(sessionId);
    if (data) {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vargate-compliance-${sessionId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  const filteredAudit = audit.filter(r => {
    if (filterSource !== 'all' && r.source !== filterSource) return false;
    if (filterDecision !== 'all' && r.decision !== filterDecision) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="card" style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
        Loading session...
      </div>
    );
  }

  const gov = status?.governance_summary || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)', gridColumn: '1 / -1' }}>
      {/* Header bar */}
      <div className="card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <button
            onClick={onBack}
            style={{
              background: 'none', border: 'none', color: 'var(--accent-blue)',
              cursor: 'pointer', padding: 0, marginBottom: '8px', fontSize: '0.78rem',
              fontFamily: 'var(--font-body)',
            }}
          >
            &larr; Back to Sessions
          </button>
          <h3 className="card-title" style={{ margin: 0 }}>
            Session {sessionId.slice(0, 20)}
          </h3>
          <div style={{ display: 'flex', gap: '16px', marginTop: '8px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <span>Agent: <b style={{ color: 'var(--text-secondary)' }}>{status?.agent_id?.slice(0, 24) || '—'}</b></span>
            <span>Created: <b style={{ color: 'var(--text-secondary)' }}>{timeAgo(status?.created_at)}</b></span>
            {status?.ended_at && <span>Ended: <b style={{ color: 'var(--text-secondary)' }}>{timeAgo(status?.ended_at)}</b></span>}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          {status?.status === 'active' && (
            <button
              onClick={() => setShowInterrupt(!showInterrupt)}
              style={{
                padding: '6px 14px', borderRadius: '6px',
                border: '1px solid rgba(239,68,68,0.3)',
                background: 'rgba(239,68,68,0.1)', color: '#ef4444',
                cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600,
                fontFamily: 'var(--font-body)',
              }}
            >
              Emergency Stop
            </button>
          )}
          <button
            onClick={handleExport}
            style={{
              padding: '6px 14px', borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              background: 'transparent', color: 'var(--text-secondary)',
              cursor: 'pointer', fontSize: '0.75rem', fontFamily: 'var(--font-body)',
            }}
          >
            Export Compliance
          </button>
          <button
            onClick={handleReplay}
            style={{
              padding: '6px 14px', borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              background: 'transparent', color: 'var(--text-secondary)',
              cursor: 'pointer', fontSize: '0.75rem', fontFamily: 'var(--font-body)',
            }}
          >
            Replay Policy
          </button>
        </div>
      </div>

      {/* Interrupt dialog */}
      {showInterrupt && (
        <div className="card" style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.03)' }}>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input
              type="text"
              value={interruptReason}
              onChange={e => setInterruptReason(e.target.value)}
              placeholder="Reason for emergency stop..."
              style={{
                flex: 1, padding: '8px 12px', borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                background: 'var(--bg-base)', color: 'var(--text-primary)',
                fontSize: '0.8rem', fontFamily: 'var(--font-body)',
              }}
              onKeyDown={e => e.key === 'Enter' && handleInterrupt()}
            />
            <button
              onClick={handleInterrupt}
              style={{
                padding: '8px 20px', borderRadius: '6px', border: 'none',
                background: '#ef4444', color: '#fff', cursor: 'pointer',
                fontSize: '0.78rem', fontWeight: 600, fontFamily: 'var(--font-body)',
              }}
            >
              Confirm Interrupt
            </button>
            <button
              onClick={() => setShowInterrupt(false)}
              style={{
                padding: '8px 14px', borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                background: 'transparent', color: 'var(--text-muted)',
                cursor: 'pointer', fontSize: '0.78rem', fontFamily: 'var(--font-body)',
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Governance summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 'var(--space-md)' }}>
        {[
          { label: 'Status', value: status?.status || '—', color: status?.status === 'active' ? '#22c55e' : status?.status === 'interrupted' ? '#ef4444' : '#94a3b8' },
          { label: 'Governed Calls', value: gov.total_governed_calls || 0, color: '#22c55e' },
          { label: 'Observed Calls', value: gov.total_observed_calls || 0, color: '#3b82f6' },
          { label: 'Denied', value: gov.total_denied || 0, color: gov.total_denied > 0 ? '#ef4444' : '#94a3b8' },
          { label: 'Pending', value: gov.total_pending || 0, color: gov.total_pending > 0 ? '#f59e0b' : '#94a3b8' },
          { label: 'Prompt Hash', value: status?.system_prompt_hash?.slice(0, 12) + '...' || '—', color: '#8b5cf6', mono: true },
        ].map((card, i) => (
          <div key={i} className="card" style={{ textAlign: 'center', padding: '16px 12px' }}>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '6px' }}>
              {card.label}
            </div>
            <div style={{
              fontSize: card.mono ? '0.7rem' : '1.4rem', fontWeight: 700,
              color: card.color,
              fontFamily: card.mono ? 'var(--font-mono)' : 'var(--font-display)',
            }}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      {/* Replay result */}
      {replayResult && (
        <div className="card" style={{ borderColor: 'rgba(139,92,246,0.3)' }}>
          <h4 style={{ margin: '0 0 8px 0', fontSize: '0.85rem', color: 'var(--text-primary)' }}>Policy Replay Result</h4>
          <div style={{ display: 'flex', gap: '16px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            <span>Total: <b>{replayResult.summary?.total || 0}</b></span>
            <span style={{ color: '#22c55e' }}>Matched: <b>{replayResult.summary?.matched || 0}</b></span>
            <span style={{ color: '#ef4444' }}>Mismatched: <b>{replayResult.summary?.mismatched || 0}</b></span>
            <span style={{ color: '#f59e0b' }}>Errors: <b>{replayResult.summary?.errors || 0}</b></span>
          </div>
          <button
            onClick={() => setReplayResult(null)}
            style={{
              marginTop: '8px', padding: '4px 10px', borderRadius: '4px',
              border: '1px solid var(--border-subtle)', background: 'transparent',
              color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.7rem',
              fontFamily: 'var(--font-body)',
            }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Timeline filters */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 className="card-title" style={{ margin: 0 }}>Session Timeline</h3>
          <div style={{ display: 'flex', gap: '12px', fontSize: '0.7rem' }}>
            <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-muted)' }}>Source:</span>
              {['all', 'mcp_governed', 'mcp_observed', 'control_plane'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilterSource(f)}
                  style={{
                    padding: '2px 8px', borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    background: filterSource === f ? 'var(--bg-hover)' : 'transparent',
                    color: filterSource === f ? 'var(--text-primary)' : 'var(--text-faint)',
                    cursor: 'pointer', fontSize: '0.68rem', fontFamily: 'var(--font-body)',
                  }}
                >
                  {f === 'all' ? 'All' : (SOURCE_STYLES[f]?.label || f)}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-muted)' }}>Decision:</span>
              {['all', 'allow', 'deny', 'observed', 'pending_approval'].map(f => (
                <button
                  key={f}
                  onClick={() => setFilterDecision(f)}
                  style={{
                    padding: '2px 8px', borderRadius: '4px',
                    border: '1px solid var(--border-subtle)',
                    background: filterDecision === f ? 'var(--bg-hover)' : 'transparent',
                    color: filterDecision === f ? 'var(--text-primary)' : 'var(--text-faint)',
                    cursor: 'pointer', fontSize: '0.68rem', fontFamily: 'var(--font-body)',
                  }}
                >
                  {f === 'all' ? 'All' : (DECISION_STYLES[f]?.label || f)}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Timeline entries */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          {filteredAudit.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '24px', fontSize: '0.8rem' }}>
              No events match the current filters.
            </div>
          ) : filteredAudit.map(record => {
            const src = SOURCE_STYLES[record.source] || SOURCE_STYLES.direct;
            const dec = DECISION_STYLES[record.decision] || { color: '#94a3b8', label: record.decision };
            const hasViolations = record.violations && record.violations.length > 0;
            const isInterrupt = record.method === 'interrupt_session';

            return (
              <div
                key={record.action_id}
                style={{
                  display: 'flex', gap: '12px', padding: '10px 12px',
                  borderRadius: '6px', background: src.bg,
                  borderLeft: `3px solid ${src.color}`,
                  alignItems: 'flex-start',
                }}
              >
                {/* Source indicator */}
                <div style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center',
                  minWidth: '64px', gap: '2px',
                }}>
                  <span style={{ fontSize: '0.65rem', fontWeight: 600, color: src.color, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    {src.label}
                  </span>
                  <span style={{
                    fontSize: '0.65rem', fontWeight: 600, color: dec.color,
                    padding: '1px 6px', borderRadius: '3px',
                    background: `${dec.color}15`,
                  }}>
                    {dec.label}
                  </span>
                </div>

                {/* Main content */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: '0.8rem',
                      fontWeight: 600, color: 'var(--text-primary)',
                    }}>
                      {isInterrupt ? 'SESSION INTERRUPTED' : `${record.tool}.${record.method}`}
                    </span>
                    {hasViolations && (
                      <span style={{
                        fontSize: '0.65rem', padding: '1px 6px', borderRadius: '3px',
                        background: 'rgba(239,68,68,0.1)', color: '#ef4444',
                      }}>
                        {record.violations.join(', ')}
                      </span>
                    )}
                    {record.severity && record.severity !== 'none' && (
                      <span style={{
                        fontSize: '0.6rem', padding: '1px 6px', borderRadius: '3px',
                        background: record.severity === 'critical' ? 'rgba(239,68,68,0.15)' :
                                    record.severity === 'high' ? 'rgba(245,158,11,0.15)' : 'rgba(148,163,184,0.1)',
                        color: record.severity === 'critical' ? '#ef4444' :
                               record.severity === 'high' ? '#f59e0b' : 'var(--text-muted)',
                        textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em',
                      }}>
                        {record.severity}
                      </span>
                    )}
                  </div>
                  <div style={{
                    fontSize: '0.68rem', color: 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', marginTop: '2px',
                  }}>
                    {record.action_id?.slice(0, 24)}
                  </div>
                </div>

                {/* Timestamp */}
                <div style={{ fontSize: '0.68rem', color: 'var(--text-faint)', whiteSpace: 'nowrap' }}>
                  {formatTime(record.created_at)}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
