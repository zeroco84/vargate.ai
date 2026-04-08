import React, { useState, useEffect, useCallback } from 'react';
import { fetchJSON } from '../api.js';

export default function ApprovalQueue() {
  const [pending, setPending] = useState([]);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [view, setView] = useState('pending'); // 'pending' | 'history'
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState({});
  const [expandedId, setExpandedId] = useState(null);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      const [pendingData, historyData] = await Promise.all([
        fetchJSON('/api/approvals'),
        fetchJSON('/api/approvals/history'),
      ]);
      setPending(pendingData.pending || []);
      setStats(pendingData.stats || null);
      setHistory(historyData.history || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-refresh every 15 seconds
  useEffect(() => {
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleAction = async (actionId, type) => {
    setActionLoading(prev => ({ ...prev, [actionId]: type }));
    try {
      await fetchJSON(`/api/${type}/${actionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: '' }),
      });
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setActionLoading(prev => ({ ...prev, [actionId]: null }));
    }
  };

  const formatTime = (iso) => {
    if (!iso) return '—';
    const d = new Date(iso);
    const now = new Date();
    const diffMs = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return d.toLocaleDateString();
  };

  const timeRemaining = (timeoutAt) => {
    if (!timeoutAt) return '—';
    const remaining = new Date(timeoutAt) - new Date();
    if (remaining <= 0) return 'expired';
    const min = Math.floor(remaining / 60000);
    if (min < 60) return `${min}m left`;
    return `${Math.floor(min / 60)}h ${min % 60}m left`;
  };

  const severityColor = (sev) => {
    switch (sev) {
      case 'critical': return 'var(--accent-red)';
      case 'high': return 'var(--accent-amber)';
      case 'medium': return 'var(--accent-blue)';
      default: return 'var(--text-muted)';
    }
  };

  const statusBadge = (status) => {
    const colors = {
      approved: { bg: 'var(--accent-green-bg)', color: 'var(--accent-green)', border: 'var(--accent-green-border)' },
      rejected: { bg: 'var(--accent-red-bg)', color: 'var(--accent-red)', border: 'var(--accent-red-border)' },
      expired: { bg: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)', border: 'var(--border-subtle)' },
      pending: { bg: 'var(--accent-amber-bg)', color: 'var(--accent-amber)', border: 'var(--accent-amber-border)' },
    };
    const c = colors[status] || colors.pending;
    return (
      <span style={{
        display: 'inline-block', padding: '2px 8px', borderRadius: '100px',
        fontSize: '.68rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.04em',
        background: c.bg, color: c.color, border: `1px solid ${c.border}`,
      }}>
        {status}
      </span>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)' }}>
      {/* Header with stats */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Approval Queue</span>
          <div style={{ display: 'flex', gap: 'var(--space-sm)' }}>
            <button
              className={`header-nav-btn ${view === 'pending' ? 'active' : ''}`}
              onClick={() => setView('pending')}
            >
              Pending {stats?.pending > 0 ? `(${stats.pending})` : ''}
            </button>
            <button
              className={`header-nav-btn ${view === 'history' ? 'active' : ''}`}
              onClick={() => setView('history')}
            >
              History
            </button>
            <button className="btn btn-ghost" onClick={refresh} style={{ fontSize: '.7rem' }}>
              ↻ Refresh
            </button>
          </div>
        </div>

        {/* Stats bar */}
        {stats && (
          <div style={{
            display: 'flex', gap: 'var(--space-xl)', padding: 'var(--space-md) var(--space-lg)',
            borderBottom: '1px solid var(--border-subtle)', fontSize: '.78rem',
          }}>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Pending: </span>
              <span style={{ color: 'var(--accent-amber)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{stats.pending}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Approved: </span>
              <span style={{ color: 'var(--accent-green)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{stats.approved}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Rejected: </span>
              <span style={{ color: 'var(--accent-red)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{stats.rejected}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Expired: </span>
              <span style={{ color: 'var(--text-secondary)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{stats.expired}</span>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div style={{ padding: 'var(--space-md)', background: 'var(--accent-red-bg)', border: '1px solid var(--accent-red-border)', borderRadius: 'var(--radius-md)', color: 'var(--accent-red)', fontSize: '.8rem' }}>
          {error}
        </div>
      )}

      {loading && pending.length === 0 && history.length === 0 && (
        <div style={{ textAlign: 'center', padding: 'var(--space-2xl)', color: 'var(--text-muted)' }}>
          Loading approval queue...
        </div>
      )}

      {/* Pending view */}
      {view === 'pending' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-md)' }}>
          {pending.length === 0 && !loading && (
            <div className="panel" style={{ textAlign: 'center', padding: 'var(--space-2xl)' }}>
              <div style={{ fontSize: '2rem', marginBottom: 'var(--space-md)' }}>✓</div>
              <div style={{ color: 'var(--text-secondary)' }}>No actions pending approval</div>
            </div>
          )}

          {pending.map(action => (
            <div key={action.action_id} className="panel" style={{
              borderLeft: `3px solid ${severityColor(action.severity)}`,
            }}>
              <div style={{ padding: 'var(--space-lg)' }}>
                {/* Action header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-md)' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', marginBottom: '4px' }}>
                      <span style={{ fontWeight: 600, fontSize: '.9rem' }}>{action.tool}</span>
                      <span style={{ color: 'var(--text-faint)' }}>→</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{action.method}</span>
                    </div>
                    <div style={{ fontSize: '.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Agent: {action.agent_id} · {formatTime(action.created_at)}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
                    <span style={{
                      fontSize: '.68rem', fontWeight: 600, color: severityColor(action.severity),
                      textTransform: 'uppercase', letterSpacing: '.04em',
                    }}>
                      {action.severity}
                    </span>
                    <span style={{ fontSize: '.68rem', color: 'var(--text-muted)' }}>
                      {timeRemaining(action.timeout_at)}
                    </span>
                  </div>
                </div>

                {/* Action params (expandable) */}
                <button
                  onClick={() => setExpandedId(expandedId === action.action_id ? null : action.action_id)}
                  style={{
                    background: 'none', border: 'none', color: 'var(--accent-blue)',
                    cursor: 'pointer', fontSize: '.75rem', padding: 0, marginBottom: 'var(--space-md)',
                  }}
                >
                  {expandedId === action.action_id ? '▾ Hide details' : '▸ Show details'}
                </button>

                {expandedId === action.action_id && (
                  <pre style={{
                    background: 'var(--bg-base)', border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)', padding: 'var(--space-md)',
                    fontFamily: 'var(--font-mono)', fontSize: '.7rem', color: 'var(--text-secondary)',
                    overflow: 'auto', maxHeight: '200px', marginBottom: 'var(--space-md)',
                  }}>
                    {JSON.stringify(action.params, null, 2)}
                  </pre>
                )}

                {/* Violations */}
                {action.violations && action.violations.length > 0 && (
                  <div style={{ marginBottom: 'var(--space-md)', display: 'flex', gap: 'var(--space-xs)', flexWrap: 'wrap' }}>
                    {action.violations.map((v, i) => (
                      <span key={i} style={{
                        padding: '2px 8px', borderRadius: '100px', fontSize: '.65rem',
                        background: 'var(--accent-amber-bg)', color: 'var(--accent-amber)',
                        border: '1px solid var(--accent-amber-border)', fontWeight: 600,
                      }}>
                        {v}
                      </span>
                    ))}
                  </div>
                )}

                {/* Action buttons */}
                <div style={{ display: 'flex', gap: 'var(--space-sm)' }}>
                  <button
                    className="btn btn-success"
                    onClick={() => handleAction(action.action_id, 'approve')}
                    disabled={!!actionLoading[action.action_id]}
                  >
                    {actionLoading[action.action_id] === 'approve' ? 'Approving...' : '✓ Approve'}
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={() => handleAction(action.action_id, 'reject')}
                    disabled={!!actionLoading[action.action_id]}
                  >
                    {actionLoading[action.action_id] === 'reject' ? 'Rejecting...' : '✕ Reject'}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* History view */}
      {view === 'history' && (
        <div className="panel">
          <div style={{ padding: 'var(--space-md) var(--space-lg)' }}>
            {history.length === 0 && (
              <div style={{ textAlign: 'center', padding: 'var(--space-xl)', color: 'var(--text-muted)' }}>
                No approval history yet
              </div>
            )}
            {history.map(item => (
              <div key={item.action_id} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: 'var(--space-md) 0',
                borderBottom: '1px solid var(--border-subtle)',
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)', marginBottom: '2px' }}>
                    <span style={{ fontWeight: 500, fontSize: '.8rem' }}>{item.tool}</span>
                    <span style={{ color: 'var(--text-faint)', fontSize: '.75rem' }}>→</span>
                    <span style={{ color: 'var(--text-secondary)', fontSize: '.8rem' }}>{item.method}</span>
                  </div>
                  <div style={{ fontSize: '.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {item.agent_id} · {formatTime(item.created_at)}
                    {item.reviewer_email && ` · by ${item.reviewer_email}`}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-sm)' }}>
                  {statusBadge(item.status)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
