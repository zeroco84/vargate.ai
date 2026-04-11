import React, { useState, useEffect } from 'react';
import { fetchManagedSessions, timeAgo } from '../api';

const STATUS_STYLES = {
  active:      { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  label: 'Active' },
  completed:   { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', label: 'Completed' },
  interrupted: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   label: 'Interrupted' },
  failed:      { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)',  label: 'Failed' },
  idled:       { color: '#6366f1', bg: 'rgba(99,102,241,0.1)',  label: 'Idled' },
};

export default function ManagedSessionList({ onSelectSession }) {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    loadSessions();
    const interval = setInterval(loadSessions, 10000);
    return () => clearInterval(interval);
  }, [filter]);

  async function loadSessions() {
    const params = {};
    if (filter !== 'all') params.status = filter;
    const data = await fetchManagedSessions(params);
    if (data?.sessions) {
      setSessions(data.sessions);
    }
    setLoading(false);
  }

  const statusDot = (status) => {
    const s = STATUS_STYLES[status] || STATUS_STYLES.completed;
    return (
      <span style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        padding: '2px 10px', borderRadius: '12px',
        background: s.bg, color: s.color,
        fontSize: '0.7rem', fontWeight: 600,
      }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color }} />
        {s.label}
      </span>
    );
  };

  return (
    <div className="card" style={{ gridColumn: '1 / -1' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h3 className="card-title" style={{ margin: 0 }}>Managed Agent Sessions</h3>
        <div style={{ display: 'flex', gap: '4px' }}>
          {['all', 'active', 'completed', 'interrupted'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '4px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)',
                background: filter === f ? 'var(--bg-hover)' : 'transparent',
                color: filter === f ? 'var(--text-primary)' : 'var(--text-muted)',
                cursor: 'pointer', fontSize: '0.7rem', fontFamily: 'var(--font-body)',
                fontWeight: filter === f ? 600 : 400,
              }}
            >
              {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '32px 0', fontSize: '0.8rem' }}>
          Loading sessions...
        </div>
      ) : sessions.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '32px 0', fontSize: '0.8rem' }}>
          No managed agent sessions found.
          {filter !== 'all' && <span> Try changing the filter.</span>}
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <th style={thStyle}>Session</th>
                <th style={thStyle}>Agent</th>
                <th style={thStyle}>Status</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Governed</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Observed</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Denied</th>
                <th style={thStyle}>Created</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => (
                <tr
                  key={s.id}
                  onClick={() => onSelectSession?.(s.id)}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={tdStyle}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
                      {s.id.slice(0, 16)}
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {s.agent_id?.slice(0, 20) || '—'}
                    </span>
                  </td>
                  <td style={tdStyle}>{statusDot(s.status)}</td>
                  <td style={{ ...tdStyle, textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--accent-green)' }}>{s.total_governed_calls || 0}</span>
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--accent-blue)' }}>{s.total_observed_calls || 0}</span>
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: s.total_denied > 0 ? 'var(--accent-red, #ef4444)' : 'var(--text-faint)' }}>
                      {s.total_denied || 0}
                    </span>
                  </td>
                  <td style={{ ...tdStyle, color: 'var(--text-muted)' }}>
                    {timeAgo(s.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const thStyle = {
  textAlign: 'left', padding: '8px 12px',
  color: 'var(--text-muted)', fontWeight: 600,
  fontSize: '0.68rem', textTransform: 'uppercase',
  letterSpacing: '0.05em',
};

const tdStyle = {
  padding: '10px 12px',
};
