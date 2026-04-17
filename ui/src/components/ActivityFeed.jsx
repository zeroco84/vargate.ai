import React, { useState } from 'react';
import ActivityCard from './ActivityCard';

const INITIAL_VISIBLE = 10;
const PAGE_SIZE = 20;

export default function ActivityFeed({ records, newIds }) {
  const [visible, setVisible] = useState(INITIAL_VISIBLE);
  const allowed = records.filter(r => r.decision === 'allow').length;
  const blocked = records.filter(r => r.decision === 'deny').length;
  const shown = records.slice(0, visible);
  const remaining = records.length - shown.length;

  return (
    <div>
      {/* Feed header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 'var(--space-md)',
      }}>
        <div style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          color: 'var(--text-muted)',
        }}>
          Activity Feed
        </div>
        <div style={{
          display: 'flex',
          gap: 'var(--space-lg)',
          fontSize: '0.72rem',
          fontFamily: 'var(--font-mono)',
        }}>
          <span style={{ color: 'var(--accent-green)' }}>
            {allowed} allowed
          </span>
          <span style={{ color: 'var(--accent-red)' }}>
            {blocked} blocked
          </span>
          <span style={{ color: 'var(--text-muted)' }}>
            {records.length} total
          </span>
        </div>
      </div>

      {/* Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
        {records.length === 0 && (
          <div className="panel" style={{ textAlign: 'center', padding: 'var(--space-2xl)' }}>
            <div style={{ fontSize: '2rem', marginBottom: 'var(--space-md)' }}>📋</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No agent activity yet
            </div>
            <div style={{ color: 'var(--text-faint)', fontSize: '0.75rem', marginTop: 'var(--space-xs)' }}>
              Run test scripts to generate audit records
            </div>
          </div>
        )}
        {shown.map((rec) => (
          <ActivityCard
            key={rec.action_id}
            rec={rec}
            isNew={newIds.has(rec.action_id)}
          />
        ))}
      </div>

      {remaining > 0 && (
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: 'var(--space-md)' }}>
          <button
            onClick={() => setVisible(v => v + PAGE_SIZE)}
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.78rem',
              fontFamily: 'var(--font-mono)',
            }}
          >
            Show more ({remaining} more)
          </button>
        </div>
      )}
    </div>
  );
}
