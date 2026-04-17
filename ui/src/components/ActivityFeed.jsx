import React from 'react';
import ActivityCard from './ActivityCard';

// Agent IDs whose audit records are hidden from the public activity feed.
// These are smoke-test artefacts from dev work — the audit records still
// exist (the hash chain is immutable) but they don't surface publicly.
// Add new test IDs here rather than deleting records.
const EXCLUDED_AGENTS = new Set([
  's',
  'smoke',
  'test-agent',
  'test-debug',
  'managed-agent',
  'admin-cleanup',
]);

export default function ActivityFeed({ records, newIds, total = 0, onLoadMore, loadingMore = false }) {
  const visible = records.filter(r => !EXCLUDED_AGENTS.has(r.agent_id));
  const allowed = visible.filter(r => r.decision === 'allow').length;
  const blocked = visible.filter(r => r.decision === 'deny').length;
  // Server still owns pagination state; client filtering is cosmetic.
  // "remaining" reflects how many records are behind us on the server,
  // whether or not they're visible after filtering.
  const remaining = Math.max(0, (total || records.length) - records.length);

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
            {visible.length} shown · {total || records.length} total
          </span>
        </div>
      </div>

      {/* Cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-sm)' }}>
        {visible.length === 0 && (
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
        {visible.map((rec) => (
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
            onClick={() => onLoadMore && onLoadMore()}
            disabled={loadingMore || !onLoadMore}
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              cursor: loadingMore ? 'not-allowed' : 'pointer',
              fontSize: '0.78rem',
              fontFamily: 'var(--font-mono)',
              opacity: loadingMore ? 0.5 : 1,
            }}
          >
            {loadingMore ? 'Loading…' : `Show more (${remaining} more)`}
          </button>
        </div>
      )}
    </div>
  );
}
