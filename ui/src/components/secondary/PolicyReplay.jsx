import React, { useState } from 'react';
import { replayAction, truncate } from '../../api';

export default function PolicyReplay() {
  const [actionId, setActionId] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleReplay = async () => {
    if (!actionId) return;
    setLoading(true);
    const data = await replayAction(actionId);
    setResult(data);
    setLoading(false);
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Policy Replay</span>
      </div>
      <div className="panel-body">
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 'var(--space-lg)' }}>
          Re-evaluate a past action against the current policy to see if the decision would change.
        </p>

        <div style={{ display: 'flex', alignItems: 'end', gap: 'var(--space-md)', marginBottom: 'var(--space-lg)' }}>
          <div style={{ flex: 1 }}>
            <label className="label">Action ID</label>
            <input
              className="input"
              value={actionId}
              onChange={e => setActionId(e.target.value)}
              placeholder="Paste action ID from audit log…"
            />
          </div>
          <button className="btn btn-primary" onClick={handleReplay} disabled={loading || !actionId}>
            {loading ? 'Replaying…' : '▶ Replay'}
          </button>
        </div>

        {result && (
          <div style={{
            padding: 'var(--space-md)',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--bg-base)',
            border: '1px solid var(--border-subtle)',
          }}>
            <div style={{ display: 'flex', gap: 'var(--space-lg)', marginBottom: 'var(--space-md)' }}>
              <div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Original</span>
                <div style={{
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  color: result.original_decision === 'allow' ? 'var(--accent-green)' : 'var(--accent-red)',
                }}>
                  {result.original_decision?.toUpperCase()}
                </div>
              </div>
              <div style={{ fontSize: '1.2rem', color: 'var(--text-faint)', alignSelf: 'center' }}>→</div>
              <div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Current Policy</span>
                <div style={{
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  color: result.replayed_decision === 'allow' ? 'var(--accent-green)' : 'var(--accent-red)',
                }}>
                  {result.replayed_decision?.toUpperCase()}
                </div>
              </div>
            </div>

            {result.changed && (
              <div style={{
                fontSize: '0.75rem',
                padding: 'var(--space-sm)',
                background: 'var(--accent-amber-bg)',
                color: 'var(--accent-amber)',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--accent-amber-border)',
              }}>
                ⚠ Decision would change under current policy
              </div>
            )}

            {result.replayed_violations?.length > 0 && (
              <div style={{ marginTop: 'var(--space-md)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Violations: {result.replayed_violations.join(', ')}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
