import React from 'react';
import { timeAgo } from '../api';

export default function ChainPanel({ chain }) {
  const valid = chain?.valid;
  const count = chain?.record_count ?? 0;
  const failedId = chain?.failed_at_action_id;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Chain Integrity</span>
      </div>
      <div className="panel-body">
        {valid === undefined ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Loading…</div>
        ) : valid ? (
          <>
            <div className="chain-status-value intact">● INTACT</div>
            <div className="chain-detail">{count} records verified</div>
            <div className="chain-detail">SHA-256 linked</div>
            <div className="chain-detail" style={{ marginTop: 'var(--space-md)' }}>
              Last verified: just now
            </div>
          </>
        ) : (
          <div className={failedId ? 'chain-break-flash' : ''}>
            <div className="chain-status-value broken">⚠ VIOLATION DETECTED</div>
            <div className="chain-detail" style={{ color: 'var(--accent-amber)' }}>
              Tampered at record #{failedId?.slice(0, 8) || '???'}…
            </div>
            <div className="chain-detail">Records after this point are unverified</div>
          </div>
        )}
      </div>
    </div>
  );
}
