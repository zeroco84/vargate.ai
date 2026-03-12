import React from 'react';
import { parseBundleRevision } from '../api';

export default function Header({ chain, liveMode, setLiveMode, anchorStatus, policy, view, setView }) {
  const valid = chain?.valid;
  const count = chain?.record_count ?? 0;
  const failedId = chain?.failed_at_action_id;
  const anchorConnected = anchorStatus?.blockchain_connected;
  const bundleRev = parseBundleRevision(policy?.revision);

  // Build status line
  let statusText, statusClass;
  if (!valid && failedId) {
    statusText = `⚠ Chain integrity violation detected — record ${failedId.slice(0, 8)}…`;
    statusClass = 'amber';
  } else {
    const parts = [`● Chain intact`];
    if (anchorConnected) parts.push('Anchored');
    parts.push(`${count} records`);
    statusText = parts.join(' · ');
    statusClass = 'green';
  }

  return (
    <header className="header">
      <div className="header-left">
        <span className="header-logo">VARGATE</span>
        <span className="header-subtitle">Supervision Gateway</span>
      </div>

      <div className="header-center">
        <span className={`status-dot ${statusClass}`} />
        <span style={{ color: statusClass === 'amber' ? 'var(--accent-amber)' : 'var(--text-secondary)' }}>
          {statusText}
        </span>
        {bundleRev.since !== '—' && (
          <span style={{ color: 'var(--text-faint)', marginLeft: '8px' }}>
            Policy active since {bundleRev.since}
          </span>
        )}
      </div>

      <div className="header-right">
        <button
          className={`header-nav-btn ${view === 'dashboard' ? 'active' : ''}`}
          onClick={() => setView('dashboard')}
        >
          Dashboard
        </button>
        <button
          className={`header-nav-btn ${view === 'settings' ? 'active' : ''}`}
          onClick={() => setView('settings')}
        >
          Settings
        </button>

        <div
          style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}
          onClick={() => setLiveMode(!liveMode)}
        >
          <div className={`live-dot ${liveMode ? '' : 'inactive'}`} />
          <span className={`live-label ${liveMode ? '' : 'inactive'}`}>
            {liveMode ? 'Live' : 'Paused'}
          </span>
        </div>
      </div>
    </header>
  );
}
