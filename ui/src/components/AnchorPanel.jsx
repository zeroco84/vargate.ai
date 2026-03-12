import React, { useState } from 'react';
import { timeAgo, truncate, formatTime } from '../api';
import { triggerAnchor } from '../api';

export default function AnchorPanel({ anchorStatus, anchorLog, anchorVerify }) {
  const [showHistory, setShowHistory] = useState(false);
  const [anchoring, setAnchoring] = useState(false);

  const connected = anchorStatus?.blockchain_connected;
  const contract = anchorStatus?.contract_address;
  const latestBlock = anchorStatus?.latest_block;

  const lastAnchor = anchorLog?.[0];

  const handleAnchorNow = async () => {
    setAnchoring(true);
    await triggerAnchor();
    setAnchoring(false);
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">External Witness</span>
      </div>
      <div className="panel-body">
        {!connected ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>Not connected</div>
        ) : (
          <>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 'var(--space-sm)' }}>
              Hardhat (local)
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-faint)', marginBottom: 'var(--space-md)' }}>
              Contract: {contract ? truncate(contract, 14) : '—'}
            </div>

            {lastAnchor && (
              <>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Last anchored: {timeAgo(lastAnchor.timestamp)}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Block #{lastAnchor.block_number} · {lastAnchor.records_covered || '—'} records covered
                </div>
              </>
            )}

            {anchorVerify?.valid && (
              <div style={{
                marginTop: 'var(--space-md)',
                fontSize: '0.72rem',
                color: 'var(--accent-green)',
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}>
                ⚑ Chain tip matches on-chain anchor
              </div>
            )}

            <div style={{ display: 'flex', gap: 'var(--space-sm)', marginTop: 'var(--space-md)' }}>
              <button className="btn btn-ghost" onClick={handleAnchorNow} disabled={anchoring}>
                {anchoring ? 'Anchoring…' : 'Anchor Now'}
              </button>
              <button className="btn btn-ghost" onClick={() => setShowHistory(!showHistory)}>
                {showHistory ? 'Hide' : 'View History'}
              </button>
            </div>

            {showHistory && anchorLog && (
              <div style={{ marginTop: 'var(--space-md)', maxHeight: '200px', overflowY: 'auto' }}>
                <table style={{ width: '100%', fontSize: '0.62rem', fontFamily: 'var(--font-mono)' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Block</th>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Hash</th>
                      <th style={{ textAlign: 'left', padding: '4px', color: 'var(--text-faint)' }}>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anchorLog.map((a, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '4px', color: 'var(--text-muted)' }}>#{a.block_number}</td>
                        <td style={{ padding: '4px', color: 'var(--text-faint)' }}>{a.chain_tip?.slice(0, 12)}…</td>
                        <td style={{ padding: '4px', color: 'var(--text-muted)' }}>{formatTime(a.timestamp)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
